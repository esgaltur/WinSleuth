//! Live monitoring.
//!
//! The previous implementation lived inline in `main.rs` and polled: every tick
//! it re-read the *entire* System event log — five seconds apart by default —
//! while `sysinfo::refresh_all()` enumerated every process on the machine once
//! a second to read two numbers. A tool watching for instability should not
//! itself be a sustained load.
//!
//! This subscribes to the event log instead, so Windows wakes us only when
//! something arrives, refreshes only CPU and memory, coalesces alerts so a
//! burst of fifty errors is one notification rather than fifty, and builds
//! webhook payloads with a JSON serialiser rather than by formatting strings
//! into a literal.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EvtClose, EvtNext, EvtRender, EvtRenderEventXml, EvtSubscribe,
    EvtSubscribeToFutureEvents,
};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows::core::HSTRING;

use crate::modules::core::models::{EventLevel, EventRecord};

/// How long to hold alerts before sending, so a burst becomes one message.
const COALESCE_WINDOW: Duration = Duration::from_secs(30);
/// Seconds of telemetry kept for the pre-crash snapshot.
const TELEMETRY_DEPTH: usize = 60;

#[derive(Clone)]
pub struct MonitorConfig {
    pub interval: Duration,
    pub webhook: Option<String>,
    pub log_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Detection {
    CriticalEvent {
        source: String,
        event_id: u32,
        level: EventLevel,
        message: String,
    },
    CrashDump {
        path: PathBuf,
    },
    DeviceChange {
        present: u32,
        previous: u32,
    },
}

impl Detection {
    pub fn headline(&self) -> String {
        match self {
            Detection::CriticalEvent {
                source, event_id, ..
            } => {
                format!("{source} event {event_id}")
            }
            Detection::CrashDump { path } => {
                format!("crash dump written: {}", path.display())
            }
            Detection::DeviceChange { present, previous } => {
                format!("device count changed {previous} → {present}")
            }
        }
    }

    /// Whether this warrants interrupting the user immediately.
    pub fn is_urgent(&self) -> bool {
        matches!(self, Detection::CrashDump { .. })
    }
}

// ---------------------------------------------------------------------------
// Alert coalescing
// ---------------------------------------------------------------------------

/// Holds detections briefly so a storm of related events produces one alert.
pub struct AlertBuffer {
    pending: Vec<Detection>,
    last_flush: Instant,
    window: Duration,
}

impl AlertBuffer {
    pub fn new(window: Duration) -> Self {
        Self {
            pending: Vec::new(),
            last_flush: Instant::now(),
            window,
        }
    }

    pub fn push(&mut self, detection: Detection) {
        self.pending.push(detection);
    }

    /// True when the buffer holds something urgent, or the window has elapsed.
    pub fn should_flush(&self, now: Instant) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        self.pending.iter().any(Detection::is_urgent)
            || now.duration_since(self.last_flush) >= self.window
    }

    pub fn take(&mut self, now: Instant) -> Vec<Detection> {
        self.last_flush = now;
        std::mem::take(&mut self.pending)
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// One notification summarising a batch.
pub fn summarise(batch: &[Detection]) -> (String, String) {
    if batch.len() == 1 {
        let detection = &batch[0];
        let title = if detection.is_urgent() {
            "WinSleuth: the system crashed"
        } else {
            "WinSleuth: critical event"
        };
        return (title.to_string(), detection.headline());
    }

    let crashes = batch.iter().filter(|d| d.is_urgent()).count();
    let title = if crashes > 0 {
        "WinSleuth: the system crashed".to_string()
    } else {
        format!("WinSleuth: {} critical events", batch.len())
    };

    let mut lines: Vec<String> = batch.iter().take(4).map(Detection::headline).collect();
    if batch.len() > lines.len() {
        lines.push(format!("and {} more", batch.len() - lines.len()));
    }

    (title, lines.join("\n"))
}

/// Build a webhook payload with a serialiser.
///
/// The previous version formatted event text into a raw JSON string literal, so
/// any quote or backslash in a driver path produced malformed JSON that Discord
/// rejected outright.
pub fn webhook_payload(batch: &[Detection], telemetry: &[String], hostname: &str) -> String {
    let (title, body) = summarise(batch);

    let content = format!(
        "**{title}** on `{hostname}`\n{body}\n\nRecent telemetry:\n```\n{}\n```",
        telemetry.join("\n")
    );

    serde_json::json!({
        "content": content,
        "username": "WinSleuth",
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Telemetry ring
// ---------------------------------------------------------------------------

pub struct Telemetry {
    samples: VecDeque<String>,
    system: sysinfo::System,
}

impl Telemetry {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(TELEMETRY_DEPTH),
            system: sysinfo::System::new(),
        }
    }

    /// Refresh only what is actually read. `refresh_all()` enumerated every
    /// process on the machine once a second to produce these two numbers.
    pub fn sample(&mut self) {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        let sample = format!(
            "[{}] CPU {:.0}%  RAM {} MB",
            Utc::now().format("%H:%M:%S"),
            self.system.global_cpu_usage(),
            self.system.used_memory() / 1_048_576,
        );
        if self.samples.len() >= TELEMETRY_DEPTH {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.samples.iter().cloned().collect()
    }
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Event log subscription
// ---------------------------------------------------------------------------

/// A push subscription to one channel: Windows signals an event handle when
/// records arrive, so there is no polling and no full-log rescan.
pub struct EventSubscription {
    subscription: EVT_HANDLE,
    signal: HANDLE,
}

// The handles are owned exclusively by this struct and only touched from the
// thread that owns it.
unsafe impl Send for EventSubscription {}

impl EventSubscription {
    pub fn open(channel: &str, query: &str) -> Option<Self> {
        unsafe {
            let signal = CreateEventW(None, false, false, None).ok()?;
            let channel_w = HSTRING::from(channel);
            let query_w = HSTRING::from(query);
            let subscription = EvtSubscribe(
                None,
                Some(signal),
                &channel_w,
                &query_w,
                None,
                None,
                None,
                EvtSubscribeToFutureEvents.0,
            )
            .ok();
            match subscription {
                Some(handle) => Some(Self {
                    subscription: handle,
                    signal,
                }),
                None => {
                    let _ = CloseHandle(signal);
                    None
                }
            }
        }
    }

    /// Wait up to `timeout` for records, then drain whatever arrived.
    pub fn poll(&self, timeout: Duration) -> Vec<EventRecord> {
        unsafe {
            let millis = timeout.as_millis().min(u32::MAX as u128) as u32;
            if WaitForSingleObject(self.signal, millis) != WAIT_OBJECT_0 {
                return Vec::new();
            }
        }
        self.drain()
    }

    fn drain(&self) -> Vec<EventRecord> {
        let mut records = Vec::new();
        let mut buffer = vec![0u16; 16 * 1024];
        loop {
            let mut events = [0isize; 32];
            let mut returned = 0u32;
            let more =
                unsafe { EvtNext(self.subscription, &mut events, 0, 0, &mut returned).is_ok() };
            if !more || returned == 0 {
                break;
            }

            for slot in events.iter().take(returned as usize) {
                let event = EVT_HANDLE(*slot);
                if let Some(record) = render(event, &mut buffer) {
                    records.push(record);
                }
                unsafe {
                    let _ = EvtClose(event);
                }
            }
        }

        records
    }
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        unsafe {
            let _ = EvtClose(self.subscription);
            let _ = CloseHandle(self.signal);
        }
    }
}

fn render(event: EVT_HANDLE, buffer: &mut [u16]) -> Option<EventRecord> {
    unsafe {
        let mut used = 0u32;
        let mut properties = 0u32;
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            (buffer.len() * 2) as u32,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut used,
            &mut properties,
        )
        .ok()?;
        let chars = (used as usize / 2).min(buffer.len());
        let xml = String::from_utf16_lossy(&buffer[..chars]);
        crate::modules::providers::eventlog_reader::parse_into_record(&xml)
    }
}

/// The XPath used for live monitoring: crashes, hardware errors and anything
/// critical.
pub fn live_query() -> &'static str {
    "*[System[(Level=1 or Level=2)]]"
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

/// Shared stop flag, set by Ctrl+C or the tray's Quit item.
///
/// The previous monitor had neither: the tray icon carried no menu, so the only
/// way out was Task Manager.
#[derive(Clone)]
pub struct Shutdown(Arc<AtomicBool>);

impl Shutdown {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn requested(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    pub fn request(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Install a Ctrl+C handler that sets this flag.
    pub fn install_signal_handler(&self) -> Result<(), ctrlc::Error> {
        let flag = self.clone();
        ctrlc::set_handler(move || flag.request())
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Append a detection to the audit log.
pub fn append_log(
    path: &PathBuf,
    batch: &[Detection],
    telemetry: &[String],
) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "=== {} ===", Utc::now().to_rfc3339())?;
    for detection in batch {
        writeln!(file, "  {}", detection.headline())?;
        if let Detection::CriticalEvent { message, .. } = detection
            && !message.is_empty()
        {
            writeln!(file, "    {message}")?;
        }
    }
    if !telemetry.is_empty() {
        writeln!(file, "  telemetry:")?;
        for sample in telemetry
            .iter()
            .rev()
            .take(10)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            writeln!(file, "    {sample}")?;
        }
    }
    Ok(())
}

/// Watch the crash dump directory. Returns the receiver and keeps the watcher
/// alive inside the returned guard.
pub fn watch_dumps() -> Option<(
    Receiver<notify::Result<notify::Event>>,
    notify::RecommendedWatcher,
)> {
    use notify::Watcher;

    let (sender, receiver) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(sender).ok()?;
    watcher
        .watch(
            std::path::Path::new("C:\\Windows\\Minidump"),
            notify::RecursiveMode::NonRecursive,
        )
        .ok()?;
    Some((receiver, watcher))
}

/// Count present PnP devices, for detecting hardware appearing and vanishing.
pub fn present_device_count() -> u32 {
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        DIGCF_ALLCLASSES, DIGCF_PRESENT, SP_DEVINFO_DATA, SetupDiDestroyDeviceInfoList,
        SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    };

    unsafe {
        let Ok(set) = SetupDiGetClassDevsW(None, None, None, DIGCF_PRESENT | DIGCF_ALLCLASSES)
        else {
            return 0;
        };
        if set.is_invalid() {
            return 0;
        }

        let mut data = SP_DEVINFO_DATA {
            cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        let mut count = 0u32;
        while SetupDiEnumDeviceInfo(set, count, &mut data).is_ok() {
            count += 1;
        }

        let _ = SetupDiDestroyDeviceInfoList(set);
        count
    }
}

/// Shared state the tray thread and the worker thread both touch.
pub type SharedBuffer = Arc<Mutex<AlertBuffer>>;

pub fn shared_buffer() -> SharedBuffer {
    Arc::new(Mutex::new(AlertBuffer::new(COALESCE_WINDOW)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn critical(id: u32) -> Detection {
        Detection::CriticalEvent {
            source: "Disk".into(),
            event_id: id,
            level: EventLevel::Error,
            message: "bad block".into(),
        }
    }

    #[test]
    fn a_burst_of_events_becomes_one_alert() {
        let mut buffer = AlertBuffer::new(Duration::from_secs(30));
        let start = Instant::now();
        for id in 0..50 {
            buffer.push(critical(id));
        }
        assert_eq!(buffer.len(), 50);
        // Not yet: the window has not elapsed and nothing is urgent.
        assert!(!buffer.should_flush(start));
        let later = start + Duration::from_secs(31);
        assert!(buffer.should_flush(later));
        let batch = buffer.take(later);
        assert_eq!(batch.len(), 50);
        assert!(buffer.is_empty());
        let (title, body) = summarise(&batch);
        assert!(title.contains("50 critical events"));
        assert!(body.contains("and 46 more"), "{body}");
    }

    #[test]
    fn a_crash_flushes_immediately() {
        let mut buffer = AlertBuffer::new(Duration::from_secs(3600));
        buffer.push(critical(1));
        assert!(!buffer.should_flush(Instant::now()));
        buffer.push(Detection::CrashDump {
            path: PathBuf::from("C:\\Windows\\Minidump\\a.dmp"),
        });
        assert!(
            buffer.should_flush(Instant::now()),
            "a crash must not wait for the window"
        );
    }

    #[test]
    fn an_empty_buffer_never_flushes() {
        let buffer = AlertBuffer::new(Duration::from_secs(0));
        assert!(!buffer.should_flush(Instant::now()));
    }

    #[test]
    fn a_single_detection_is_summarised_directly() {
        let (title, body) = summarise(&[critical(7)]);
        assert!(title.contains("critical event"));
        assert_eq!(body, "Disk event 7");
        let (title, _) = summarise(&[Detection::CrashDump {
            path: PathBuf::from("a.dmp"),
        }]);
        assert!(title.contains("crashed"));
    }

    #[test]
    fn webhook_payloads_survive_quotes_and_backslashes() {
        // The old payload was a format! into a raw JSON literal, so this input
        // produced malformed JSON that Discord rejected.
        let batch = vec![Detection::CriticalEvent {
            source: "Disk".into(),
            event_id: 7,
            level: EventLevel::Error,
            message: r#"The device \Device\Harddisk0 said "no" \ again"#.into(),
        }];
        let telemetry = vec![r#"CPU "100%" \ RAM"#.to_string()];
        let payload = webhook_payload(&batch, &telemetry, r#"HOST\"NAME"#);
        let parsed: serde_json::Value =
            serde_json::from_str(&payload).expect("payload must be valid JSON");
        assert_eq!(parsed["username"], "WinSleuth");
        assert!(parsed["content"].as_str().unwrap().contains("Disk event 7"));
    }

    #[test]
    fn telemetry_is_bounded_and_reads_plausible_values() {
        let mut telemetry = Telemetry::new();
        for _ in 0..(TELEMETRY_DEPTH + 20) {
            telemetry.sample();
        }
        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.len(), TELEMETRY_DEPTH, "the ring must be bounded");
        assert!(snapshot.last().unwrap().contains("RAM"));
        assert!(snapshot.last().unwrap().contains("MB"));
    }

    #[test]
    fn shutdown_is_observable_from_a_clone() {
        let shutdown = Shutdown::new();
        let other = shutdown.clone();
        assert!(!shutdown.requested());
        other.request();
        assert!(
            shutdown.requested(),
            "the tray and the worker share one flag"
        );
    }

    #[test]
    fn the_live_query_filters_at_the_server() {
        let query = live_query();
        assert!(query.contains("Level=1"));
        assert!(query.contains("Level=2"));
        // No time predicate: a subscription only ever delivers future events.
        assert!(!query.contains("timediff"));
    }

    #[test]
    fn device_counting_returns_a_plausible_number() {
        let count = present_device_count();
        assert!(count > 5, "a Windows machine has more than {count} devices");
    }

    #[test]
    fn a_live_subscription_can_be_opened_and_closed() {
        match EventSubscription::open("System", live_query()) {
            Some(subscription) => {
                // Nothing is expected to arrive in a few milliseconds; what
                // matters is that polling returns rather than blocking or
                // faulting.
                let records = subscription.poll(Duration::from_millis(50));
                assert!(records.len() < 10_000);
                drop(subscription);
            }
            None => eprintln!("event subscription unavailable; skipping"),
        }
    }
}
