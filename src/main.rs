//! WinSleuth command line entry point.
//!
//! `main` dispatches. The monitor loop that used to live here inline — forty
//! lines of SetupAPI FFI included — now lives in `core::watcher`.

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

use winsleuth::modules::analysis::loldrivers;
use winsleuth::modules::core::engine::WinSleuthEngine;
use winsleuth::modules::core::models::*;
use winsleuth::modules::core::traits::{
    DeviceInspectorProvider, DriverInventoryProvider, EventLogProvider,
};
use winsleuth::modules::core::watcher::{self, Detection, Shutdown};
use winsleuth::modules::core::{privilege, store};
use winsleuth::modules::providers::{device_inspector, driver_inventory, eventlog_reader};
use winsleuth::modules::ui_layer::cli::{
    Cli, Commands, MonitorArgs, ReportFormat, ScanArgs, VerifyArgs,
};
use winsleuth::modules::ui_layer::{bundle, html_report, reporting};
use winsleuth::modules::verifier;

/// Steps reported through the progress bar during a scan.
const SCAN_STEPS: u64 = 8;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn,winsleuth=info"))
        .init();

    let cli = Cli::parse();

    // Elevation is opt-in: re-launching without being asked would be surprising.
    if cli.elevate && !privilege::is_elevated() {
        let args: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| a != "--elevate")
            .collect();
        match privilege::relaunch_elevated(&args) {
            Ok(true) => return Ok(()),
            Ok(false) => eprintln!("Elevation was declined; continuing without it.\n"),
            Err(e) => eprintln!("Could not relaunch elevated: {e}\n"),
        }
    }

    match cli.command {
        Commands::Scan(args) => run_scan(args),
        Commands::InspectDrivers {
            all,
            vulnerable_only,
        } => inspect_drivers(all, vulnerable_only),
        Commands::InspectDevices => inspect_devices(),
        Commands::InspectEvents { days } => inspect_events(days),
        Commands::Timeline { days } => timeline(days),
        Commands::Monitor(args) => monitor(args),
        Commands::Collect {
            output,
            days,
            include_dumps,
        } => collect(output, days, include_dumps),
        Commands::Diff { against, days } => diff(against, days),
        Commands::History => history(),
        Commands::UpdateBlocklist => update_blocklist(),
        Commands::Verify(args) => verify(args),
        Commands::Ui => launch_ui(),
    }
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

fn warn_if_unelevated() {
    if let Some(notice) = privilege::degradation_notice() {
        eprintln!("! {notice}");
        eprintln!("  Re-run with --elevate, or from an Administrator terminal.\n");
    }
}

fn build_engine(days: u32, no_hashes: bool, quiet: bool) -> WinSleuthEngine {
    let window = ScanWindow::last_days(days as i64);
    let mut engine = WinSleuthEngine::with_defaults(window);

    if no_hashes {
        engine.set_driver_provider(Box::new(
            driver_inventory::WindowsDriverInventory::without_hashes(),
        ));
    }

    if !quiet {
        let bar = ProgressBar::new(SCAN_STEPS);
        if let Ok(style) = ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:32.cyan/blue}] {msg}")
        {
            bar.set_style(style.progress_chars("#>-"));
        }
        engine.set_progress_bar(bar);
    }

    engine
}

fn run_scan(args: ScanArgs) -> Result<()> {
    warn_if_unelevated();

    let quiet = args.format != ReportFormat::Text || args.output.is_some();
    let engine = build_engine(args.days, args.no_hashes, quiet);
    let report = engine.run_scan();

    let rendered = match args.format {
        ReportFormat::Text => reporting::render_text(&report),
        ReportFormat::Json => reporting::export_json(&report),
        ReportFormat::Html => html_report::render(&report),
    };

    match &args.output {
        Some(path) => {
            reporting::write_utf8(path, &rendered)?;
            println!("Report written to {}", path.display());
        }
        None => println!("{rendered}"),
    }

    if !args.no_save {
        match store::save(&report) {
            Ok(path) => {
                if args.format == ReportFormat::Text {
                    println!("Saved to history: {}", path.display());
                }
            }
            Err(e) => eprintln!("Could not save to history: {e}"),
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

fn inspect_drivers(all: bool, vulnerable_only: bool) -> Result<()> {
    warn_if_unelevated();

    let collected = driver_inventory::WindowsDriverInventory::new().collect_drivers();
    if let Some(reason) = collected.status.reason() {
        eprintln!("! {reason}\n");
    }

    let drivers: Vec<&DriverInfo> = collected
        .value
        .iter()
        .filter(|d| all || !d.is_os_driver)
        .filter(|d| !vulnerable_only || d.vulnerability.is_some())
        .collect();

    println!("{} driver(s):\n", drivers.len());
    for driver in &drivers {
        println!(
            "  {:<34} {:<14} {}",
            driver.name,
            driver.category.label(),
            driver.company
        );
        println!("    v{}  {}", driver.version, driver.signature.label());
        println!("    {}", driver.path);
        if let Some(vulnerability) = &driver.vulnerability {
            println!(
                "    KNOWN VULNERABLE — matched on {}{}",
                vulnerability.matched_on,
                if vulnerability.cves.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", vulnerability.cves.join(", "))
                }
            );
        }
        println!();
    }

    if !all {
        let hidden =
            collected.value.len() - collected.value.iter().filter(|d| !d.is_os_driver).count();
        println!("{hidden} Microsoft-signed OS drivers hidden. Pass --all to include them.");
    }
    Ok(())
}

fn inspect_devices() -> Result<()> {
    let collected = device_inspector::WindowsDeviceInspector.collect_device_problems();
    if let Some(reason) = collected.status.reason() {
        eprintln!("! {reason}\n");
    }

    if collected.value.is_empty() {
        println!("No devices are reporting a problem code.");
        return Ok(());
    }

    for device in &collected.value {
        let marker = if device
            .problem_code
            .is_some_and(device_inspector::is_hardware_fault)
        {
            "!"
        } else {
            " "
        };
        println!("{marker} {}", device.name);
        println!("    {}", device.status);
        println!("    {}\n", device.device_id);
    }
    Ok(())
}

fn inspect_events(days: u32) -> Result<()> {
    warn_if_unelevated();

    let window = ScanWindow::last_days(days as i64);
    let collected = eventlog_reader::WindowsEventLogReader::new().collect_events(&window);
    if let Some(reason) = collected.status.reason() {
        eprintln!("! {reason}\n");
    }

    println!(
        "{} event(s) in the last {days} days:\n",
        collected.value.len()
    );
    for event in &collected.value {
        println!(
            "  {}  [{}] {} {}",
            event.timestamp.format("%Y-%m-%d %H:%M:%S"),
            event.level.label(),
            event.source,
            event.event_id
        );
        if !event.message.is_empty() {
            println!("      {}", first_line(&event.message, 140));
        }
    }
    Ok(())
}

fn timeline(days: u32) -> Result<()> {
    warn_if_unelevated();

    let engine = build_engine(days, true, false);
    let report = engine.run_scan();

    if report.correlations.is_empty() {
        println!("\nNo crashes to build a timeline around.\n");
        println!(
            "{} events were collected in the window.",
            report.timeline.len()
        );
        return Ok(());
    }

    for window in &report.correlations {
        println!(
            "\n{} — {}",
            window.crash.timestamp.format("%Y-%m-%d %H:%M:%S"),
            window.crash.bugcheck_name
        );
        println!("  {} minutes either side\n", window.window_minutes);
        for event in window.preceding.iter().rev() {
            println!(
                "    before  {}  {} {}",
                event.timestamp.format("%H:%M:%S"),
                event.source,
                event.event_id
            );
        }
        println!("    ---- CRASH ----");
        for event in &window.following {
            println!(
                "    after   {}  {} {}",
                event.timestamp.format("%H:%M:%S"),
                event.source,
                event.event_id
            );
        }
    }
    Ok(())
}

fn first_line(text: &str, limit: usize) -> String {
    let cleaned = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.chars().count() <= limit {
        cleaned
    } else {
        cleaned.chars().take(limit).collect::<String>() + "…"
    }
}

// ---------------------------------------------------------------------------
// Monitor
// ---------------------------------------------------------------------------

fn monitor(args: MonitorArgs) -> Result<()> {
    warn_if_unelevated();

    let shutdown = Shutdown::new();
    if let Err(e) = shutdown.install_signal_handler() {
        eprintln!("Could not install the Ctrl+C handler: {e}");
    }

    // The tray icon needs the main thread's message loop on Windows, so the
    // watching happens on a worker and the main thread pumps messages.
    let _tray = if args.no_tray {
        None
    } else {
        build_tray(&shutdown)
    };

    println!("Watching for crashes and critical events. Press Ctrl+C to stop.");
    if args.webhook.is_some() {
        println!("  Webhook alerts enabled.");
    }
    if let Some(path) = &args.log_file {
        println!("  Logging to {}", path.display());
    }

    let worker_shutdown = shutdown.clone();
    let worker = std::thread::spawn(move || watch_loop(args, worker_shutdown));

    pump_messages(&shutdown);

    let _ = worker.join();
    println!("Stopped.");
    Ok(())
}

fn watch_loop(args: MonitorArgs, shutdown: Shutdown) {
    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "this machine".to_string());
    let mut telemetry = watcher::Telemetry::new();
    let mut alerts = watcher::AlertBuffer::new(Duration::from_secs(30));

    let subscription = watcher::EventSubscription::open("System", watcher::live_query());
    if subscription.is_none() {
        eprintln!("! Could not subscribe to the System log; only crash dumps will be watched.");
    }

    let dumps = watcher::watch_dumps();
    let (dump_events, _dump_watcher) = match dumps {
        Some((receiver, watcher)) => (Some(receiver), Some(watcher)),
        None => {
            eprintln!("! Could not watch the crash dump directory.");
            (None, None)
        }
    };

    let mut device_count = watcher::present_device_count();
    let mut last_device_check = Instant::now();
    let device_interval = Duration::from_secs(args.interval.max(5));

    while !shutdown.requested() {
        telemetry.sample();

        // Blocks until Windows signals that records arrived, or the timeout
        // elapses. No polling, and no re-reading the whole log.
        if let Some(subscription) = &subscription {
            for event in subscription.poll(Duration::from_secs(1)) {
                alerts.push(Detection::CriticalEvent {
                    source: event.source,
                    event_id: event.event_id,
                    level: event.level,
                    message: event.message,
                });
            }
        } else {
            std::thread::sleep(Duration::from_secs(1));
        }

        if let Some(receiver) = &dump_events {
            while let Ok(Ok(event)) = receiver.try_recv() {
                if !(event.kind.is_create() || event.kind.is_modify()) {
                    continue;
                }
                for path in event.paths {
                    if path
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("dmp"))
                    {
                        alerts.push(Detection::CrashDump { path });
                    }
                }
            }
        }

        if last_device_check.elapsed() >= device_interval {
            last_device_check = Instant::now();
            let present = watcher::present_device_count();
            if present != device_count {
                alerts.push(Detection::DeviceChange {
                    present,
                    previous: device_count,
                });
                device_count = present;
            }
        }

        let now = Instant::now();
        if alerts.should_flush(now) {
            let batch = alerts.take(now);
            let snapshot = telemetry.snapshot();
            deliver(&batch, &snapshot, &args, &hostname);
        }
    }

    // Anything still buffered goes out rather than being dropped on exit.
    if !alerts.is_empty() {
        let batch = alerts.take(Instant::now());
        deliver(&batch, &telemetry.snapshot(), &args, &hostname);
    }
}

fn deliver(batch: &[Detection], telemetry: &[String], args: &MonitorArgs, hostname: &str) {
    let (title, body) = watcher::summarise(batch);

    println!("\n[{}] {title}", chrono::Local::now().format("%H:%M:%S"));
    for line in body.lines() {
        println!("    {line}");
    }
    let _ = std::io::stdout().flush();

    let _ = notify_rust::Notification::new()
        .summary(&title)
        .body(&body)
        .show();

    if let Some(path) = &args.log_file
        && let Err(e) = watcher::append_log(path, batch, telemetry)
    {
        eprintln!("    (could not write the log: {e})");
    }

    if let Some(url) = &args.webhook {
        let payload = watcher::webhook_payload(batch, telemetry, hostname);
        match ureq::post(url)
            .header("Content-Type", "application/json")
            .send(&payload)
        {
            Ok(_) => {}
            Err(e) => eprintln!("    (webhook failed: {e})"),
        }
    }
}

/// Tray icon with a working Quit item.
///
/// The previous tray icon had no menu at all, so the only way to stop the
/// monitor was Task Manager.
fn build_tray(shutdown: &Shutdown) -> Option<tray_icon::TrayIcon> {
    use tray_icon::menu::{Menu, MenuEvent, MenuItem};

    let mut pixels = vec![0u8; 4 * 32 * 32];
    for y in 0..32usize {
        for x in 0..32usize {
            let i = (y * 32 + x) * 4;
            let edge = x == 0 || x == 31 || y == 0 || y == 31;
            let (r, g, b) = if edge { (255, 255, 255) } else { (0, 120, 215) };
            pixels[i] = r;
            pixels[i + 1] = g;
            pixels[i + 2] = b;
            pixels[i + 3] = 255;
        }
    }

    // The old code unwrapped both of these, so a failure took the process down
    // rather than simply running without a tray icon.
    let icon = tray_icon::Icon::from_rgba(pixels, 32, 32).ok()?;

    let menu = Menu::new();
    let quit = MenuItem::new("Quit WinSleuth", true, None);
    menu.append(&quit).ok()?;

    let tray = tray_icon::TrayIconBuilder::new()
        .with_tooltip("WinSleuth monitor")
        .with_icon(icon)
        .with_menu(Box::new(menu))
        .build()
        .ok()?;

    let quit_id = quit.id().clone();
    let flag = shutdown.clone();
    std::thread::spawn(move || {
        while let Ok(event) = MenuEvent::receiver().recv() {
            if event.id == quit_id {
                flag.request();
                break;
            }
        }
    });

    Some(tray)
}

/// Pump Windows messages so the tray icon stays responsive, exiting when
/// shutdown is requested.
fn pump_messages(shutdown: &Shutdown) {
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
    };

    while !shutdown.requested() {
        unsafe {
            let mut message = MSG::default();
            // PeekMessage rather than GetMessage: GetMessage blocks until a
            // message arrives, so Ctrl+C could not break the loop.
            while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ---------------------------------------------------------------------------
// Bundle, history, blocklist
// ---------------------------------------------------------------------------

fn collect(output: PathBuf, days: u32, include_dumps: bool) -> Result<()> {
    warn_if_unelevated();

    let engine = build_engine(days, false, false);
    let report = engine.run_scan();

    let result = bundle::build(&report, &output, include_dumps)?;

    println!("\nBundle written to {}", result.path.display());
    println!(
        "  {} file(s), {:.1} KB",
        result.entries.len(),
        result.bytes as f64 / 1024.0
    );
    println!(
        "  {} redaction rule(s) applied to the text files",
        result.redactions
    );
    if include_dumps {
        println!("  Crash dumps are included and are NOT redacted.");
    }
    println!("\nCheck the contents before sharing — only you know what is sensitive here.");
    Ok(())
}

fn diff(against: Option<PathBuf>, days: u32) -> Result<()> {
    let previous = match against {
        Some(path) => store::load(&path)?,
        None => match store::previous(chrono::Utc::now()) {
            Some((snapshot, report)) => {
                println!(
                    "Comparing against {}",
                    snapshot.taken_at.format("%Y-%m-%d %H:%M")
                );
                report
            }
            None => {
                println!("No saved scans yet. Run `winsleuth scan` first.");
                return Ok(());
            }
        },
    };

    let engine = build_engine(days, false, false);
    let current = engine.run_scan();

    println!(
        "{}",
        reporting::render_diff(&store::diff(&previous, &current))
    );
    Ok(())
}

fn history() -> Result<()> {
    let snapshots = store::list();
    if snapshots.is_empty() {
        println!("No saved scans. Run `winsleuth scan` to create one.");
        return Ok(());
    }

    println!(
        "{} saved scan(s) in {}:\n",
        snapshots.len(),
        store::snapshot_dir().display()
    );
    for snapshot in &snapshots {
        let summary = store::load(&snapshot.path)
            .map(|r| {
                format!(
                    "{} cause(s), {} crash(es)",
                    r.suspected_causes.len(),
                    r.crashes.len()
                )
            })
            .unwrap_or_else(|_| "unreadable".to_string());
        println!(
            "  {}  {:<28} {}",
            snapshot.taken_at.format("%Y-%m-%d %H:%M"),
            summary,
            snapshot.path.display()
        );
    }
    Ok(())
}

fn update_blocklist() -> Result<()> {
    println!("Fetching the known-vulnerable driver corpus from loldrivers.io…");
    match loldrivers::update_corpus() {
        Ok(count) => {
            println!(
                "Stored {count} driver hashes at {}",
                loldrivers::corpus_path().display()
            );
            println!(
                "The curated list of {} driver names is always available offline.",
                loldrivers::curated_size()
            );
        }
        Err(e) => {
            eprintln!("Could not update the corpus: {e}");
            eprintln!(
                "Scans will still match the {} curated driver names.",
                loldrivers::curated_size()
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Driver Verifier
// ---------------------------------------------------------------------------

fn verify(args: VerifyArgs) -> Result<()> {
    if !privilege::is_elevated() {
        eprintln!("Driver Verifier can only be configured with Administrator rights.");
        eprintln!("Re-run with --elevate, or from an Administrator terminal.");
        return Ok(());
    }

    if args.status {
        let outcome = verifier::query()?;
        println!("{}", outcome.output);
        return Ok(());
    }

    if args.off {
        let outcome = verifier::disable()?;
        println!("{}", outcome.output);
        println!("\nDriver Verifier is off from the next reboot.");
        return Ok(());
    }

    if !args.suspects {
        println!("Choose one of --suspects, --off or --status.");
        return Ok(());
    }

    println!("Scanning to identify the drivers worth testing…\n");
    let engine = build_engine(args.days, false, false);
    let report = engine.run_scan();

    let plan = verifier::plan_from_report(&report);
    if plan.is_empty() {
        println!("\nNo third-party drivers stand out as suspects, so there is nothing useful");
        println!("to arm Driver Verifier against. That is a good result.");
        return Ok(());
    }

    println!("\n{}\n", verifier::recovery_notice(&plan));

    if !args.yes && !confirm("Arm Driver Verifier against these drivers?")? {
        println!("Nothing was changed.");
        return Ok(());
    }

    let outcome = verifier::arm(&plan)?;
    println!("{}", outcome.output);
    if outcome.success {
        println!("\nArmed. Reboot when ready, then run `winsleuth scan` after the next crash.");
    } else {
        println!("\nDriver Verifier reported a problem; nothing may have changed.");
    }
    Ok(())
}

/// Explicit confirmation before an action that can leave a machine unbootable.
fn confirm(question: &str) -> Result<bool> {
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
}

// ---------------------------------------------------------------------------
// Desktop
// ---------------------------------------------------------------------------

fn launch_ui() -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([1000.0, 720.0]),
        ..Default::default()
    };

    eframe::run_native(
        "WinSleuth",
        options,
        Box::new(|cc| {
            Ok(Box::new(
                winsleuth::modules::ui_layer::ui::WinSleuthApp::new(cc),
            ))
        }),
    )
    .map_err(|e| anyhow::anyhow!("could not start the desktop interface: {e}"))
}
