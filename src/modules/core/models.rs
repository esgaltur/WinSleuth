use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Scan window
// ---------------------------------------------------------------------------

/// The time range a scan covers. Threaded through every provider so that
/// `--days` actually bounds collection instead of only being printed.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub struct ScanWindow {
    pub since: DateTime<Utc>,
    pub until: DateTime<Utc>,
}

impl ScanWindow {
    pub fn last_days(days: i64) -> Self {
        let until = Utc::now();
        Self {
            since: until - Duration::days(days.max(1)),
            until,
        }
    }

    pub fn contains(&self, at: DateTime<Utc>) -> bool {
        at >= self.since && at <= self.until
    }

    pub fn days(&self) -> i64 {
        (self.until - self.since).num_days().max(1)
    }

    /// How much weight evidence from `at` should carry: 1.0 at the end of the
    /// window, decaying linearly to 0.4 at its start. Anything outside the
    /// window keeps the floor rather than dropping to zero, so stale-but-real
    /// evidence still counts for something.
    pub fn recency_weight(&self, at: DateTime<Utc>) -> f32 {
        const FLOOR: f32 = 0.4;
        let span = (self.until - self.since).num_seconds() as f32;
        if span <= 0.0 {
            return 1.0;
        }
        let age = (self.until - at).num_seconds() as f32;
        let fresh = 1.0 - (age / span);
        FLOOR + fresh.clamp(0.0, 1.0) * (1.0 - FLOOR)
    }
}

impl Default for ScanWindow {
    fn default() -> Self {
        Self::last_days(7)
    }
}

// ---------------------------------------------------------------------------
// Collection status
// ---------------------------------------------------------------------------

/// Whether a provider managed to collect everything it wanted to. Without this
/// an unelevated run silently reports "no problems found", which is a worse
/// outcome than an error.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CollectionStatus {
    Complete,
    Partial { reason: String },
    Failed { reason: String },
}

impl CollectionStatus {
    pub fn is_complete(&self) -> bool {
        matches!(self, CollectionStatus::Complete)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            CollectionStatus::Complete => None,
            CollectionStatus::Partial { reason } | CollectionStatus::Failed { reason } => {
                Some(reason)
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CollectionNote {
    pub provider: String,
    pub status: CollectionStatus,
    pub items: usize,
}

/// A provider result paired with how completely it was gathered.
#[derive(Debug, Clone)]
pub struct Collected<T> {
    pub value: T,
    pub status: CollectionStatus,
}

impl<T> Collected<T> {
    pub fn complete(value: T) -> Self {
        Self {
            value,
            status: CollectionStatus::Complete,
        }
    }

    pub fn partial(value: T, reason: impl Into<String>) -> Self {
        Self {
            value,
            status: CollectionStatus::Partial {
                reason: reason.into(),
            },
        }
    }

    pub fn failed(value: T, reason: impl Into<String>) -> Self {
        Self {
            value,
            status: CollectionStatus::Failed {
                reason: reason.into(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// System identity
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SystemIdentity {
    pub hostname: String,
    pub os_caption: String,
    pub os_build: String,
    pub motherboard_vendor: String,
    pub motherboard_model: String,
    pub cpu_model: String,
    pub physical_memory_gb: f32,
    pub last_boot: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct FirmwareInfo {
    pub vendor: String,
    pub version: String,
    pub date: String,
    /// Parsed form of `date`, when it could be understood.
    pub release_date: Option<DateTime<Utc>>,
}

impl FirmwareInfo {
    pub fn age_years(&self) -> Option<f32> {
        self.release_date
            .map(|d| (Utc::now() - d).num_days() as f32 / 365.25)
    }
}

// ---------------------------------------------------------------------------
// Drivers
// ---------------------------------------------------------------------------

/// Three-state signature result. The old `signed: bool` could not distinguish
/// "no embedded signature" from "not signed at all", which is the difference
/// between almost every Windows driver and an actual problem.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SignatureStatus {
    /// Signature lives in a `.cat` file in the driver store. Normal for OS and
    /// most WHQL drivers.
    Catalog { signer: String },
    /// Authenticode signature embedded in the PE itself.
    Embedded { signer: String },
    /// Verified as carrying no valid signature.
    Unsigned,
    /// Verification could not be performed (file locked, access denied).
    Unknown { reason: String },
}

impl SignatureStatus {
    pub fn is_signed(&self) -> bool {
        matches!(
            self,
            SignatureStatus::Catalog { .. } | SignatureStatus::Embedded { .. }
        )
    }

    pub fn signer(&self) -> Option<&str> {
        match self {
            SignatureStatus::Catalog { signer } | SignatureStatus::Embedded { signer } => {
                Some(signer)
            }
            _ => None,
        }
    }

    /// Whether this signer identifies an operating system component.
    ///
    /// Matching "microsoft" anywhere is not enough. Third-party drivers are
    /// WHQL-attested through the *Microsoft Windows Hardware Compatibility
    /// Publisher* authority, so NVIDIA, ASUS and MSI drivers all carry a signer
    /// with "Microsoft" in it while being emphatically not part of Windows.
    pub fn is_microsoft(&self) -> bool {
        let Some(signer) = self.signer() else {
            return false;
        };
        let signer = signer.to_lowercase();

        // The attestation authority signs other people's drivers.
        if signer.contains("hardware compatibility") {
            return false;
        }

        matches!(
            signer.as_str(),
            "microsoft windows"
                | "microsoft windows publisher"
                | "microsoft corporation"
                | "microsoft windows production pca 2011"
        )
    }

    pub fn label(&self) -> String {
        match self {
            SignatureStatus::Catalog { signer } => format!("catalog ({signer})"),
            SignatureStatus::Embedded { signer } => format!("embedded ({signer})"),
            SignatureStatus::Unsigned => "UNSIGNED".to_string(),
            SignatureStatus::Unknown { reason } => format!("unverified: {reason}"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DriverInfo {
    /// Short file name, e.g. `nvlddmkm.sys`.
    pub name: String,
    /// Full resolved path on disk.
    pub path: String,
    pub version: String,
    pub publisher: String,
    pub description: String,
    pub company: String,
    pub hash: Option<String>,
    pub base_address: u64,
    /// Image size from the PE header. Zero means unknown — never guess a range
    /// from it.
    pub size: u32,
    pub signature: SignatureStatus,
    pub is_os_driver: bool,
    pub category: DriverCategory,
    /// Set when the driver's hash or name matches a known-vulnerable driver.
    pub vulnerability: Option<VulnerableDriver>,
}

impl DriverInfo {
    /// True when `addr` falls inside this driver's loaded image. Requires a
    /// real size; an unknown size never claims an address.
    pub fn contains_address(&self, addr: u64) -> bool {
        self.base_address > 0
            && self.size > 0
            && addr >= self.base_address
            && addr < self.base_address.saturating_add(self.size as u64)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DriverCategory {
    Monitoring,
    Rgb,
    Overclocking,
    Antivirus,
    Network,
    Storage,
    Usb,
    Graphics,
    Virtualisation,
    AntiCheat,
    Other,
}

impl DriverCategory {
    pub fn label(&self) -> &'static str {
        match self {
            DriverCategory::Monitoring => "Monitoring",
            DriverCategory::Rgb => "RGB/Lighting",
            DriverCategory::Overclocking => "Overclocking",
            DriverCategory::Antivirus => "Security",
            DriverCategory::Network => "Network",
            DriverCategory::Storage => "Storage",
            DriverCategory::Usb => "USB",
            DriverCategory::Graphics => "Graphics",
            DriverCategory::Virtualisation => "Virtualisation",
            DriverCategory::AntiCheat => "Anti-cheat",
            DriverCategory::Other => "Other",
        }
    }

    /// Categories that compete for the same low-level hardware interfaces
    /// (SMBus/I2C sensor access) and therefore genuinely conflict with each
    /// other when several are loaded at once.
    pub fn contends_for_sensors(&self) -> bool {
        matches!(
            self,
            DriverCategory::Monitoring | DriverCategory::Rgb | DriverCategory::Overclocking
        )
    }
}

/// A match against the known-vulnerable driver corpus (loldrivers.io and the
/// Microsoft recommended driver blocklist).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerableDriver {
    pub matched_on: String,
    pub category: String,
    pub cves: Vec<String>,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Security posture
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SecurityPosture {
    /// Hypervisor-protected Code Integrity — the mitigation that actually stops
    /// a vulnerable driver being loaded.
    pub hvci_enabled: Option<bool>,
    pub vbs_enabled: Option<bool>,
    pub driver_blocklist_enabled: Option<bool>,
    pub test_signing: Option<bool>,
    pub secure_boot: Option<bool>,
    pub kernel_dma_protection: Option<bool>,
}

// ---------------------------------------------------------------------------
// Devices, services, changes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceState {
    pub name: String,
    pub device_id: String,
    pub problem_code: Option<u32>,
    pub problem_name: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceState {
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub exit_code: u32,
    pub service_specific_exit_code: u32,
    /// True only when the service manager also logged a failure for it — a
    /// stopped service holding a stale exit code is not a fault.
    pub corroborated_by_log: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemChange {
    pub name: String,
    pub date: DateTime<Utc>,
    pub change_type: ChangeType,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    WindowsUpdate,
    Software,
    Driver,
}

impl ChangeType {
    pub fn label(&self) -> &'static str {
        match self {
            ChangeType::WindowsUpdate => "Windows Update",
            ChangeType::Software => "Software",
            ChangeType::Driver => "Driver",
        }
    }
}

// ---------------------------------------------------------------------------
// Events and crashes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventLevel {
    Verbose,
    Information,
    Warning,
    Error,
    Critical,
}

impl EventLevel {
    pub fn label(&self) -> &'static str {
        match self {
            EventLevel::Verbose => "Verbose",
            EventLevel::Information => "Information",
            EventLevel::Warning => "Warning",
            EventLevel::Error => "Error",
            EventLevel::Critical => "Critical",
        }
    }

    /// Windows event log level codes (1=Critical .. 5=Verbose).
    pub fn from_win32(level: u32) -> Self {
        match level {
            1 => EventLevel::Critical,
            2 => EventLevel::Error,
            3 => EventLevel::Warning,
            4 => EventLevel::Information,
            _ => EventLevel::Verbose,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EventRecord {
    pub source: String,
    pub channel: String,
    pub event_id: u32,
    pub timestamp: DateTime<Utc>,
    pub level: EventLevel,
    pub message: String,
}

impl EventRecord {
    /// A stable identity for de-duplication across providers and channels.
    pub fn dedup_key(&self) -> (String, u32, i64) {
        (
            self.source.to_lowercase(),
            self.event_id,
            self.timestamp.timestamp(),
        )
    }

    pub fn is_bugcheck(&self) -> bool {
        self.event_id == 1001 && self.source.contains("BugCheck")
    }

    pub fn is_unexpected_shutdown(&self) -> bool {
        self.event_id == 41 || self.event_id == 6008
    }

    pub fn is_crash_marker(&self) -> bool {
        self.is_bugcheck() || self.is_unexpected_shutdown()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CrashRecord {
    pub timestamp: DateTime<Utc>,
    pub bugcheck_code: u32,
    pub bugcheck_name: String,
    pub parameters: [u64; 4],
    /// Module owning the faulting instruction pointer, resolved against the
    /// dump's own module list.
    pub faulting_module: Option<String>,
    pub faulting_address: Option<u64>,
    /// How the culprit was determined, so the report can be honest about it.
    pub attribution: CrashAttribution,
    pub dump_path: String,
    pub source: CrashSource,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum CrashSource {
    /// A kernel crash dump: the machine bugchecked.
    KernelDump,
    /// A user-mode application crash dump. A different and far less severe
    /// thing — conflating the two reported `0xC0000409 STACK_BUFFER_OVERRUN`
    /// (a user-mode exception) as a system stop code.
    UserDump,
    /// A crash marker in the event log with no dump behind it.
    EventLog,
}

impl CrashSource {
    /// Whether this represents the whole machine going down.
    pub fn is_system_crash(&self) -> bool {
        matches!(self, CrashSource::KernelDump | CrashSource::EventLog)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CrashAttribution {
    /// The faulting address fell inside a known module's image range.
    ModuleRange { module: String },
    /// The address resolved against an image range saved in a kernel triage
    /// dump. This remains valid after reboot or removal of the driver.
    DumpModuleRange {
        module: String,
        base_address: u64,
        size: u32,
    },
    /// The dump named the module but the address could not be bounded.
    DumpReported { module: String },
    /// No culprit could be established. This is a legitimate answer.
    Undetermined,
}

impl CrashAttribution {
    pub fn module(&self) -> Option<&str> {
        match self {
            CrashAttribution::ModuleRange { module }
            | CrashAttribution::DumpModuleRange { module, .. }
            | CrashAttribution::DumpReported { module } => Some(module),
            CrashAttribution::Undetermined => None,
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            CrashAttribution::ModuleRange { .. } => {
                "faulting address resolved inside the module's image range"
            }
            CrashAttribution::DumpModuleRange { .. } => {
                "faulting address resolved inside the module's image range recorded in the dump"
            }
            CrashAttribution::DumpReported { .. } => "module named by the crash dump",
            CrashAttribution::Undetermined => "no culprit could be established",
        }
    }
}

/// Events grouped around a crash. Produced by correlation *alongside* the
/// timeline rather than replacing it.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CrashWindow {
    pub crash: CrashRecord,
    pub window_minutes: i64,
    pub preceding: Vec<EventRecord>,
    pub following: Vec<EventRecord>,
}

// ---------------------------------------------------------------------------
// Findings, causes and scoring
// ---------------------------------------------------------------------------

/// The thing a rule reports. Findings sharing a `root_cause` are merged by the
/// engine into a single ranked `SuspectedCause`, so three rules pointing at one
/// hardware fault produce one strong verdict instead of three weak ones.
#[derive(Debug, Clone)]
pub struct Finding {
    pub title: String,
    pub root_cause: RootCause,
    /// Base severity on 0..100 before recency and corroboration are applied.
    pub weight: f32,
    pub evidence: Vec<Evidence>,
    pub explanation: String,
    pub recommendation: String,
    pub commands: Vec<RemediationCommand>,
    /// Most recent moment this finding was observed, for recency weighting.
    pub last_seen: Option<DateTime<Utc>>,
    pub rule: &'static str,
}

impl Finding {
    pub fn new(
        rule: &'static str,
        root_cause: RootCause,
        title: impl Into<String>,
        weight: f32,
    ) -> Self {
        Self {
            title: title.into(),
            root_cause,
            weight,
            evidence: Vec::new(),
            explanation: String::new(),
            recommendation: String::new(),
            commands: Vec::new(),
            last_seen: None,
            rule,
        }
    }

    pub fn explain(mut self, s: impl Into<String>) -> Self {
        self.explanation = s.into();
        self
    }

    pub fn recommend(mut self, s: impl Into<String>) -> Self {
        self.recommendation = s.into();
        self
    }

    pub fn evidence(mut self, e: Evidence) -> Self {
        self.evidence.push(e);
        self
    }

    pub fn evidence_all(mut self, e: impl IntoIterator<Item = Evidence>) -> Self {
        self.evidence.extend(e);
        self
    }

    pub fn command(mut self, label: impl Into<String>, cmd: impl Into<String>) -> Self {
        self.commands.push(RemediationCommand {
            label: label.into(),
            command: cmd.into(),
        });
        self
    }

    pub fn seen_at(mut self, at: Option<DateTime<Utc>>) -> Self {
        self.last_seen = at;
        self
    }
}

/// Corroboration key. Two findings with an equal `RootCause` describe the same
/// underlying problem and are combined.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RootCause {
    HardwareError,
    StorageFailure,
    MemoryError,
    DriverFault { module: String },
    SensorContention,
    VulnerableDriver,
    UnsignedDriver,
    PowerLoss,
    DeviceInstability,
    ServiceFailure,
    RecentRegression,
    InstabilityTrend,
    GraphicsTimeout,
    ApplicationFault { process: String },
}

impl RootCause {
    pub fn key(&self) -> String {
        match self {
            RootCause::HardwareError => "hardware-error".into(),
            RootCause::StorageFailure => "storage-failure".into(),
            RootCause::MemoryError => "memory-error".into(),
            RootCause::DriverFault { module } => format!("driver-fault:{}", module.to_lowercase()),
            RootCause::SensorContention => "sensor-contention".into(),
            RootCause::VulnerableDriver => "vulnerable-driver".into(),
            RootCause::UnsignedDriver => "unsigned-driver".into(),
            RootCause::PowerLoss => "power-loss".into(),
            RootCause::DeviceInstability => "device-instability".into(),
            RootCause::ServiceFailure => "service-failure".into(),
            RootCause::RecentRegression => "recent-regression".into(),
            RootCause::InstabilityTrend => "instability-trend".into(),
            RootCause::GraphicsTimeout => "graphics-timeout".into(),
            RootCause::ApplicationFault { process } => {
                format!("application-fault:{}", process.to_lowercase())
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Evidence {
    pub detail: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub source: Option<String>,
}

impl Evidence {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            timestamp: None,
            source: None,
        }
    }

    pub fn at(detail: impl Into<String>, timestamp: DateTime<Utc>) -> Self {
        Self {
            detail: detail.into(),
            timestamp: Some(timestamp),
            source: None,
        }
    }

    pub fn from(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemediationCommand {
    pub label: String,
    pub command: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SuspectedCause {
    pub id: String,
    pub title: String,
    /// 0..100, produced by combining every corroborating finding.
    pub score: f32,
    pub confidence: ConfidenceLevel,
    pub evidence: Vec<Evidence>,
    pub explanation: String,
    pub recommendation: String,
    pub commands: Vec<RemediationCommand>,
    /// Which rules contributed. More independent rules means more confidence.
    pub contributing_rules: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidenceLevel {
    Low,
    Moderate,
    High,
    Certain,
}

impl ConfidenceLevel {
    pub fn label(&self) -> &'static str {
        match self {
            ConfidenceLevel::Low => "Low",
            ConfidenceLevel::Moderate => "Moderate",
            ConfidenceLevel::High => "High",
            ConfidenceLevel::Certain => "Certain",
        }
    }

    /// Derived from the combined score and how many independent rules agree.
    pub fn derive(score: f32, corroborating_rules: usize) -> Self {
        match score {
            s if s >= 90.0 && corroborating_rules >= 2 => ConfidenceLevel::Certain,
            s if s >= 75.0 => ConfidenceLevel::High,
            s if s >= 50.0 => ConfidenceLevel::Moderate,
            _ => ConfidenceLevel::Low,
        }
    }
}

// ---------------------------------------------------------------------------
// Changepoint analysis
// ---------------------------------------------------------------------------

/// "Your system was stable until X" — the answer, rather than the data.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChangepointAnalysis {
    pub changepoint: DateTime<Utc>,
    pub crashes_before: usize,
    pub crashes_after: usize,
    pub stable_days_before: i64,
    /// Changes that landed within the suspect window around the changepoint.
    pub suspect_changes: Vec<SystemChange>,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiagnosticReport {
    pub generated_at: DateTime<Utc>,
    pub scan_window: ScanWindow,
    pub elevated: bool,
    pub system: SystemIdentity,
    pub firmware: FirmwareInfo,
    pub security: SecurityPosture,
    pub crashes: Vec<CrashRecord>,
    pub drivers: Vec<DriverInfo>,
    pub device_problems: Vec<DeviceState>,
    pub service_problems: Vec<ServiceState>,
    pub recent_changes: Vec<SystemChange>,
    pub suspected_causes: Vec<SuspectedCause>,
    /// The full collected record, never mutated by correlation.
    pub timeline: Vec<EventRecord>,
    /// Correlation output, produced alongside the timeline.
    pub correlations: Vec<CrashWindow>,
    pub changepoint: Option<ChangepointAnalysis>,
    pub collection: Vec<CollectionNote>,
}

impl DiagnosticReport {
    pub fn empty(window: ScanWindow) -> Self {
        Self {
            generated_at: Utc::now(),
            scan_window: window,
            elevated: false,
            system: SystemIdentity::default(),
            firmware: FirmwareInfo::default(),
            security: SecurityPosture::default(),
            crashes: Vec::new(),
            drivers: Vec::new(),
            device_problems: Vec::new(),
            service_problems: Vec::new(),
            recent_changes: Vec::new(),
            suspected_causes: Vec::new(),
            timeline: Vec::new(),
            correlations: Vec::new(),
            changepoint: None,
            collection: Vec::new(),
        }
    }

    /// Third-party drivers: everything not signed by Microsoft. Uses the signer
    /// identity rather than the file's folder.
    pub fn third_party_drivers(&self) -> impl Iterator<Item = &DriverInfo> {
        self.drivers.iter().filter(|d| !d.is_os_driver)
    }

    /// Crashes that took the whole machine down.
    pub fn system_crashes(&self) -> impl Iterator<Item = &CrashRecord> {
        self.crashes.iter().filter(|c| c.source.is_system_crash())
    }

    /// User-mode application crashes. A different and far less severe thing.
    pub fn application_crashes(&self) -> impl Iterator<Item = &CrashRecord> {
        self.crashes
            .iter()
            .filter(|c| c.source == CrashSource::UserDump)
    }

    pub fn incomplete_collection(&self) -> impl Iterator<Item = &CollectionNote> {
        self.collection.iter().filter(|n| !n.status.is_complete())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_window_bounds_and_decay() {
        let w = ScanWindow::last_days(10);
        assert!(w.contains(Utc::now() - Duration::days(5)));
        assert!(!w.contains(Utc::now() - Duration::days(20)));
        let fresh = w.recency_weight(w.until);
        let stale = w.recency_weight(w.since);
        assert!(fresh > stale, "recent evidence must outweigh old evidence");
        assert!((fresh - 1.0).abs() < 0.01);
        assert!((stale - 0.4).abs() < 0.01);
        // Evidence older than the window keeps the floor, it does not vanish.
        assert!((w.recency_weight(w.since - Duration::days(100)) - 0.4).abs() < 0.01);
    }

    #[test]
    fn signature_status_distinguishes_catalog_from_unsigned() {
        let cat = SignatureStatus::Catalog {
            signer: "Microsoft Windows Publisher".into(),
        };
        assert!(cat.is_signed());
        assert!(cat.is_microsoft());
        let oem = SignatureStatus::Embedded {
            signer: "NVIDIA Corporation".into(),
        };
        assert!(oem.is_signed());
        assert!(!oem.is_microsoft());
        assert!(!SignatureStatus::Unsigned.is_signed());
        assert!(
            !SignatureStatus::Unknown {
                reason: "locked".into()
            }
            .is_signed()
        );
        // An unverifiable file must never be reported as Microsoft's.
        assert!(
            !SignatureStatus::Unknown {
                reason: "locked".into()
            }
            .is_microsoft()
        );
    }

    /// Real signer strings taken from a live Windows install.
    #[test]
    fn whql_attestation_is_not_an_operating_system_signer() {
        let os = SignatureStatus::Catalog {
            signer: "Microsoft Windows".into(),
        };
        assert!(
            os.is_microsoft(),
            "core OS drivers are signed by Microsoft Windows"
        );

        // NVIDIA, ASUS and MSI drivers all carry this signer. Treating it as an
        // OS signature hid every vendor driver from the report, including the
        // known-vulnerable ones.
        let whql = SignatureStatus::Catalog {
            signer: "Microsoft Windows Hardware Compatibility Publisher".into(),
        };
        assert!(whql.is_signed());
        assert!(!whql.is_microsoft());
        let vendor = SignatureStatus::Embedded {
            signer: "Samsung Electronics CO., LTD.".into(),
        };
        assert!(!vendor.is_microsoft());
    }

    #[test]
    fn address_containment_requires_a_real_size() {
        let mut d = DriverInfo {
            name: "x.sys".into(),
            path: "C:\\x.sys".into(),
            version: "1".into(),
            publisher: String::new(),
            description: String::new(),
            company: String::new(),
            hash: None,
            base_address: 0xfffff800_0000_0000,
            size: 0,
            signature: SignatureStatus::Unsigned,
            is_os_driver: false,
            category: DriverCategory::Other,
            vulnerability: None,
        };
        // Size zero must never claim an address — this was the 100 MB guess.
        assert!(!d.contains_address(0xfffff800_0000_1000));
        d.size = 0x2000;
        assert!(d.contains_address(0xfffff800_0000_1000));
        assert!(!d.contains_address(0xfffff800_0000_3000));
    }

    #[test]
    fn confidence_needs_corroboration_for_certainty() {
        assert_eq!(ConfidenceLevel::derive(95.0, 1), ConfidenceLevel::High);
        assert_eq!(ConfidenceLevel::derive(95.0, 2), ConfidenceLevel::Certain);
        assert_eq!(ConfidenceLevel::derive(60.0, 3), ConfidenceLevel::Moderate);
        assert_eq!(ConfidenceLevel::derive(20.0, 1), ConfidenceLevel::Low);
    }
}
