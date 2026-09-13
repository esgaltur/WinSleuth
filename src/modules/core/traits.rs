use crate::modules::core::models::*;

/// Every provider is `Send + Sync` so the engine can fan collection out across
/// threads. Each implementation creates its own WMI/COM connection, so they are
/// safe to run concurrently.
pub trait SystemInventoryProvider: Send + Sync {
    fn collect_system_identity(&self) -> Collected<SystemIdentity>;
}

pub trait FirmwareInventoryProvider: Send + Sync {
    fn collect_firmware_info(&self) -> Collected<FirmwareInfo>;
}

pub trait DriverInventoryProvider: Send + Sync {
    fn collect_drivers(&self) -> Collected<Vec<DriverInfo>>;
}

pub trait EventLogProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn collect_events(&self, window: &ScanWindow) -> Collected<Vec<EventRecord>>;
}

pub trait DeviceInspectorProvider: Send + Sync {
    fn collect_device_problems(&self) -> Collected<Vec<DeviceState>>;
}

pub trait ServiceProvider: Send + Sync {
    fn collect_problematic_services(&self, window: &ScanWindow) -> Collected<Vec<ServiceState>>;
}

pub trait ChangeProvider: Send + Sync {
    fn collect_recent_changes(&self, window: &ScanWindow) -> Collected<Vec<SystemChange>>;
}

pub trait MinidumpProvider: Send + Sync {
    /// `modules` is the current inventory, available for enrichment only.
    /// Kernel attribution must use the module map saved in the dump: neither
    /// current addresses nor the dump file's modification time prove boot identity.
    fn parse_minidumps(
        &self,
        window: &ScanWindow,
        modules: &[DriverInfo],
    ) -> Collected<Vec<CrashRecord>>;
}

pub trait SecurityPostureProvider: Send + Sync {
    fn collect_posture(&self) -> Collected<SecurityPosture>;
}

/// A heuristic rule. Returns *findings*, not finished causes: the engine merges
/// findings that share a `RootCause` so corroborating rules reinforce one
/// verdict instead of producing several competing ones.
///
/// Returning a `Vec` also lets one rule report several distinct instances —
/// two failing disks are two findings, not one merged sentence.
pub trait HeuristicRule: Send + Sync {
    fn name(&self) -> &'static str;
    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding>;
}
