use crate::modules::*;

pub trait SystemInventoryProvider {
    fn collect_system_identity(&self) -> SystemIdentity;
}

pub trait FirmwareInventoryProvider {
    fn collect_firmware_info(&self) -> FirmwareInfo;
}

pub trait DriverInventoryProvider {
    fn collect_drivers(&self) -> Vec<DriverInfo>;
}

pub trait EventLogProvider {
    fn collect_events(&self) -> Vec<EventRecord>;
}

pub trait DeviceInspectorProvider {
    fn collect_device_problems(&self) -> Vec<DeviceState>;
}

pub trait ServiceProvider {
    fn collect_problematic_services(&self) -> Vec<ServiceState>;
}

pub trait ChangeProvider {
    fn collect_recent_changes(&self, days: i64) -> Vec<SystemChange>;
}

pub trait MinidumpProvider {
    fn parse_minidumps(&self) -> Vec<CrashRecord>;
}

pub trait HeuristicRule {
    fn evaluate(&self, report: &DiagnosticReport) -> Option<SuspectedCause>;
}
