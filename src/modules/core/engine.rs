//! Scan orchestration.
//!
//! Three changes worth calling out:
//!
//! * Providers run concurrently. The white paper described "parallel execution
//!   of all registered Providers"; the implementation was strictly sequential.
//! * Correlation writes to `report.correlations` and leaves `report.timeline`
//!   alone, so rules see everything that was collected.
//! * Findings go through the scorer, which merges corroborating rules and ranks
//!   the result. Causes used to be emitted in rule-registration order.

use indicatif::ProgressBar;

use crate::modules::analysis::{changepoint, correlation_engine, rules};
use crate::modules::core::models::*;
use crate::modules::core::scoring;
use crate::modules::core::traits::*;
use crate::modules::providers::*;

/// Service Control Manager event ids that mean a service actually failed.
const SCM_FAILURE_EVENTS: &[u32] = &[
    7000, 7001, 7009, 7011, 7022, 7023, 7024, 7026, 7031, 7032, 7034,
];

pub struct WinSleuthEngine {
    system_provider: Box<dyn SystemInventoryProvider>,
    firmware_provider: Box<dyn FirmwareInventoryProvider>,
    driver_provider: Box<dyn DriverInventoryProvider>,
    device_provider: Box<dyn DeviceInspectorProvider>,
    service_provider: Box<dyn ServiceProvider>,
    change_provider: Box<dyn ChangeProvider>,
    minidump_provider: Box<dyn MinidumpProvider>,
    security_provider: Box<dyn SecurityPostureProvider>,
    event_providers: Vec<Box<dyn EventLogProvider>>,
    rules: Vec<Box<dyn HeuristicRule>>,
    progress: Option<ProgressBar>,
    window: ScanWindow,
    elevated: bool,
}

impl WinSleuthEngine {
    /// The one place providers and rules are registered.
    ///
    /// Both the CLI and the desktop UI previously repeated seventeen lines of
    /// construction verbatim, and the two lists were free to drift apart.
    pub fn with_defaults(window: ScanWindow) -> Self {
        let mut engine = Self {
            system_provider: Box::new(system_inventory::WindowsSystemInventory),
            firmware_provider: Box::new(firmware_inventory::WindowsFirmwareInventory),
            driver_provider: Box::new(driver_inventory::WindowsDriverInventory::new()),
            device_provider: Box::new(device_inspector::WindowsDeviceInspector),
            service_provider: Box::new(service_inspector::WindowsServiceInspector),
            change_provider: Box::new(change_tracker::WindowsChangeTracker),
            minidump_provider: Box::new(minidump_reader::WindowsMinidumpReader::new()),
            security_provider: Box::new(security_posture::WindowsSecurityPosture),
            event_providers: Vec::new(),
            rules: Vec::new(),
            progress: None,
            window,
            elevated: crate::modules::core::privilege::is_elevated(),
        };
        engine.add_event_provider(Box::new(eventlog_reader::WindowsEventLogReader::new()));
        engine.add_event_provider(Box::new(reliability_reader::WindowsReliabilityReader));
        for rule in rules::all_rules() {
            engine.add_rule(rule);
        }

        engine
    }

    /// Build an engine from explicit providers, for tests and alternative hosts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        system: Box<dyn SystemInventoryProvider>,
        firmware: Box<dyn FirmwareInventoryProvider>,
        driver: Box<dyn DriverInventoryProvider>,
        device: Box<dyn DeviceInspectorProvider>,
        service: Box<dyn ServiceProvider>,
        change: Box<dyn ChangeProvider>,
        minidump: Box<dyn MinidumpProvider>,
        security: Box<dyn SecurityPostureProvider>,
        window: ScanWindow,
    ) -> Self {
        Self {
            system_provider: system,
            firmware_provider: firmware,
            driver_provider: driver,
            device_provider: device,
            service_provider: service,
            change_provider: change,
            minidump_provider: minidump,
            security_provider: security,
            event_providers: Vec::new(),
            rules: Vec::new(),
            progress: None,
            window,
            elevated: false,
        }
    }

    /// Swap the driver provider, used by `--no-hashes`.
    pub fn set_driver_provider(&mut self, provider: Box<dyn DriverInventoryProvider>) {
        self.driver_provider = provider;
    }

    pub fn set_progress_bar(&mut self, bar: ProgressBar) {
        self.progress = Some(bar);
    }

    pub fn add_event_provider(&mut self, provider: Box<dyn EventLogProvider>) {
        self.event_providers.push(provider);
    }

    pub fn add_rule(&mut self, rule: Box<dyn HeuristicRule>) {
        self.rules.push(rule);
    }

    pub fn window(&self) -> ScanWindow {
        self.window
    }

    fn step(&self, message: &str) {
        if let Some(bar) = &self.progress {
            bar.inc(1);
            bar.set_message(message.to_string());
        }
    }

    pub fn run_scan(&self) -> DiagnosticReport {
        let mut report = DiagnosticReport::empty(self.window);
        report.elevated = self.elevated;

        // ------------------------------------------------------------------
        // Collection, concurrently. Each provider opens its own WMI/COM
        // connection, so they are safe to run side by side.
        // ------------------------------------------------------------------
        if let Some(bar) = &self.progress {
            bar.set_message("Collecting system state...".to_string());
        }

        let (system, firmware, security, drivers, devices, services, changes, events) =
            std::thread::scope(|scope| {
                let system = scope.spawn(|| self.system_provider.collect_system_identity());
                let firmware = scope.spawn(|| self.firmware_provider.collect_firmware_info());
                let security = scope.spawn(|| self.security_provider.collect_posture());
                let drivers = scope.spawn(|| self.driver_provider.collect_drivers());
                let devices = scope.spawn(|| self.device_provider.collect_device_problems());
                let services = scope.spawn(|| {
                    self.service_provider
                        .collect_problematic_services(&self.window)
                });
                let changes =
                    scope.spawn(|| self.change_provider.collect_recent_changes(&self.window));
                let events = scope.spawn(|| self.collect_events());

                (
                    join(system),
                    join(firmware),
                    join(security),
                    join(drivers),
                    join(devices),
                    join(services),
                    join(changes),
                    events.join().unwrap_or_default(),
                )
            });
        self.step("Reading system identity");
        report.system = system.value;
        report
            .collection
            .push(note("SystemInventory", system.status, 1));
        report.firmware = firmware.value;
        report.collection.push(note("Firmware", firmware.status, 1));
        report.security = security.value;
        report
            .collection
            .push(note("SecurityPosture", security.status, 1));
        self.step("Enumerating drivers");
        report
            .collection
            .push(note("Drivers", drivers.status, drivers.value.len()));
        report.drivers = drivers.value;
        self.step("Checking devices");
        report
            .collection
            .push(note("Devices", devices.status, devices.value.len()));
        report.device_problems = devices.value;
        self.step("Checking services");
        report
            .collection
            .push(note("Services", services.status, services.value.len()));
        report.service_problems = services.value;
        self.step("Reading recent changes");
        report
            .collection
            .push(note("Changes", changes.status, changes.value.len()));
        report.recent_changes = changes.value;
        self.step("Reading event logs");
        let (timeline, event_notes) = events;
        for (name, status, count) in event_notes {
            report.collection.push(CollectionNote {
                provider: name,
                status,
                items: count,
            });
        }
        report.timeline = timeline;

        // ------------------------------------------------------------------
        // Crash dumps. These need the module list to resolve a culprit address
        // against a real image range, so they run after driver enumeration.
        // ------------------------------------------------------------------
        self.step("Analysing crash dumps");
        let crashes = self
            .minidump_provider
            .parse_minidumps(&self.window, &report.drivers);
        report
            .collection
            .push(note("CrashDumps", crashes.status, crashes.value.len()));
        report.crashes = crashes.value;

        // ------------------------------------------------------------------
        // Post-processing
        // ------------------------------------------------------------------
        self.step("Correlating events");
        corroborate_services(&mut report);
        report.correlations = correlation_engine::correlate(&report);
        let crash_times: Vec<_> = report
            .correlations
            .iter()
            .map(|w| w.crash.timestamp)
            .collect();
        report.changepoint =
            changepoint::analyse(&crash_times, &report.recent_changes, &self.window);
        self.step("Evaluating rules");
        let findings: Vec<Finding> = self
            .rules
            .iter()
            .flat_map(|rule| rule.evaluate(&report))
            .collect();
        report.suspected_causes = scoring::combine(findings, &self.window);
        if let Some(bar) = &self.progress {
            bar.finish_with_message("Scan complete.");
        }

        report
    }

    /// Merge every event provider, de-duplicated and ordered.
    fn collect_events(&self) -> (Vec<EventRecord>, Vec<(String, CollectionStatus, usize)>) {
        let mut all = Vec::new();
        let mut notes = Vec::new();
        for provider in &self.event_providers {
            let collected = provider.collect_events(&self.window);
            notes.push((
                provider.name().to_string(),
                collected.status,
                collected.value.len(),
            ));
            all.extend(collected.value);
        }

        let mut seen = std::collections::HashSet::new();
        all.retain(|event| seen.insert(event.dedup_key()));
        all.sort_by_key(|event| event.timestamp);

        (all, notes)
    }
}

fn join<T>(handle: std::thread::ScopedJoinHandle<'_, Collected<T>>) -> Collected<T>
where
    T: Default,
{
    handle
        .join()
        .unwrap_or_else(|_| Collected::failed(T::default(), "the collection thread panicked"))
}

fn note(provider: &str, status: CollectionStatus, items: usize) -> CollectionNote {
    CollectionNote {
        provider: provider.to_string(),
        status,
        items,
    }
}

/// Mark services the Service Control Manager also logged as failing.
///
/// A stopped service holding a stale exit code is not evidence of anything; it
/// was reporting those that made "System Service Failures" appear on healthy
/// machines.
fn corroborate_services(report: &mut DiagnosticReport) {
    let scm_events: Vec<&EventRecord> = report
        .timeline
        .iter()
        .filter(|e| {
            e.source.contains("Service Control Manager") && SCM_FAILURE_EVENTS.contains(&e.event_id)
        })
        .collect();

    if scm_events.is_empty() {
        return;
    }

    let corroborated: Vec<bool> = report
        .service_problems
        .iter()
        .map(|service| {
            scm_events.iter().any(|event| {
                let message = event.message.to_lowercase();
                (!service.display_name.is_empty()
                    && message.contains(&service.display_name.to_lowercase()))
                    || (!service.name.is_empty() && message.contains(&service.name.to_lowercase()))
            })
        })
        .collect();

    for (service, flag) in report.service_problems.iter_mut().zip(corroborated) {
        service.corroborated_by_log = flag;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::core::fixtures;
    use chrono::Utc;

    #[test]
    fn services_are_corroborated_only_when_the_log_names_them() {
        let mut report = fixtures::healthy_machine();
        report.service_problems = vec![
            fixtures::service("AudioSrv", 1067, false),
            fixtures::service("Unmentioned", 1053, false),
        ];
        report.timeline.push(EventRecord {
            source: "Service Control Manager".into(),
            channel: "System".into(),
            event_id: 7031,
            timestamp: Utc::now(),
            level: EventLevel::Error,
            message: "The AudioSrv service terminated unexpectedly.".into(),
        });
        corroborate_services(&mut report);
        assert!(report.service_problems[0].corroborated_by_log);
        assert!(!report.service_problems[1].corroborated_by_log);
    }

    #[test]
    fn unrelated_scm_events_do_not_corroborate() {
        let mut report = fixtures::healthy_machine();
        report.service_problems = vec![fixtures::service("AudioSrv", 1067, false)];
        // 7036 is a routine state change, not a failure.
        report.timeline.push(EventRecord {
            source: "Service Control Manager".into(),
            channel: "System".into(),
            event_id: 7036,
            timestamp: Utc::now(),
            level: EventLevel::Information,
            message: "The AudioSrv service entered the stopped state.".into(),
        });
        corroborate_services(&mut report);
        assert!(!report.service_problems[0].corroborated_by_log);
    }

    #[test]
    fn the_default_engine_registers_every_rule() {
        let engine = WinSleuthEngine::with_defaults(ScanWindow::last_days(7));
        assert_eq!(engine.rules.len(), rules::all_rules().len());
        assert_eq!(engine.event_providers.len(), 2);
    }
}
