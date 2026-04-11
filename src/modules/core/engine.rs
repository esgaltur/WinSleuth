use crate::modules::*;
use crate::modules::core::traits::*;
use indicatif::ProgressBar;

// Dependency Injection: The Engine relies on abstractions, not concretions.
pub struct WinSleuthEngine {
    system_provider: Box<dyn SystemInventoryProvider>,
    firmware_provider: Box<dyn FirmwareInventoryProvider>,
    driver_provider: Box<dyn DriverInventoryProvider>,
    event_providers: Vec<Box<dyn EventLogProvider>>,
    device_provider: Box<dyn DeviceInspectorProvider>,
    service_provider: Box<dyn ServiceProvider>,
    change_provider: Box<dyn ChangeProvider>,
    minidump_provider: Box<dyn MinidumpProvider>,
    rules: Vec<Box<dyn HeuristicRule>>,
    progress_bar: Option<ProgressBar>,
}

impl WinSleuthEngine {
    pub fn new(
        system: Box<dyn SystemInventoryProvider>,
        firmware: Box<dyn FirmwareInventoryProvider>,
        driver: Box<dyn DriverInventoryProvider>,
        device: Box<dyn DeviceInspectorProvider>,
        service: Box<dyn ServiceProvider>,
        change: Box<dyn ChangeProvider>,
        minidump: Box<dyn MinidumpProvider>,
    ) -> Self {
        Self {
            system_provider: system,
            firmware_provider: firmware,
            driver_provider: driver,
            event_providers: Vec::new(),
            device_provider: device,
            service_provider: service,
            change_provider: change,
            minidump_provider: minidump,
            rules: Vec::new(),
            progress_bar: None,
        }
    }

    pub fn set_progress_bar(&mut self, pb: ProgressBar) {
        self.progress_bar = Some(pb);
    }


    pub fn add_event_provider(&mut self, provider: Box<dyn EventLogProvider>) {
        self.event_providers.push(provider);
    }

    pub fn add_rule(&mut self, rule: Box<dyn HeuristicRule>) {
        self.rules.push(rule);
    }

    pub fn run_scan(&self) -> DiagnosticReport {
        if let Some(ref pb) = self.progress_bar {
            pb.set_message("Collecting system identity...");
        }
        let system = self.system_provider.collect_system_identity();
        if let Some(ref pb) = self.progress_bar {
            pb.inc(1);
            pb.set_message("Collecting firmware info...");
        }
        let firmware = self.firmware_provider.collect_firmware_info();
        if let Some(ref pb) = self.progress_bar {
            pb.inc(1);
            pb.set_message("Collecting drivers...");
        }
        let drivers = self.driver_provider.collect_drivers();
        if let Some(ref pb) = self.progress_bar {
            pb.inc(1);
            pb.set_message("Collecting device problems...");
        }
        let device_problems = self.device_provider.collect_device_problems();
        if let Some(ref pb) = self.progress_bar {
            pb.inc(1);
            pb.set_message("Collecting service problems...");
        }
        let service_problems = self.service_provider.collect_problematic_services();
        if let Some(ref pb) = self.progress_bar {
            pb.inc(1);
            pb.set_message("Collecting recent changes...");
        }
        let recent_changes = self.change_provider.collect_recent_changes(30); // Default to 30 days for analysis context
        if let Some(ref pb) = self.progress_bar {
            pb.inc(1);
            pb.set_message("Parsing minidumps...");
        }
        let crashes = self.minidump_provider.parse_minidumps();
        if let Some(ref pb) = self.progress_bar {
            pb.inc(1);
            pb.set_message("Collecting events...");
        }

        let mut timeline = Vec::new();
        for provider in &self.event_providers {
            timeline.extend(provider.collect_events());
        }

        if let Some(ref pb) = self.progress_bar {
            pb.inc(1);
            pb.set_message("Correlating events...");
        }

        let mut report = DiagnosticReport {
            system,
            firmware,
            crashes,
            drivers,
            device_problems,
            service_problems,
            recent_changes,
            suspected_causes: Vec::new(),
            timeline,
        };

        // Correlate events based on crashes and critical rules
        correlation_engine::correlate_events(&mut report);

        if let Some(ref pb) = self.progress_bar {
            pb.inc(1);
            pb.set_message("Evaluating rules...");
        }

        // Run analysis using injected Strategy rules
        let mut causes = Vec::new();
        for rule in &self.rules {
            if let Some(cause) = rule.evaluate(&report) {
                causes.push(cause);
            }
        }
        report.suspected_causes = causes;

        if let Some(ref pb) = self.progress_bar {
            pb.finish_with_message("Scan completed.");
        }

        report
    }
}
