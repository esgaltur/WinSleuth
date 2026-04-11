use eframe::egui;
use std::sync::{Arc, Mutex};
use std::thread;
use crate::modules::{
    core::models::DiagnosticReport,
    providers::system_inventory::WindowsSystemInventory,
    providers::firmware_inventory::WindowsFirmwareInventory,
    providers::driver_inventory::WindowsDriverInventory,
    providers::eventlog_reader::WindowsEventLogReader,
    providers::device_inspector::WindowsDeviceInspector,
    providers::minidump_reader::WindowsMinidumpReader,
    providers::reliability_reader::WindowsReliabilityReader,
    providers::service_inspector::WindowsServiceInspector,
    providers::change_tracker::WindowsChangeTracker,
    core::engine::WinSleuthEngine,
    analysis::rules::{MonitoringConflictRule, UnsignedDriverRule, WheaErrorRule, BugCheckRule, CrashCorrelationRule, DeviceReEnumerationRule, ServiceFailureRule, ReliabilityScoreRule, DiskErrorRule, RecentChangeCorrelationRule},
};

pub struct WinSleuthApp {
    report: Arc<Mutex<Option<DiagnosticReport>>>,
    is_scanning: Arc<Mutex<bool>>,
}

impl WinSleuthApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            report: Arc::new(Mutex::new(None)),
            is_scanning: Arc::new(Mutex::new(false)),
        }
    }

    fn run_scan_async(&mut self, ctx: egui::Context) {
        let is_scanning = self.is_scanning.clone();
        let report_mutex = self.report.clone();
        
        *is_scanning.lock().unwrap() = true;
        
        thread::spawn(move || {
            let system_provider = Box::new(WindowsSystemInventory);
            let firmware_provider = Box::new(WindowsFirmwareInventory);
            let driver_provider = Box::new(WindowsDriverInventory);
            let device_provider = Box::new(WindowsDeviceInspector);
            let service_provider = Box::new(WindowsServiceInspector);
            let change_provider = Box::new(WindowsChangeTracker);
            let minidump_provider = Box::new(WindowsMinidumpReader);

            let mut engine = WinSleuthEngine::new(
                system_provider,
                firmware_provider,
                driver_provider,
                device_provider,
                service_provider,
                change_provider,
                minidump_provider,
            );

            engine.add_event_provider(Box::new(WindowsEventLogReader));
            engine.add_event_provider(Box::new(WindowsReliabilityReader));

            engine.add_rule(Box::new(MonitoringConflictRule));
            engine.add_rule(Box::new(UnsignedDriverRule));
            engine.add_rule(Box::new(WheaErrorRule));
            engine.add_rule(Box::new(BugCheckRule));
            engine.add_rule(Box::new(CrashCorrelationRule));
            engine.add_rule(Box::new(DeviceReEnumerationRule));
            engine.add_rule(Box::new(ServiceFailureRule));
            engine.add_rule(Box::new(ReliabilityScoreRule));
            engine.add_rule(Box::new(DiskErrorRule));
            engine.add_rule(Box::new(RecentChangeCorrelationRule));

            let scan_result = engine.run_scan();
            *report_mutex.lock().unwrap() = Some(scan_result);
            *is_scanning.lock().unwrap() = false;
            
            // Request a repaint to update the UI once the scan finishes
            ctx.request_repaint();
        });
    }
}

impl eframe::App for WinSleuthApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.heading("Instability WinSleuth");
        
        let is_scanning = *self.is_scanning.lock().unwrap();
        
        ui.add_enabled_ui(!is_scanning, |ui| {
            if ui.button("Run Diagnostic Scan").clicked() {
                self.run_scan_async(ui.ctx().clone());
            }
        });
        
        if is_scanning {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Scanning system... This may take a moment.");
            });
        }
        
        ui.separator();
        
        let report_guard = self.report.lock().unwrap();
        if let Some(report) = &*report_guard {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.heading("System Identity");
                ui.label(format!("CPU: {}", report.system.cpu_model));
                ui.label(format!("Motherboard: {} {}", report.system.motherboard_vendor, report.system.motherboard_model));
                ui.label(format!("BIOS: {} (v{}) dated {}", report.firmware.vendor, report.firmware.version, report.firmware.date));
                
                ui.add_space(10.0);
                ui.heading("Ranked Causes");
                if report.suspected_causes.is_empty() {
                    ui.label("No significant instability patterns detected.");
                } else {
                    for cause in &report.suspected_causes {
                        ui.group(|ui| {
                            ui.strong(format!("[{:?}] {} (Score: {:.1})", cause.confidence, cause.title, cause.score));
                            ui.label(format!("Explanation: {}", cause.explanation));
                            ui.label(format!("Evidence: {}", cause.evidence.join(", ")));
                            ui.label(format!("Recommendation: {}", cause.recommendation));
                        });
                    }
                }
                
                ui.add_space(10.0);
                ui.heading("Suspicious Drivers");
                for driver in &report.drivers {
                    ui.group(|ui| {
                        ui.strong(format!("[{:?}] {}", driver.category, driver.name));
                        ui.label(format!("Company: {}, Publisher: {}", driver.company, driver.publisher));
                        ui.label(format!("Description: {}", driver.description));
                        ui.label(format!("SHA256: {}", driver.hash));
                        ui.label(format!("Signed: {}", driver.signed));
                    });
                }                
                ui.add_space(10.0);
                ui.heading("Device Problems");
                for device in &report.device_problems {
                    ui.label(format!("- {} (ID: {}): {:?}", device.name, device.device_id, device.problem_code));
                }
                
                ui.add_space(10.0);
                ui.heading("Timeline Events");
                for event in &report.timeline {
                    ui.label(format!("- [{}] {}: ID {}", event.timestamp, event.source, event.event_id));
                }
            });
        } else if !is_scanning {
            ui.label("Click the button above to start a scan. This will take a moment.");
        }
    }
}
