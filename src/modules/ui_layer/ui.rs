//! Desktop interface.
//!
//! Uses `WinSleuthEngine::with_defaults`, so it can no longer drift away from
//! what the CLI runs — the two front-ends previously repeated seventeen lines
//! of provider and rule registration each.

use std::sync::{Arc, Mutex};

use eframe::egui;

use crate::modules::core::engine::WinSleuthEngine;
use crate::modules::core::models::*;
use crate::modules::core::privilege;
use crate::modules::providers::device_inspector;

#[derive(Default)]
enum ScanState {
    #[default]
    Idle,
    Running,
    Done(Box<DiagnosticReport>),
    Failed(String),
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Causes,
    Crashes,
    Drivers,
    Timeline,
    Coverage,
}

pub struct WinSleuthApp {
    state: Arc<Mutex<ScanState>>,
    tab: Tab,
    days: u32,
    driver_filter: String,
    third_party_only: bool,
    elevated: bool,
}

impl WinSleuthApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ScanState::Idle)),
            tab: Tab::Causes,
            days: 7,
            driver_filter: String::new(),
            third_party_only: true,
            elevated: privilege::is_elevated(),
        }
    }

    fn start_scan(&self, ctx: egui::Context) {
        let state = self.state.clone();
        let days = self.days as i64;
        if let Ok(mut guard) = state.lock() {
            if matches!(*guard, ScanState::Running) {
                return;
            }
            *guard = ScanState::Running;
        }
        ctx.request_repaint();
        std::thread::spawn(move || {
            let engine = WinSleuthEngine::with_defaults(ScanWindow::last_days(days));
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| engine.run_scan()));
            if let Ok(mut guard) = state.lock() {
                *guard = match outcome {
                    Ok(report) => ScanState::Done(Box::new(report)),
                    Err(_) => ScanState::Failed("The scan failed partway through.".to_string()),
                };
            }
            ctx.request_repaint();
        });
    }

    fn save_report(report: &DiagnosticReport, html: bool) -> Option<std::path::PathBuf> {
        let dir = crate::modules::core::store::data_dir();
        std::fs::create_dir_all(&dir).ok()?;
        let path = dir.join(format!(
            "report-{}.{}",
            report.generated_at.format("%Y%m%dT%H%M%SZ"),
            if html { "html" } else { "txt" }
        ));
        let contents = if html {
            crate::modules::ui_layer::html_report::render(report)
        } else {
            crate::modules::ui_layer::reporting::render_text(report)
        };
        crate::modules::ui_layer::reporting::write_utf8(&path, &contents).ok()?;
        Some(path)
    }
}

impl eframe::App for WinSleuthApp {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root.ctx().clone();
        egui::Panel::top("controls").show_inside(root, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("WinSleuth");
                ui.separator();
                let running = matches!(*self.state.lock().unwrap(), ScanState::Running);
                ui.add_enabled_ui(!running, |ui| {
                    if ui.button("Run scan").clicked() {
                        self.start_scan(ctx.clone());
                    }
                });
                ui.label("Days:");
                ui.add(egui::DragValue::new(&mut self.days).range(1..=365));
                if running {
                    ui.spinner();
                    ui.label("Collecting evidence…");
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !self.elevated {
                        ui.colored_label(
                            egui::Color32::from_rgb(200, 140, 40),
                            "Not elevated — findings will be incomplete",
                        );
                    }
                });
            });
            ui.add_space(6.0);
        });
        let guard = self.state.lock().unwrap();
        let report = match &*guard {
            ScanState::Done(report) => Some(report.as_ref().clone()),
            _ => None,
        };
        let status = match &*guard {
            ScanState::Idle => Some("Run a scan to begin.".to_string()),
            ScanState::Running => Some("Scanning…".to_string()),
            ScanState::Failed(message) => Some(message.clone()),
            ScanState::Done(_) => None,
        };
        drop(guard);
        let Some(report) = report else {
            egui::CentralPanel::default().show_inside(root, |ui| {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(status.unwrap_or_default());
                });
            });
            return;
        };
        egui::Panel::top("tabs").show_inside(root, |ui| {
            ui.horizontal(|ui| {
                for (tab, label) in [
                    (
                        Tab::Causes,
                        format!("Causes ({})", report.suspected_causes.len()),
                    ),
                    (Tab::Crashes, format!("Crashes ({})", report.crashes.len())),
                    (
                        Tab::Drivers,
                        format!("Drivers ({})", report.third_party_drivers().count()),
                    ),
                    (
                        Tab::Timeline,
                        format!("Timeline ({})", report.timeline.len()),
                    ),
                    (Tab::Coverage, "Coverage".to_string()),
                ] {
                    ui.selectable_value(&mut self.tab, tab, label);
                }
            });
        });
        egui::Panel::bottom("actions").show_inside(root, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Save HTML report").clicked()
                    && let Some(path) = Self::save_report(&report, true)
                {
                    let _ = open_folder(&path);
                }
                if ui.button("Save text report").clicked()
                    && let Some(path) = Self::save_report(&report, false)
                {
                    let _ = open_folder(&path);
                }
                ui.label(format!(
                    "{} — {} · {} {}",
                    report.system.hostname,
                    report.system.os_caption,
                    report.system.motherboard_vendor,
                    report.system.motherboard_model
                ));
            });
        });
        egui::CentralPanel::default().show_inside(root, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.tab {
                Tab::Causes => self.causes_tab(ui, &report),
                Tab::Crashes => crashes_tab(ui, &report),
                Tab::Drivers => self.drivers_tab(ui, &report),
                Tab::Timeline => timeline_tab(ui, &report),
                Tab::Coverage => coverage_tab(ui, &report),
            });
        });
    }
}

impl WinSleuthApp {
    fn causes_tab(&mut self, ui: &mut egui::Ui, report: &DiagnosticReport) {
        if let Some(analysis) = &report.changepoint {
            ui.group(|ui| {
                ui.strong("When it changed");
                ui.label(&analysis.summary);
            });
            ui.add_space(8.0);
        }

        if report.suspected_causes.is_empty() {
            ui.label("No instability patterns were found in this window.");
            if !report.elevated {
                ui.label(
                    "An unelevated scan can miss the evidence entirely. Re-run as \
                     Administrator before concluding the machine is healthy.",
                );
            }
            return;
        }

        for (index, cause) in report.suspected_causes.iter().enumerate() {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(format!("{}. {}", index + 1, cause.title));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(format!("{:.0}/100", cause.score));
                        ui.colored_label(
                            confidence_colour(cause.confidence),
                            cause.confidence.label(),
                        );
                    });
                });
                ui.label(&cause.explanation);
                ui.add_space(4.0);
                egui::CollapsingHeader::new(format!("Evidence ({})", cause.evidence.len()))
                    .id_salt(&cause.id)
                    .show(ui, |ui| {
                        for item in &cause.evidence {
                            let when = item
                                .timestamp
                                .map(|t| format!("{}  ", t.format("%Y-%m-%d %H:%M")))
                                .unwrap_or_default();
                            ui.label(format!("• {when}{}", item.detail));
                        }
                    });
                ui.add_space(4.0);
                ui.strong("What to do");
                ui.label(&cause.recommendation);
                for command in &cause.commands {
                    ui.horizontal(|ui| {
                        ui.code(&command.command);
                        if ui.small_button("Copy").clicked() {
                            ui.ctx().copy_text(command.command.clone());
                        }
                    });
                    ui.weak(&command.label);
                }

                ui.weak(format!(
                    "Corroborated by {}",
                    cause.contributing_rules.join(", ")
                ));
            });
            ui.add_space(8.0);
        }
    }

    fn drivers_tab(&mut self, ui: &mut egui::Ui, report: &DiagnosticReport) {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.driver_filter);
            ui.checkbox(&mut self.third_party_only, "Third-party only");
        });
        ui.add_space(6.0);
        let needle = self.driver_filter.to_lowercase();
        let matching: Vec<&DriverInfo> = report
            .drivers
            .iter()
            .filter(|d| !self.third_party_only || !d.is_os_driver)
            .filter(|d| {
                needle.is_empty()
                    || d.name.to_lowercase().contains(&needle)
                    || d.company.to_lowercase().contains(&needle)
            })
            .collect();
        ui.weak(format!(
            "{} of {} drivers",
            matching.len(),
            report.drivers.len()
        ));
        ui.add_space(4.0);
        for driver in matching {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(&driver.name);
                    ui.weak(driver.category.label());
                    if driver.vulnerability.is_some() {
                        ui.colored_label(egui::Color32::from_rgb(190, 60, 50), "KNOWN VULNERABLE");
                    }
                });
                ui.label(format!("{} · v{}", driver.company, driver.version));
                ui.weak(driver.signature.label());
                ui.weak(&driver.path);
                if let Some(vulnerability) = &driver.vulnerability {
                    ui.label(&vulnerability.description);
                    if !vulnerability.cves.is_empty() {
                        ui.weak(vulnerability.cves.join(", "));
                    }
                }
            });
        }
    }
}

fn crashes_tab(ui: &mut egui::Ui, report: &DiagnosticReport) {
    if report.crashes.is_empty() {
        ui.label("No crash dumps were found in this window.");
        return;
    }

    let system: Vec<&CrashRecord> = report.system_crashes().collect();
    let applications: Vec<&CrashRecord> = report.application_crashes().collect();

    if system.is_empty() {
        ui.label("No system crashes in this window.");
    } else {
        ui.strong("System crashes");
    }

    for crash in &system {
        ui.group(|ui| {
            ui.strong(format!(
                "{}  0x{:08X} {}",
                crash.timestamp.format("%Y-%m-%d %H:%M"),
                crash.bugcheck_code,
                crash.bugcheck_name
            ));
            match crash.attribution.module() {
                Some(module) => ui.label(format!(
                    "Culprit: {module} ({})",
                    crash.attribution.describe()
                )),
                None => ui.label("Culprit: not established"),
            };
            ui.weak(format!(
                "Parameters: {}",
                crash
                    .parameters
                    .iter()
                    .map(|p| format!("0x{p:X}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            ui.weak(&crash.dump_path);
        });
    }

    if !applications.is_empty() {
        ui.add_space(10.0);
        ui.strong("Application crashes");
        ui.weak("User-mode program crashes, not system faults.");
        for crash in &applications {
            ui.label(format!(
                "{}  {}  0x{:08X} {}",
                crash.timestamp.format("%Y-%m-%d %H:%M"),
                crash.faulting_module.as_deref().unwrap_or("unknown"),
                crash.bugcheck_code,
                crash.bugcheck_name
            ));
        }
    }
}

fn timeline_tab(ui: &mut egui::Ui, report: &DiagnosticReport) {
    for window in &report.correlations {
        egui::CollapsingHeader::new(format!(
            "{} — {} ({} events either side)",
            window.crash.timestamp.format("%Y-%m-%d %H:%M"),
            window.crash.bugcheck_name,
            window.preceding.len() + window.following.len()
        ))
        .show(ui, |ui| {
            ui.strong("Before");
            for event in &window.preceding {
                ui.label(format!(
                    "{}  {} {}",
                    event.timestamp.format("%H:%M:%S"),
                    event.source,
                    event.event_id
                ));
            }
            ui.strong("After");
            for event in &window.following {
                ui.label(format!(
                    "{}  {} {}",
                    event.timestamp.format("%H:%M:%S"),
                    event.source,
                    event.event_id
                ));
            }
        });
    }

    ui.add_space(8.0);
    ui.separator();
    ui.strong(format!("All collected events ({})", report.timeline.len()));
    for event in report.timeline.iter().rev().take(500) {
        ui.label(format!(
            "{}  [{}] {} {} — {}",
            event.timestamp.format("%Y-%m-%d %H:%M:%S"),
            event.level.label(),
            event.source,
            event.event_id,
            truncate(&event.message, 120)
        ));
    }
}

fn coverage_tab(ui: &mut egui::Ui, report: &DiagnosticReport) {
    ui.strong("Kernel protections");
    let tri = |value: Option<bool>| match value {
        Some(true) => "on",
        Some(false) => "OFF",
        None => "unknown",
    };
    ui.label(format!(
        "Memory Integrity (HVCI): {}",
        tri(report.security.hvci_enabled)
    ));
    ui.label(format!(
        "Vulnerable driver blocklist: {}",
        tri(report.security.driver_blocklist_enabled)
    ));
    ui.label(format!("Secure Boot: {}", tri(report.security.secure_boot)));

    ui.add_space(10.0);
    ui.strong("Collection");
    for note in &report.collection {
        let text = format!(
            "{}: {} item(s){}",
            note.provider,
            note.items,
            note.status
                .reason()
                .map(|r| format!(" — {r}"))
                .unwrap_or_default()
        );
        if note.status.is_complete() {
            ui.label(text);
        } else {
            ui.colored_label(egui::Color32::from_rgb(200, 140, 40), text);
        }
    }

    if !report.device_problems.is_empty() {
        ui.add_space(10.0);
        ui.strong("Device problems");
        for device in &report.device_problems {
            let fault = device
                .problem_code
                .is_some_and(device_inspector::is_hardware_fault);
            let text = format!("{} — {}", device.name, device.status);
            if fault {
                ui.colored_label(egui::Color32::from_rgb(190, 60, 50), text);
            } else {
                ui.label(text);
            }
        }
    }
}

fn confidence_colour(level: ConfidenceLevel) -> egui::Color32 {
    match level {
        ConfidenceLevel::Certain => egui::Color32::from_rgb(190, 60, 50),
        ConfidenceLevel::High => egui::Color32::from_rgb(190, 130, 40),
        ConfidenceLevel::Moderate => egui::Color32::from_rgb(90, 130, 180),
        ConfidenceLevel::Low => egui::Color32::GRAY,
    }
}

fn truncate(text: &str, limit: usize) -> String {
    let cleaned = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.chars().count() <= limit {
        cleaned
    } else {
        cleaned.chars().take(limit).collect::<String>() + "…"
    }
}

fn open_folder(path: &std::path::Path) -> std::io::Result<()> {
    std::process::Command::new("explorer.exe")
        .arg("/select,")
        .arg(path)
        .spawn()
        .map(|_| ())
}
