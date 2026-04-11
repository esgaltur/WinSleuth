use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use notify_rust::Notification;
use winsleuth::modules::{
    ui_layer::cli::{Cli, Commands},
    providers::system_inventory::WindowsSystemInventory,
    providers::firmware_inventory::WindowsFirmwareInventory,
    providers::driver_inventory::WindowsDriverInventory,
    providers::eventlog_reader::WindowsEventLogReader,
    providers::device_inspector::WindowsDeviceInspector,
    providers::service_inspector::WindowsServiceInspector,
    providers::change_tracker::WindowsChangeTracker,
    providers::minidump_reader::WindowsMinidumpReader,
    providers::reliability_reader::WindowsReliabilityReader,
    core::engine::WinSleuthEngine,
    analysis::rules::{MonitoringConflictRule, UnsignedDriverRule, WheaErrorRule, BugCheckRule, CrashCorrelationRule, DeviceReEnumerationRule, ServiceFailureRule, ReliabilityScoreRule, DiskErrorRule, RecentChangeCorrelationRule},
    ui_layer::reporting,
    core::traits::{DriverInventoryProvider, DeviceInspectorProvider, EventLogProvider},
};

fn main() -> anyhow::Result<()> {
    // Initializing tracing for logging, filtering out noisy wgpu/egui logs
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn,winsleuth=info"))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { format, days } => {
            println!("Starting Instability WinSleuth scan (last {} days)...", days);
            
            let pb = ProgressBar::new(10);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")?
                .progress_chars("#>-"));

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

            engine.set_progress_bar(pb);

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

            let report = engine.run_scan();

            // Output
            if format == "json" {
                println!("{}", reporting::export_json(&report));
            } else {
                reporting::print_report(&report);
            }
        }
        Commands::InspectDrivers => {
            let provider = WindowsDriverInventory;
            let drivers = provider.collect_drivers();
            println!("Suspicious Drivers Detected:");
            for driver in drivers {
                println!("- {} (Publisher: {})", driver.name, driver.publisher);
            }
        }
        Commands::InspectDevices => {
            let provider = WindowsDeviceInspector;
            let devices = provider.collect_device_problems();
            println!("Device Problem Report:");
            for device in devices {
                println!("- {}: Status: {}, Problem Code: {:?}", device.name, device.status, device.problem_code);
            }
        }
        Commands::InspectEvents { days } => {
            let provider = WindowsEventLogReader;
            let events = provider.collect_events();
            println!("Critical Events (Last {} days):", days);
            for event in events {
                println!("- [{}] {}: ID {} (Message: {})", event.timestamp, event.source, event.event_id, event.message);
            }
        }
        Commands::Timeline => {
            println!("System Event Timeline:");
            let pb = ProgressBar::new(3);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")?
                .progress_chars("#>-"));

            pb.set_message("Collecting event logs...");
            let ev_provider = WindowsEventLogReader;
            let mut events = ev_provider.collect_events();
            pb.inc(1);

            pb.set_message("Collecting reliability data...");
            let rel_provider = WindowsReliabilityReader;
            events.extend(rel_provider.collect_events());
            pb.inc(1);
            
            pb.set_message("Sorting timeline...");
            events.sort_by_key(|e| e.timestamp);
            pb.finish_with_message("Timeline ready.");

            for event in events {
                println!("- [{}] {}: ID {} (Level: {})", event.timestamp, event.source, event.event_id, event.level);
            }
        }
        Commands::Monitor { interval, webhook, log_file } => {
            println!("Starting live monitoring (interval: {}s)... Press Ctrl+C to stop.", interval);
            if log_file.is_some() {
                println!("Persistent logging enabled.");
            }
            if webhook.is_some() {
                println!("Webhook alerts enabled.");
            }

            // Setup system tray icon (Blue square with white border)
            let mut icon_rgba = vec![0; 4 * 32 * 32];
            for y in 0..32 {
                for x in 0..32 {
                    let i = (y * 32 + x) * 4;
                    if x == 0 || x == 31 || y == 0 || y == 31 {
                        // White border
                        icon_rgba[i] = 255;     // R
                        icon_rgba[i+1] = 255;   // G
                        icon_rgba[i+2] = 255;   // B
                        icon_rgba[i+3] = 255;   // A
                    } else {
                        // Blue center
                        icon_rgba[i] = 0;       // R
                        icon_rgba[i+1] = 120;   // G
                        icon_rgba[i+2] = 215;   // B
                        icon_rgba[i+3] = 255;   // A
                    }
                }
            }
            let icon = tray_icon::Icon::from_rgba(icon_rgba, 32, 32).unwrap();
            let _tray_icon = tray_icon::TrayIconBuilder::new()
                .with_tooltip("WinSleuth Monitor")
                .with_icon(icon)
                .build()
                .unwrap();

            // Helper to count active PnP devices
            let get_pnp_count = || -> u32 {
                let mut count = 0;
                unsafe {
                    use windows::Win32::Devices::DeviceAndDriverInstallation::{
                        SetupDiGetClassDevsW, SetupDiEnumDeviceInfo, SP_DEVINFO_DATA, DIGCF_PRESENT, DIGCF_ALLCLASSES, SetupDiDestroyDeviceInfoList
                    };
                    let dev_info = SetupDiGetClassDevsW(None, None, None, DIGCF_PRESENT | DIGCF_ALLCLASSES).unwrap_or_default();
                    if !dev_info.is_invalid() {
                        let mut dev_data = SP_DEVINFO_DATA {
                            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                            ClassGuid: Default::default(),
                            DevInst: 0,
                            Reserved: 0,
                        };
                        let mut index = 0;
                        while SetupDiEnumDeviceInfo(dev_info, index, &mut dev_data).is_ok() {
                            count += 1;
                            index += 1;
                        }
                        let _ = SetupDiDestroyDeviceInfoList(dev_info);
                    }
                }
                count
            };

            // Start the background monitoring thread
            std::thread::spawn(move || {
                let provider = WindowsEventLogReader;
                let mut last_timestamp = chrono::Utc::now();
                let mut last_pnp_count = get_pnp_count();

                // Setup Minidump Watcher
                let (tx, rx) = std::sync::mpsc::channel();
                let mut watcher = notify::recommended_watcher(tx).ok();
                if let Some(w) = &mut watcher {
                    use notify::Watcher;
                    let _ = w.watch(std::path::Path::new("C:\\Windows\\Minidump"), notify::RecursiveMode::NonRecursive);
                }

                // Setup Telemetry
                let mut sys = sysinfo::System::new_all();
                let mut telemetry_buffer = std::collections::VecDeque::new();
                let mut seconds_since_last_check = 0;

                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    seconds_since_last_check += 1;

                    // Update Telemetry
                    sys.refresh_all();
                    let cpu_usage = sys.global_cpu_usage();
                    let mem_used_mb = sys.used_memory() / 1048576;
                    telemetry_buffer.push_back(format!("[{}] CPU: {:.1}% | RAM: {} MB", chrono::Utc::now().format("%H:%M:%S"), cpu_usage, mem_used_mb));
                    if telemetry_buffer.len() > 10 {
                        telemetry_buffer.pop_front();
                    }

                    // Check for new Minidumps
                    while let Ok(res) = rx.try_recv() {
                        if let Ok(notify::Event { kind, paths, .. }) = res {
                            if kind.is_create() || kind.is_modify() {
                                for path in paths {
                                    if path.extension().map_or(false, |ext| ext == "dmp") {
                                        let msg = format!("CRITICAL: New Minidump detected at {:?}", path);
                                        println!("[CRASH] {}", msg);
                                        let telemetry_dump = telemetry_buffer.iter().cloned().collect::<Vec<_>>().join("\n");
                                        println!("--- Last 10 seconds of Telemetry ---\n{}", telemetry_dump);

                                        let _ = Notification::new()
                                            .summary("WinSleuth Crash Alert")
                                            .body("A new Minidump (BSOD) was just created!")
                                            .show();

                                        if let Some(log_path) = &log_file {
                                            use std::io::Write;
                                            if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
                                                let _ = writeln!(file, "[{}] MINIDUMP: {:?}\nTELEMETRY:\n{}", chrono::Utc::now(), path, telemetry_dump);
                                            }
                                        }

                                        if let Some(url) = &webhook {
                                            let json_payload = format!(
                                                r#"{{"content": "**WinSleuth CRASH Alert**: New Minidump Detected\n`Path`: {:?}\n\n**Pre-Crash Telemetry (10s):**\n```\n{}\n```"}}"#,
                                                path, telemetry_dump
                                            );
                                            let _ = ureq::post(url)
                                                .header("Content-Type", "application/json")
                                                .send(&json_payload);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Run the heavy PnP and Event Log checks every `interval` seconds
                    if seconds_since_last_check >= interval {
                        seconds_since_last_check = 0;

                        // 1. PnP Device Tracking
                        let current_pnp_count = get_pnp_count();
                        if current_pnp_count != last_pnp_count {
                            let msg = format!("PnP Device change detected: {} present (was {})", current_pnp_count, last_pnp_count);
                            println!("[PNP] [{}] {}", chrono::Utc::now(), msg);
                            last_pnp_count = current_pnp_count;
                            
                            if let Some(path) = &log_file {
                                use std::io::Write;
                                if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                                    let _ = writeln!(file, "[{}] PNP_CHANGE: {}", chrono::Utc::now(), msg);
                                }
                            }
                        }

                        // 2. Event Log Tracking
                        let events = provider.collect_events();
                        
                        // Get events strictly newer than last_timestamp
                        let mut new_events: Vec<_> = events.into_iter().filter(|e| e.timestamp > last_timestamp).collect();
                        new_events.sort_by_key(|e| e.timestamp);
                        
                        for event in new_events {
                            let log_msg = format!("[{}] {}: ID {} (Level: {})", event.timestamp, event.source, event.event_id, event.level);
                            println!("[NEW] {}", log_msg);
                            
                            let telemetry_dump = telemetry_buffer.iter().cloned().collect::<Vec<_>>().join("\n");
                            
                            // Native Notification
                            let _ = Notification::new()
                                .summary("WinSleuth Alert")
                                .body(&format!("Critical event detected!\nSource: {}\nID: {}", event.source, event.event_id))
                                .show();
                                
                            // Persistent Audit Logging
                            if let Some(path) = &log_file {
                                use std::io::Write;
                                if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                                    let _ = writeln!(file, "EVENT: {}\nTELEMETRY:\n{}", log_msg, telemetry_dump);
                                }
                            }
                            
                            // Webhook Alert
                            if let Some(url) = &webhook {
                                let json_payload = format!(
                                    r#"{{"content": "**WinSleuth Alert**: Critical Event Detected\n`Source`: {}\n`Event ID`: {}\n`Level`: {}\n`Time`: {}\n\n**Telemetry Snapshot:**\n```\n{}\n```"}}"#,
                                    event.source, event.event_id, event.level, event.timestamp, telemetry_dump
                                );
                                let _ = ureq::post(url)
                                    .header("Content-Type", "application/json")
                                    .send(&json_payload);
                            }
                                
                            if event.timestamp > last_timestamp {
                                last_timestamp = event.timestamp;
                            }
                        }
                    }
                }
            });

            // Process Windows messages for the tray icon to remain responsive
            #[cfg(windows)]
            unsafe {
                use windows::Win32::UI::WindowsAndMessaging::{GetMessageW, TranslateMessage, DispatchMessageW, MSG};
                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, None, 0, 0).into() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        }
        Commands::Ui => {
            println!("Launching Desktop UI...");
            let options = eframe::NativeOptions {
                viewport: eframe::egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
                ..Default::default()
            };
            eframe::run_native(
                "Instability WinSleuth",
                options,
                Box::new(|cc| Ok(Box::new(winsleuth::modules::ui_layer::ui::WinSleuthApp::new(cc)))),
            )?;
        }
    }

    Ok(())
}
