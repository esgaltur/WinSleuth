use crate::modules::core::models::DiagnosticReport;
use serde_json;

pub fn print_report(report: &DiagnosticReport) {
    println!("=== WinSleuth Diagnostic Report ===");
    println!("System Identity:");
    println!("  CPU: {}", report.system.cpu_model);
    println!("  Motherboard: {} {}", report.system.motherboard_vendor, report.system.motherboard_model);
    println!("  BIOS: {} (v{}) dated {}", report.firmware.vendor, report.firmware.version, report.firmware.date);
    println!();

    println!("Suspicious Drivers/Utilities:");
    for driver in &report.drivers {
        // Filter for display: Only show if it's NOT a standard OS driver
        if !driver.is_os_driver {
            println!("  - [{:?}] {} (Signed: {})", driver.category, driver.name, driver.signed);
            println!("    Company: {}, Publisher: {}", driver.company, driver.publisher);
            println!("    SHA256: {}", driver.hash);
            println!("    Description: {}", driver.description);
        }
    }
    println!();

    if !report.device_problems.is_empty() {
        println!("Device Issues Detected:");
        for device in &report.device_problems {
            println!("  - {} (ID: {}): Status: {}, Problem Code: {:?}", device.name, device.device_id, device.status, device.problem_code);
        }
        println!();
    }

    if !report.service_problems.is_empty() {
        println!("Service Failures Detected:");
        for service in &report.service_problems {
            println!("  - {} ({}): Exit Code: {}", service.display_name, service.name, service.exit_code);
        }
        println!();
    }

    if !report.recent_changes.is_empty() {
        println!("Recent System Changes:");
        for change in &report.recent_changes {
            println!("  - [{}] {} on {}", change.change_type, change.name, change.date);
        }
        println!();
    }

    println!("Analysis & Ranked Causes:");
    if report.suspected_causes.is_empty() {
        println!("  No significant instability patterns detected.");
    } else {
        for cause in &report.suspected_causes {
            println!("  [{:?}] {} (Score: {:.1})", cause.confidence, cause.title, cause.score);
            println!("    Explanation: {}", cause.explanation);
            println!("    Evidence: {}", cause.evidence.join(", "));
            println!("    Recommendation: {}", cause.recommendation);
            println!();
        }
    }

    println!("Recent Critical Events (Correlation Timeline):");
    for event in &report.timeline {
        println!("  - [{}] {}: Event {} (Level: {})", event.timestamp, event.source, event.event_id, event.level);
        if !event.message.is_empty() {
            println!("    Message: {}", event.message);
        }
    }
}

pub fn export_json(report: &DiagnosticReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "Error generating JSON".to_string())
}
