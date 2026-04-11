use crate::modules::core::models::{DiagnosticReport, SuspectedCause, ConfidenceLevel, DriverCategory, DriverInfo};
use crate::modules::core::traits::HeuristicRule;

pub struct MonitoringConflictRule;
impl HeuristicRule for MonitoringConflictRule {
    fn evaluate(&self, report: &DiagnosticReport) -> Option<SuspectedCause> {
        let monitoring_drivers: Vec<_> = report.drivers.iter()
            .filter(|d| d.category == DriverCategory::Monitoring && !d.is_os_driver)
            .collect();
        
        if !monitoring_drivers.is_empty() {
            Some(SuspectedCause {
                title: "Potential Low-Level Monitoring Conflict".to_string(),
                score: 75.0,
                confidence: ConfidenceLevel::Moderate,
                evidence: monitoring_drivers.iter().map(|d| d.name.clone()).collect(),
                explanation: "Multiple hardware monitoring tools or drivers detected. These often compete for low-level sensor access, leading to system hangs or crashes.".to_string(),
                recommendation: "Try disabling third-party monitoring software (e.g., AIDA64, HWInfo, vendor utilities) and monitor for stability.".to_string(),
            })
        } else {
            None
        }
    }
}

pub struct UnsignedDriverRule;
impl HeuristicRule for UnsignedDriverRule {
    fn evaluate(&self, report: &DiagnosticReport) -> Option<SuspectedCause> {
        let unsigned_drivers: Vec<_> = report.drivers.iter()
            .filter(|d| !d.signed)
            .collect();

        if !unsigned_drivers.is_empty() {
            Some(SuspectedCause {
                title: "Unsigned Kernel Drivers Detected".to_string(),
                score: 60.0,
                confidence: ConfidenceLevel::Low,
                evidence: unsigned_drivers.iter().map(|d| d.name.clone()).collect(),
                explanation: "Unsigned drivers bypass standard Windows security and stability checks. They are more likely to cause instability.".to_string(),
                recommendation: "Ensure all drivers are up-to-date and provided by the official manufacturer.".to_string(),
            })
        } else {
            None
        }
    }
}

pub struct WheaErrorRule;
impl HeuristicRule for WheaErrorRule {
    fn evaluate(&self, report: &DiagnosticReport) -> Option<SuspectedCause> {
        let whea_events = report.timeline.iter().filter(|e| e.source.contains("WHEA")).count();
        if whea_events > 0 {
            Some(SuspectedCause {
                title: "Hardware Errors Detected (WHEA)".to_string(),
                score: 90.0,
                confidence: ConfidenceLevel::High,
                evidence: vec![format!("{} WHEA-Logger events detected in logs", whea_events)],
                explanation: "Windows Hardware Error Architecture (WHEA) reported hardware-level issues. This is often related to CPU/RAM instability or overclocking.".to_string(),
                recommendation: "Check CPU/RAM temperatures and consider reverting any overclocking (XMP/EXPO) to defaults.".to_string(),
            })
        } else {
            None
        }
    }
}

pub struct CrashCorrelationRule;
impl HeuristicRule for CrashCorrelationRule {
    fn evaluate(&self, report: &DiagnosticReport) -> Option<SuspectedCause> {
        let bugcheck_events: Vec<_> = report.timeline.iter()
            .filter(|e| e.event_id == 1001 || e.event_id == 41)
            .collect();

        let mut suspicious_drivers = Vec::new();

        for event in bugcheck_events {
            // Find all potential kernel addresses (starts with fffff)
            // We'll look for 0x followed by at least 12 hex digits or just fffff...
            // A simple way is to look for "fffff" in any hex string
            for part in event.message.split(|c| c == ' ' || c == '(' || c == ')' || c == ',' || c == '|') {
                let clean_part = part.trim().trim_start_matches("0x");
                if clean_part.starts_with("fffff") {
                    if let Ok(addr) = u64::from_str_radix(clean_part, 16) {
                        // Find the driver that owns this address
                        let mut best_driver = None;
                        let mut best_diff = u64::MAX;

                        for driver in &report.drivers {
                            if driver.base_address > 0 && addr >= driver.base_address {
                                let diff = addr - driver.base_address;
                                if diff < best_diff {
                                    best_diff = diff;
                                    best_driver = Some(driver);
                                }
                            }
                        }

                        if let Some(driver) = best_driver {
                            // Only count it if it's reasonably close (drivers are rarely > 100MB)
                            if best_diff < 100 * 1024 * 1024 {
                                // De-duplicate by driver name
                                if !suspicious_drivers.iter().any(|(d, _): &(&DriverInfo, u64)| d.name == driver.name) {
                                    suspicious_drivers.push((driver, addr));
                                }
                            }
                        }
                    }
                }
            }
        }

        if !suspicious_drivers.is_empty() {
            let mut evidence = Vec::new();
            for (driver, addr) in &suspicious_drivers {
                evidence.push(format!("Driver '{}' was active at crash address 0x{:x}", driver.name, addr));
            }

            Some(SuspectedCause {
                title: "Specific Driver Correlated with Crash".to_string(),
                score: 95.0,
                confidence: ConfidenceLevel::High,
                evidence,
                explanation: "An analysis of the crash addresses suggests that a specific third-party driver was active or faulting at the time of the BSOD.".to_string(),
                recommendation: format!("Update or reinstall the driver: {}", suspicious_drivers[0].0.name),
            })
        } else {
            None
        }
    }
}

fn get_bugcheck_name(code: u32) -> &'static str {
    match code {
        0x1 => "APC_INDEX_MISMATCH",
        0xA => "IRQL_NOT_LESS_OR_EQUAL",
        0x1E => "KMODE_EXCEPTION_NOT_HANDLED",
        0x24 => "NTFS_FILE_SYSTEM",
        0x3B => "SYSTEM_SERVICE_EXCEPTION",
        0x3D => "INTERRUPT_EXCEPTION_NOT_HANDLED",
        0x44 => "MULTIPLE_IRP_COMPLETE_REQUESTS",
        0x50 => "PAGE_FAULT_IN_NONPAGED_AREA",
        0x7E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0x7F => "UNEXPECTED_KERNEL_MODE_TRAP",
        0x9F => "DRIVER_POWER_STATE_FAILURE",
        0xA0 => "INTERNAL_POWER_ERROR",
        0xBE => "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
        0xC2 => "BAD_POOL_CALLER",
        0xC4 => "DRIVER_VERIFIER_DETECTED_VIOLATION",
        0xC5 => "DRIVER_CORRUPTED_EXPOOL",
        0xD1 => "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        0x101 => "CLOCK_WATCHDOG_TIMEOUT",
        0x109 => "CRITICAL_STRUCTURE_CORRUPTION",
        0x116 => "VIDEO_TDR_FAILURE",
        0x117 => "VIDEO_TDR_TIMEOUT_DETECTED",
        0x119 => "VIDEO_SCHEDULER_INTERNAL_ERROR",
        0x124 => "WHEA_UNCORRECTABLE_ERROR",
        0x133 => "DPC_WATCHDOG_VIOLATION",
        0x139 => "KERNEL_SECURITY_CHECK_FAILURE",
        0x141 => "VIDEO_ENGINE_TIMEOUT_DETECTED",
        0x154 => "UNEXPECTED_STORE_EXCEPTION",
        0x162 => "KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE",
        0x192 => "KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL",
        0x1A1 => "WIN32K_POWER_WATCHDOG_TIMEOUT",
        _ => "Unknown BugCheck",
    }
}

pub struct BugCheckRule;
impl HeuristicRule for BugCheckRule {
    fn evaluate(&self, report: &DiagnosticReport) -> Option<SuspectedCause> {
        let bugcheck_events: Vec<_> = report.timeline.iter()
            .filter(|e| e.event_id == 1001 || e.event_id == 41)
            .collect();

        if !bugcheck_events.is_empty() {
            let mut evidence = vec![format!("Detected {} critical crash events (BugCheck/Kernel-Power)", bugcheck_events.len())];
            
            // Try to extract bugcheck codes from messages
            for event in &bugcheck_events {
                // Look for 0x... hex code
                if let Some(pos) = event.message.find("0x") {
                    let end = event.message[pos..].find(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X').unwrap_or(event.message[pos..].len());
                    let code_str = &event.message[pos..pos+end];
                    if let Ok(code) = u32::from_str_radix(code_str.trim_start_matches("0x"), 16) {
                        let name = get_bugcheck_name(code);
                        evidence.push(format!("Crash Code: {} ({}) at {}", code_str, name, event.timestamp));
                    }
                } else if event.event_id == 41 {
                    // Kernel-Power 41 often has decimal code as first parameter in message
                    if let Some(first_part) = event.message.split('|').next() {
                        if let Ok(code) = first_part.trim().parse::<u32>() {
                            if code != 0 {
                                let name = get_bugcheck_name(code);
                                evidence.push(format!("Crash Code: 0x{:x} ({}) at {}", code, name, event.timestamp));
                            }
                        }
                    }
                }
            }

            Some(SuspectedCause {
                title: "Critical System Crashes Detected".to_string(),
                score: 85.0,
                confidence: ConfidenceLevel::High,
                evidence,
                explanation: "The system has experienced one or more Blue Screen of Death (BSOD) events or unexpected shutdowns. This indicates severe instability.".to_string(),
                recommendation: "Examine the correlation timeline to see which drivers or services were active just before these crashes.".to_string(),
            })
        } else {
            None
        }
    }
}

pub struct DeviceReEnumerationRule;
impl HeuristicRule for DeviceReEnumerationRule {
    fn evaluate(&self, report: &DiagnosticReport) -> Option<SuspectedCause> {
        let pnp_events: Vec<_> = report.timeline.iter()
            .filter(|e| e.source.contains("Kernel-PnP") && (e.event_id == 400 || e.event_id == 411))
            .collect();

        if pnp_events.len() > 3 {
            Some(SuspectedCause {
                title: "Frequent Device Re-enumeration".to_string(),
                score: 70.0,
                confidence: ConfidenceLevel::Moderate,
                evidence: vec![format!("Detected {} PnP re-enumeration events", pnp_events.len())],
                explanation: "The system is frequently re-detecting or re-configuring devices. This can be caused by unstable USB connections, failing hardware, or problematic drivers.".to_string(),
                recommendation: "Check for loose cables, failing USB hubs, or devices that seem to disappear and reappear in Device Manager.".to_string(),
            })
        } else {
            None
        }
    }
}

pub struct ServiceFailureRule;
impl HeuristicRule for ServiceFailureRule {
    fn evaluate(&self, report: &DiagnosticReport) -> Option<SuspectedCause> {
        let mut evidence = Vec::new();
        for svc in &report.service_problems {
            // Ignore common non-error codes: 0 (Success), 1077 (Never started)
            if svc.exit_code != 0 && svc.exit_code != 1077 {
                evidence.push(format!("Service '{}' ({}) exited with code {}", svc.display_name, svc.name, svc.exit_code));
            }
        }

        if !evidence.is_empty() {
            Some(SuspectedCause {
                title: "System Service Failures".to_string(),
                score: 65.0,
                confidence: ConfidenceLevel::Moderate,
                evidence,
                explanation: "One or more system services have reported abnormal exit codes. This can be a symptom of underlying instability or resource exhaustion.".to_string(),
                recommendation: "Investigate why these specific services are failing. Check for corresponding errors in the Application event log.".to_string(),
            })
        } else {
            None
        }
    }
}

pub struct DiskErrorRule;
impl HeuristicRule for DiskErrorRule {
    fn evaluate(&self, report: &DiagnosticReport) -> Option<SuspectedCause> {
        let disk_events: Vec<_> = report.timeline.iter()
            .filter(|e| {
                let s = e.source.to_lowercase();
                (s.contains("disk") || s.contains("ntfs") || s.contains("volmgr")) &&
                (e.event_id == 7 || e.event_id == 11 || e.event_id == 51 || e.event_id == 55)
            })
            .collect();

        if !disk_events.is_empty() {
            Some(SuspectedCause {
                title: "Critical Disk/Storage Errors".to_string(),
                score: 90.0,
                confidence: ConfidenceLevel::High,
                evidence: disk_events.iter().map(|e| format!("{}: Event {}", e.source, e.event_id)).collect(),
                explanation: "The system logs contain critical disk or file system errors (e.g., bad blocks, controller errors). This is a strong indicator of failing hardware or severe corruption.".to_string(),
                recommendation: "Immediately backup important data. Run 'chkdsk /f' and check SSD/HDD health (S.M.A.R.T.) using tools like CrystalDiskInfo.".to_string(),
            })
        } else {
            None
        }
    }
}

pub struct ReliabilityScoreRule;
impl HeuristicRule for ReliabilityScoreRule {
    fn evaluate(&self, report: &DiagnosticReport) -> Option<SuspectedCause> {
        let rel_events = report.timeline.iter()
            .filter(|e| e.level == "Reliability")
            .count();

        if rel_events > 5 {
            Some(SuspectedCause {
                title: "Frequent Reliability Issues Detected".to_string(),
                score: 80.0,
                confidence: ConfidenceLevel::High,
                evidence: vec![format!("Detected {} reliability events in the analyzed period", rel_events)],
                explanation: "Windows Reliability Monitor has recorded a high frequency of application, service, or system failures recently.".to_string(),
                recommendation: "This system is showing a clear trend of instability. A deep dive into the correlation timeline is recommended to find common factors.".to_string(),
            })
        } else {
            None
        }
    }
}

pub struct RecentChangeCorrelationRule;
impl HeuristicRule for RecentChangeCorrelationRule {
    fn evaluate(&self, report: &DiagnosticReport) -> Option<SuspectedCause> {
        let first_crash_time = report.timeline.iter()
            .filter(|e| e.event_id == 1001 || e.event_id == 41)
            .map(|e| e.timestamp)
            .min();

        if let Some(crash_time) = first_crash_time {
            let mut correlated_changes = Vec::new();
            for change in &report.recent_changes {
                let diff = if change.date > crash_time {
                    change.date - crash_time
                } else {
                    crash_time - change.date
                };

                if diff.num_hours() <= 48 {
                    correlated_changes.push(format!("{} ({}) on {}", change.name, change.change_type, change.date));
                }
            }

            if !correlated_changes.is_empty() {
                return Some(SuspectedCause {
                    title: "Recent System Changes Correlated with Crashes".to_string(),
                    score: 85.0,
                    confidence: ConfidenceLevel::High,
                    evidence: correlated_changes,
                    explanation: "One or more system updates or software installations occurred very close to the first recorded system crash. This is a strong indicator of a causal relationship.".to_string(),
                    recommendation: "Consider rolling back the identified updates or uninstalling recently added software to see if stability returns.".to_string(),
                });
            }
        }
        None
    }
}
