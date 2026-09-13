//! Heuristic rules.
//!
//! Every rule returns `Vec<Finding>` rather than `Option<SuspectedCause>`, for
//! two reasons: a rule can now report several distinct instances (two failing
//! disks are two findings), and findings that share a `RootCause` are merged by
//! the engine so corroborating rules reinforce one verdict instead of producing
//! several competing ones.
//!
//! Rules read `report.timeline`, which correlation no longer overwrites.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::modules::analysis::bugcheck;
use crate::modules::core::models::*;
use crate::modules::core::traits::HeuristicRule;
use crate::modules::providers::device_inspector;
use crate::modules::providers::service_inspector;

/// Newest timestamp in a set of events, for recency weighting.
fn latest(events: &[&EventRecord]) -> Option<DateTime<Utc>> {
    events.iter().map(|e| e.timestamp).max()
}

// ---------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------

/// Windows Hardware Error Architecture records.
pub struct WheaRule;

impl HeuristicRule for WheaRule {
    fn name(&self) -> &'static str {
        "WheaRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        let events: Vec<&EventRecord> = report
            .timeline
            .iter()
            .filter(|e| e.source.contains("WHEA"))
            .collect();
        if events.is_empty() {
            return Vec::new();
        }

        // Event 17 is a corrected error — an early warning, not a crash. Events
        // 18 and 47 are uncorrected and far more serious.
        let uncorrected = events
            .iter()
            .filter(|e| matches!(e.event_id, 18 | 47))
            .count();
        let corrected = events.len() - uncorrected;
        let weight = if uncorrected > 0 { 92.0 } else { 55.0 };
        let mut evidence: Vec<Evidence> = events
            .iter()
            .take(10)
            .map(|e| {
                Evidence::at(
                    format!(
                        "{} event {}: {}",
                        e.source,
                        e.event_id,
                        truncate(&e.message, 160)
                    ),
                    e.timestamp,
                )
                .from(e.channel.clone())
            })
            .collect();
        if uncorrected > 0 {
            evidence.insert(
                0,
                Evidence::new(format!(
                    "{uncorrected} uncorrected and {corrected} corrected hardware error(s)"
                )),
            );
        }

        vec![
            Finding::new(
                self.name(),
                RootCause::HardwareError,
                hardware_title(uncorrected),
                weight,
            )
            .explain(if uncorrected > 0 {
                "The processor reported hardware errors it could not correct. These come from \
                     the CPU, memory controller or a PCIe link, and are not caused by software."
            } else {
                "The processor reported hardware errors it corrected without failing. These are \
                     an early warning: silicon, memory or a link is operating out of spec."
            })
            .recommend(
                "Return CPU and memory to stock settings, including XMP/EXPO, and retest. If \
                     errors persist at stock, test memory with a dedicated pass and check that the \
                     BIOS is current.",
            )
            .command(
                "Check current BIOS version",
                "wmic bios get smbiosbiosversion",
            )
            .command("Run Windows memory diagnostic", "mdsched.exe")
            .evidence_all(evidence)
            .seen_at(latest(&events)),
        ]
    }
}

fn hardware_title(uncorrected: usize) -> &'static str {
    if uncorrected > 0 {
        "Uncorrected hardware errors reported (WHEA)"
    } else {
        "Corrected hardware errors reported (WHEA)"
    }
}

/// Storage and file system faults.
pub struct DiskErrorRule;

impl HeuristicRule for DiskErrorRule {
    fn name(&self) -> &'static str {
        "DiskErrorRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        // Group by the device the event names, so two failing disks produce two
        // findings rather than one merged sentence.
        let mut by_device: HashMap<String, Vec<&EventRecord>> = HashMap::new();
        for event in &report.timeline {
            let source = event.source.to_lowercase();
            let storage = source.contains("disk")
                || source.contains("ntfs")
                || source.contains("volmgr")
                || source.contains("storahci")
                || source.contains("stornvme")
                || source.contains("storport");
            let critical = matches!(event.event_id, 7 | 9 | 11 | 15 | 51 | 55 | 98 | 129 | 153);
            if storage && critical {
                let device = extract_device(&event.message)
                    .unwrap_or_else(|| "an unidentified storage device".to_string());
                by_device.entry(device).or_default().push(event);
            }
        }

        by_device
            .into_iter()
            .map(|(device, events)| {
                let evidence: Vec<Evidence> = events
                    .iter()
                    .take(8)
                    .map(|e| {
                        Evidence::at(
                            format!(
                                "{} event {} ({})",
                                e.source,
                                e.event_id,
                                disk_event_meaning(e.event_id)
                            ),
                            e.timestamp,
                        )
                    })
                    .collect();

                // Repetition is the signal here: one timeout is noise, a dozen
                // is a dying drive.
                let weight = (60.0 + (events.len() as f32 * 6.0)).min(95.0);

                Finding::new(
                    "DiskErrorRule",
                    RootCause::StorageFailure,
                    format!("Storage errors on {device}"),
                    weight,
                )
                .explain(
                    "The storage stack logged controller resets, bad blocks or timeouts. This is a \
                     strong indicator of a failing drive, a marginal cable, or a power delivery \
                     problem — and it can corrupt data silently before it stops the machine.",
                )
                .recommend(
                    "Back up anything irreplaceable before troubleshooting further. Then check the \
                     drive's SMART health and run a file system check.",
                )
                .command(
                    "Check disk health",
                    "Get-PhysicalDisk | Select FriendlyName, HealthStatus, OperationalStatus",
                )
                .command(
                    "Read SMART reliability counters",
                    "Get-StorageReliabilityCounter -PhysicalDisk (Get-PhysicalDisk)",
                )
                .command("Check the file system", "chkdsk C: /scan")
                .evidence_all(evidence)
                .seen_at(latest(&events))
            })
            .collect()
    }
}

fn disk_event_meaning(id: u32) -> &'static str {
    match id {
        7 => "bad block",
        9 => "the device did not respond within the timeout period",
        11 => "controller error",
        15 => "the device is not ready for access",
        51 => "an error was detected during a paging operation",
        55 => "file system corruption detected",
        98 => "volume metadata inconsistency",
        129 => "the storage adapter reset a request that timed out",
        153 => "an I/O operation was retried",
        _ => "storage error",
    }
}

/// Pull `\Device\Harddisk0\DR0` style names out of an event message.
fn extract_device(message: &str) -> Option<String> {
    let start = message.find("\\Device\\")?;
    let rest = &message[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',' || c == '.')
        .unwrap_or(rest.len());
    let device = rest[..end].trim_end_matches(['.', ',']).to_string();
    (!device.is_empty()).then_some(device)
}

// ---------------------------------------------------------------------------
// Crashes
// ---------------------------------------------------------------------------

/// Decoded stop codes from crash dumps.
pub struct BugCheckRule;

impl HeuristicRule for BugCheckRule {
    fn name(&self) -> &'static str {
        "BugCheckRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        // Kernel dumps only. A user-mode application dump carries an exception
        // code, not a stop code, and reporting `0xC0000409 STACK_BUFFER_OVERRUN`
        // as a system crash is simply wrong.
        let dumps: Vec<&CrashRecord> = report
            .crashes
            .iter()
            .filter(|c| c.source == CrashSource::KernelDump && c.bugcheck_code != 0)
            .collect();
        if dumps.is_empty() {
            return Vec::new();
        }

        // One finding per distinct stop code: repeated 0x124 and a one-off 0xD1
        // are different problems and must not be averaged together.
        let mut by_code: HashMap<u32, Vec<&CrashRecord>> = HashMap::new();
        for crash in &dumps {
            by_code.entry(crash.bugcheck_code).or_default().push(crash);
        }

        by_code
            .into_iter()
            .map(|(code, crashes)| {
                let name = bugcheck::name(code);
                let root_cause = root_cause_for(code);
                let weight = (72.0 + crashes.len() as f32 * 6.0).min(94.0);
                let evidence: Vec<Evidence> = crashes
                    .iter()
                    .take(8)
                    .map(|c| {
                        Evidence::at(
                            format!(
                                "0x{:08X} ({}) parameters {}",
                                c.bugcheck_code,
                                name,
                                format_parameters(&c.parameters)
                            ),
                            c.timestamp,
                        )
                        .from(c.dump_path.clone())
                    })
                    .collect();
                let interpretation = bugcheck::interpretation(code);
                let explanation = if interpretation.is_empty() {
                    format!(
                        "The system stopped with {name} ({} time(s)).",
                        crashes.len()
                    )
                } else {
                    format!("{interpretation} Recorded {} time(s).", crashes.len())
                };

                Finding::new(
                    "BugCheckRule",
                    root_cause,
                    format!("System crash: {name}"),
                    weight,
                )
                .explain(explanation)
                .recommend(recommendation_for(code))
                .evidence_all(evidence)
                .seen_at(crashes.iter().map(|c| c.timestamp).max())
            })
            .collect()
    }
}

/// Map a stop code onto the root cause it corroborates, so a `0x124` reinforces
/// the WHEA finding instead of standing alone.
fn root_cause_for(code: u32) -> RootCause {
    match code {
        0x124 | 0x9C => RootCause::HardwareError,
        0x1A | 0x50 | 0x7A | 0x154 => RootCause::MemoryError,
        0x7B | 0x24 | 0xF4 | 0xEF => RootCause::StorageFailure,
        0x116 | 0x117 | 0x119 | 0x141 | 0x113 => RootCause::GraphicsTimeout,
        _ => RootCause::InstabilityTrend,
    }
}

fn recommendation_for(code: u32) -> &'static str {
    match code {
        0x124 | 0x9C => {
            "Return every clock and voltage to stock, including XMP/EXPO, and retest before \
             replacing anything."
        }
        0x1A | 0x50 | 0x7A | 0x154 => {
            "Test memory at stock settings. If the machine is stable at stock but not with \
             XMP/EXPO, the memory kit is not running reliably at its rated speed."
        }
        0x116 | 0x117 | 0x119 | 0x141 | 0x113 => {
            "Clean-install the graphics driver, remove any GPU overclock, and confirm the card is \
             receiving adequate power."
        }
        0x133 => {
            "Identify the driver holding the CPU too long. Storage, network and virtualisation \
             filter drivers are the usual causes."
        }
        0x7B | 0x24 => "Check the storage controller driver and the health of the boot volume.",
        _ => "Review the correlated events around each crash and the drivers listed as suspects.",
    }
}

fn format_parameters(parameters: &[u64; 4]) -> String {
    parameters
        .iter()
        .map(|p| format!("0x{p:X}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Culprit driver attribution, from crash dumps only.
///
/// The previous rule scraped any `fffff…` token out of an event message and
/// blamed whichever driver had the nearest base address, accepting a match up
/// to 100 MB away, then published it at score 95 / confidence High. This
/// reports only what the dump established against a real image range.
pub struct CrashAttributionRule;

impl HeuristicRule for CrashAttributionRule {
    fn name(&self) -> &'static str {
        "CrashAttributionRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        let mut by_module: HashMap<String, Vec<&CrashRecord>> = HashMap::new();

        // Driver attribution applies to kernel crashes. In a user-mode dump the
        // faulting module is the application's own code, which is a different
        // finding handled by `ApplicationCrashRule`.
        for crash in &report.crashes {
            if crash.source != CrashSource::KernelDump {
                continue;
            }
            if let CrashAttribution::ModuleRange { module }
            | CrashAttribution::DumpModuleRange { module, .. } = &crash.attribution
            {
                by_module
                    .entry(module.to_lowercase())
                    .or_default()
                    .push(crash);
            }
        }

        by_module
            .into_iter()
            .map(|(module, crashes)| {
                let driver = report
                    .drivers
                    .iter()
                    .find(|d| d.name.eq_ignore_ascii_case(&module));
                let display = driver
                    .map(|d| d.name.clone())
                    .unwrap_or_else(|| module.clone());

                // Repeated attribution to one module is much stronger than one.
                let weight = if crashes.len() > 1 { 93.0 } else { 82.0 };
                let mut evidence: Vec<Evidence> = crashes
                    .iter()
                    .map(|c| {
                        Evidence::at(
                            format!(
                                "{} faulted at 0x{:X} during {} ({})",
                                display,
                                c.faulting_address.unwrap_or_default(),
                                c.bugcheck_name,
                                c.attribution.describe()
                            ),
                            c.timestamp,
                        )
                        .from(c.dump_path.clone())
                    })
                    .collect();
                if let Some(driver) = driver {
                    evidence.push(Evidence::new(format!(
                        "Currently installed: {} version {} from {}, signature {} (may differ from the crash-time build)",
                        driver.name,
                        driver.version,
                        driver.company,
                        driver.signature.label()
                    )));
                }

                let is_os = driver.map(|d| d.is_os_driver).unwrap_or(false);

                Finding::new(
                    "CrashAttributionRule",
                    RootCause::DriverFault {
                        module: display.clone(),
                    },
                    format!("{display} was executing when the system crashed"),
                    weight,
                )
                .explain(
                    "The faulting instruction pointer recorded in the crash dump falls inside this \
                     module's loaded image. That is a direct identification rather than an \
                     inference from timing.",
                )
                .recommend(if is_os {
                    "This is a Microsoft-signed component, which usually means it was called into \
                     an invalid state by something else rather than being the origin. Treat it as \
                     a symptom and look at third-party filter drivers and hardware."
                        .to_string()
                } else if driver.is_none() {
                    format!(
                        "{display} was recorded in the crash dump but is absent from the current \
                         driver inventory. Check whether it has since been updated or removed \
                         before taking action; its publisher and signature are not established."
                    )
                } else {
                    format!(
                        "Update {display} from the hardware vendor, or remove the software that \
                         installed it and retest."
                    )
                })
                .command("List installed driver packages", "pnputil /enum-drivers")
                .evidence_all(evidence)
                .seen_at(crashes.iter().map(|c| c.timestamp).max())
            })
            .collect()
    }
}

/// Unexpected shutdowns that left no bugcheck.
pub struct PowerLossRule;

impl HeuristicRule for PowerLossRule {
    fn name(&self) -> &'static str {
        "PowerLossRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        // A Kernel-Power 41 accompanied by a dump is a bugcheck, already
        // reported. One without is a hard power loss, which is a different
        // problem with different causes.
        let unexplained: Vec<&EventRecord> = report
            .timeline
            .iter()
            .filter(|e| e.is_unexpected_shutdown())
            .filter(|e| {
                !report.crashes.iter().any(|c| {
                    (c.timestamp - e.timestamp).num_minutes().abs() <= 5
                        && c.source == CrashSource::KernelDump
                })
            })
            .collect();
        if unexplained.is_empty() {
            return Vec::new();
        }

        let weight = (48.0 + unexplained.len() as f32 * 9.0).min(88.0);
        vec![
            Finding::new(
                self.name(),
                RootCause::PowerLoss,
                "Unexpected shutdowns with no crash dump", weight,
            )
            .explain(
                "The system lost power or reset without writing a crash dump. That points at power \
                 delivery, thermal shutdown, or a fault severe enough that Windows never got to \
                 record it — rather than at a driver.",
            )
            .recommend(
                "Check power supply capacity and cabling, CPU and GPU temperatures under load, and \
                 whether crash dump creation is even enabled.",
            )
            .command(
                "Verify crash dumps are enabled",
                "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' | Select CrashDumpEnabled, DumpFile",
            )
            .evidence_all(unexplained.iter().take(10).map(|e| {
                Evidence::at(
                    format!("{} event {} — system was not shut down cleanly", e.source, e.event_id), e.timestamp,
                )
            }))
            .seen_at(latest(&unexplained)),
        ]
    }
}

// ---------------------------------------------------------------------------
// Drivers
// ---------------------------------------------------------------------------

/// Known-vulnerable drivers loaded in the kernel.
pub struct VulnerableDriverRule;

impl HeuristicRule for VulnerableDriverRule {
    fn name(&self) -> &'static str {
        "VulnerableDriverRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        let hits: Vec<&DriverInfo> = report
            .drivers
            .iter()
            .filter(|d| d.vulnerability.is_some())
            .collect();
        if hits.is_empty() {
            return Vec::new();
        }

        hits.iter()
            .map(|driver| {
                let vulnerability = driver.vulnerability.as_ref().expect("filtered above");
                // An exact hash match is a much stronger statement than a name
                // match, where a vendor may have shipped a patched build.
                let exact = vulnerability.matched_on.starts_with("SHA-256"); let weight = if exact { 90.0 } else { 68.0 }; let mut evidence = vec![
                    Evidence::new(format!("{} at {}", driver.name, driver.path))
                        .from(vulnerability.matched_on.clone()),
                    Evidence::new(vulnerability.description.clone()),
                ]; if !vulnerability.cves.is_empty() {
                    evidence.push(Evidence::new(format!("Referenced as {}", vulnerability.cves.join(", "))));
                }
                if report.security.hvci_enabled == Some(false) {
                    evidence.push(Evidence::new(
                        "Memory Integrity (HVCI) is switched off, so nothing prevents this driver \
                         being loaded and abused."
                            .to_string(),
                    ));
                }

                Finding::new(
                    "VulnerableDriverRule",
                    RootCause::VulnerableDriver, format!("Known-vulnerable driver loaded: {}", driver.name), weight,
                )
                .explain(
                    "This driver is signed and therefore loads normally, but exposes privileged \
                     memory, MSR or port I/O access to any user-mode process. Such drivers are \
                     routinely brought along by attackers specifically to disable security software \
                     from the kernel, and they are a common source of instability in their own right.",
                )
                .recommend(
                    "Uninstall the software that installed this driver if you do not need it, and \
                     switch on Memory Integrity so Windows blocks known-vulnerable drivers.",
                )
                .command(
                    "Turn on the vulnerable driver blocklist",
                    "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -Name VulnerableDriverBlocklistEnable -Value 1",
                )
                .command("Open Core Isolation settings", "start windowsdefender://coreisolation")
                .evidence_all(evidence)
            })
            .collect()
    }
}

/// Genuinely unsigned third-party drivers.
pub struct UnsignedDriverRule;

impl HeuristicRule for UnsignedDriverRule {
    fn name(&self) -> &'static str {
        "UnsignedDriverRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        // `Unknown` is excluded deliberately: a file we could not verify is not
        // evidence of anything. Only a positive "no valid signature" counts.
        let unsigned: Vec<&DriverInfo> = report
            .drivers
            .iter()
            .filter(|d| d.signature == SignatureStatus::Unsigned)
            .collect();
        if unsigned.is_empty() {
            return Vec::new();
        }

        vec![
            Finding::new(
                self.name(),
                RootCause::UnsignedDriver, format!("{} unsigned kernel driver(s) loaded", unsigned.len()),
                45.0,
            )
            .explain(
                "These drivers carry no valid signature, in either an embedded Authenticode block \
                 or a system catalog. On a standard configuration Windows would refuse to load \
                 them, so either test signing is on or they were installed by unusual means.",
            )
            .recommend(
                "Replace each with a current signed release from the hardware vendor, or remove it. \
                 If test signing is enabled and you did not enable it deliberately, turn it off.",
            )
            .command("Check test signing state", "bcdedit /enum {current}")
            .evidence_all(unsigned.iter().take(20).map(|d| {
                Evidence::new(format!("{} ({}) at {}", d.name, d.company, d.path))
            }))
        ]
    }
}

/// Several tools competing for the same low-level sensor interfaces.
pub struct SensorContentionRule;

impl HeuristicRule for SensorContentionRule {
    fn name(&self) -> &'static str {
        "SensorContentionRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        let contending: Vec<&DriverInfo> = report
            .drivers
            .iter()
            .filter(|d| !d.is_os_driver && d.category.contends_for_sensors())
            .collect();

        // One monitoring tool is normal and harmless. Contention needs at least
        // two independent things polling the same bus — the previous rule fired
        // on a single driver, which is why it triggered almost everywhere.
        if contending.len() < 2 {
            return Vec::new();
        }

        let weight = (40.0 + contending.len() as f32 * 12.0).min(78.0);
        vec![
            Finding::new(
                self.name(),
                RootCause::SensorContention,
                format!(
                    "{} tools competing for hardware sensor access",
                    contending.len()
                ),
                weight,
            )
            .explain(
                "Several drivers are polling the same SMBus/I2C sensor interfaces. These buses do \
                 not arbitrate between independent readers, so simultaneous polling causes stalls, \
                 dropped transactions and — on some boards — hard hangs.",
            )
            .recommend(
                "Keep one monitoring or lighting utility and close the rest, then retest. This is \
                 free to try and rules the whole class out quickly.",
            )
            .evidence_all(contending.iter().map(|d| {
                Evidence::new(format!(
                    "{} [{}] from {}",
                    d.name,
                    d.category.label(),
                    if d.company == "Unknown" {
                        d.publisher.as_str()
                    } else {
                        d.company.as_str()
                    }
                ))
            })),
        ]
    }
}

// ---------------------------------------------------------------------------
// Devices and services
// ---------------------------------------------------------------------------

pub struct DeviceProblemRule;

impl HeuristicRule for DeviceProblemRule {
    fn name(&self) -> &'static str {
        "DeviceProblemRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        // A device the user disabled is not a fault.
        let faults: Vec<&DeviceState> = report
            .device_problems
            .iter()
            .filter(|d| {
                d.problem_code
                    .is_some_and(device_inspector::is_hardware_fault)
            })
            .collect();
        if faults.is_empty() {
            return Vec::new();
        }

        vec![
            Finding::new(
                self.name(),
                RootCause::DeviceInstability,
                format!("{} device(s) reporting a fault", faults.len()),
                (50.0 + faults.len() as f32 * 10.0).min(85.0),
            )
            .explain(
                "These devices are present but not working. A device that cannot start or that its \
                 driver has failed can stall the bus it sits on and take the rest of the system \
                 with it.",
            )
            .recommend(
                "Work through each device in Device Manager: reinstall its driver, then reseat or \
                 disconnect the hardware to see whether stability returns.",
            )
            .command("Open Device Manager", "devmgmt.msc")
            .evidence_all(
                faults
                    .iter()
                    .map(|d| Evidence::new(format!("{} — {} [{}]", d.name, d.status, d.device_id))),
            ),
        ]
    }
}

/// Devices repeatedly disappearing and returning.
pub struct DeviceReEnumerationRule;

impl HeuristicRule for DeviceReEnumerationRule {
    fn name(&self) -> &'static str {
        "DeviceReEnumerationRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        let events: Vec<&EventRecord> = report
            .timeline
            .iter()
            .filter(|e| {
                e.source.contains("Kernel-PnP") && matches!(e.event_id, 400 | 410 | 411 | 420 | 430)
            })
            .collect();

        // Some churn is normal — docking, USB devices being plugged in. A high
        // rate is not.
        let per_day = events.len() as f32 / report.scan_window.days() as f32;
        if events.len() < 10 || per_day < 4.0 {
            return Vec::new();
        }

        vec![
            Finding::new(
                self.name(),
                RootCause::DeviceInstability,
                "Devices are repeatedly re-enumerating",
                (45.0 + per_day * 2.0).min(80.0),
            )
            .explain(format!(
                "{} device configuration events in {} days ({per_day:.1} per day). Devices \
                 dropping off the bus and returning points at a marginal connection, a failing \
                 hub or controller, or a driver that keeps resetting its hardware.",
                events.len(),
                report.scan_window.days()
            ))
            .recommend(
                "Watch for a device that disappears and returns in Device Manager, then reseat its \
                 cable or move it to a different port or slot.",
            )
            .evidence_all(events.iter().take(8).map(|e| {
                Evidence::at(
                    format!(
                        "{} event {}: {}",
                        e.source,
                        e.event_id,
                        truncate(&e.message, 140)
                    ),
                    e.timestamp,
                )
            }))
            .seen_at(latest(&events)),
        ]
    }
}

/// Services that failed *and* were logged as failing.
pub struct ServiceFailureRule;

impl HeuristicRule for ServiceFailureRule {
    fn name(&self) -> &'static str {
        "ServiceFailureRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        // Corroboration is required. A stopped service holding a stale exit
        // code is not evidence of anything, and reporting it was why this rule
        // fired on every healthy machine.
        let failures: Vec<&ServiceState> = report
            .service_problems
            .iter()
            .filter(|s| s.corroborated_by_log)
            .collect();
        if failures.is_empty() {
            return Vec::new();
        }

        vec![
            Finding::new(
                self.name(),
                RootCause::ServiceFailure,
                format!("{} service(s) terminated unexpectedly", failures.len()),
                (35.0 + failures.len() as f32 * 8.0).min(70.0),
            )
            .explain(
                "The Service Control Manager recorded these services failing, and they are stopped \
                 with a failure code. Repeated service crashes are frequently downstream of the \
                 real problem — memory pressure, disk errors or a faulting driver.",
            )
            .recommend(
                "Check the Application log around each failure for the faulting module, which \
                 usually names the real cause.",
            )
            .evidence_all(failures.iter().map(|s| {
                Evidence::new(format!(
                    "{} ({}): {}",
                    s.display_name,
                    s.name,
                    service_inspector::describe_exit_code(s.exit_code)
                ))
            })),
        ]
    }
}

// ---------------------------------------------------------------------------
// Trends and context
// ---------------------------------------------------------------------------

/// Overall instability rate.
pub struct ReliabilityTrendRule;

impl HeuristicRule for ReliabilityTrendRule {
    fn name(&self) -> &'static str {
        "ReliabilityTrendRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        let days = report.scan_window.days() as f32;
        let critical: Vec<&EventRecord> = report
            .timeline
            .iter()
            .filter(|e| e.level >= EventLevel::Error)
            .collect();
        let per_day = critical.len() as f32 / days;
        // Every Windows machine logs some errors. Only an elevated rate is a
        // finding at all, and even then it is context rather than a cause.
        if per_day < 20.0 {
            return Vec::new();
        }

        vec![
            Finding::new(
                self.name(),
                RootCause::InstabilityTrend,
                "Elevated system error rate",
                (30.0 + per_day.min(60.0)).min(72.0),
            )
            .explain(format!(
                "{} error or critical events over {days:.0} days ({per_day:.0} per day). This is \
                 context rather than a cause on its own, but it says the machine is working through \
                 something continuously.", critical.len()
            ))
            .recommend("Use the ranked causes above; this rate is a symptom of them.")
            .evidence_all(top_sources(&critical).into_iter().map(|(source, count)| {
                Evidence::new(format!("{count} events from {source}"))
            }))
            .seen_at(latest(&critical)),
        ]
    }
}

fn top_sources<'a>(events: &[&'a EventRecord]) -> Vec<(&'a str, usize)> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for event in events {
        *counts.entry(event.source.as_str()).or_default() += 1;
    }
    let mut ranked: Vec<(&str, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    ranked.truncate(5);
    ranked
}

/// The regression bisect result, promoted to a finding.
pub struct ChangepointRule;

impl HeuristicRule for ChangepointRule {
    fn name(&self) -> &'static str {
        "ChangepointRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        let Some(analysis) = &report.changepoint else {
            return Vec::new();
        };
        // Without a change to point at, the changepoint is a date, not a lead.
        if analysis.suspect_changes.is_empty() {
            return Vec::new();
        }

        // A clean stable period before the changepoint is much stronger evidence
        // than a rate that merely increased.
        let weight = if analysis.crashes_before == 0 {
            84.0
        } else {
            62.0
        };
        vec![
            Finding::new(
                self.name(),
                RootCause::RecentRegression,
                "Instability began after a specific system change",
                weight,
            )
            .explain(analysis.summary.clone())
            .recommend(
                "Roll back or uninstall the change closest to that date and retest. If it is a \
                 driver, install the previous version rather than only rolling back the update.",
            )
            .command(
                "List update history",
                "Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 10",
            )
            .command("Remove an update", "wusa /uninstall /kb:<KB number>")
            .evidence_all(analysis.suspect_changes.iter().take(10).map(|change| {
                Evidence::at(
                    format!("{} [{}]", change.name, change.change_type.label()),
                    change.date,
                )
            }))
            .seen_at(Some(analysis.changepoint)),
        ]
    }
}

/// Kernel mitigations that are switched off.
pub struct SecurityPostureRule;

impl HeuristicRule for SecurityPostureRule {
    fn name(&self) -> &'static str {
        "SecurityPostureRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        let weaknesses = report.security.weaknesses();
        if weaknesses.is_empty() {
            return Vec::new();
        }

        // On its own this is advisory. It becomes a real finding when a
        // vulnerable driver is actually loaded, and the engine merges the two.
        let vulnerable_loaded = report.drivers.iter().any(|d| d.vulnerability.is_some());
        if !vulnerable_loaded {
            return Vec::new();
        }

        vec![
            Finding::new(
                self.name(),
                RootCause::VulnerableDriver,
                "Kernel protections are off while a vulnerable driver is loaded",
                60.0,
            )
            .explain(
                "The mitigations that would block a known-vulnerable driver from loading are \
                 disabled on this machine, and such a driver is loaded right now.",
            )
            .recommend(
                "Switch Memory Integrity on, then reboot and confirm the driver no longer loads.",
            )
            .evidence_all(weaknesses.into_iter().map(Evidence::new)),
        ]
    }
}

/// Old firmware on a machine that is reporting hardware errors.
pub struct FirmwareAgeRule;

impl HeuristicRule for FirmwareAgeRule {
    fn name(&self) -> &'static str {
        "FirmwareAgeRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        let Some(age) = report.firmware.age_years() else {
            return Vec::new();
        };
        // Old firmware alone is not a problem. Old firmware on a machine that is
        // reporting hardware errors is a lead, because memory training and
        // stability fixes ship in firmware updates.
        let hardware_trouble = report.timeline.iter().any(|e| e.source.contains("WHEA"))
            || report
                .crashes
                .iter()
                .any(|c| matches!(c.bugcheck_code, 0x124 | 0x9C | 0x101 | 0x1A));
        if age < 2.0 || !hardware_trouble {
            return Vec::new();
        }

        vec![
            Finding::new(
                self.name(),
                RootCause::HardwareError,
                "System firmware is well behind current",
                40.0,
            )
            .explain(format!(
                "The installed firmware ({}, version {}) is about {age:.1} years old, and this \
                 machine is reporting hardware-level errors. Memory compatibility and stability \
                 fixes are delivered through firmware updates.",
                report.firmware.vendor, report.firmware.version
            ))
            .recommend(
                "Check the board vendor's support page for a newer BIOS release, and read its \
                 changelog for memory or stability fixes before applying it.",
            )
            .evidence(Evidence::new(format!(
                "BIOS {} dated {}",
                report.firmware.version, report.firmware.date
            ))),
        ]
    }
}

/// Repeatedly crashing applications.
///
/// Not a system fault, and deliberately weighted low — but a process that dies
/// over and over is frequently downstream of something real (failing memory,
/// disk corruption, an over-aggressive security product), so it is worth
/// surfacing as its own modest finding rather than being silently dropped or,
/// as before, misreported as a blue screen.
pub struct ApplicationCrashRule;

impl HeuristicRule for ApplicationCrashRule {
    fn name(&self) -> &'static str {
        "ApplicationCrashRule"
    }

    fn evaluate(&self, report: &DiagnosticReport) -> Vec<Finding> {
        let mut by_process: HashMap<String, Vec<&CrashRecord>> = HashMap::new();
        for crash in report
            .crashes
            .iter()
            .filter(|c| c.source == CrashSource::UserDump)
        {
            let process = crash
                .faulting_module
                .clone()
                .or_else(|| {
                    std::path::Path::new(&crash.dump_path).file_name().map(|n| {
                        n.to_string_lossy()
                            .split('.')
                            .next()
                            .unwrap_or("")
                            .to_string()
                    })
                })
                .unwrap_or_else(|| "an unidentified process".to_string());
            by_process.entry(process).or_default().push(crash);
        }

        by_process
            .into_iter()
            // One application crash is an ordinary event on any machine.
            .filter(|(_, crashes)| crashes.len() > 1)
            .map(|(process, crashes)| {
                let evidence: Vec<Evidence> = crashes
                    .iter()
                    .take(8)
                    .map(|c| {
                        Evidence::at(
                            format!("{} (0x{:08X})", c.bugcheck_name, c.bugcheck_code), c.timestamp,
                        )
                        .from(c.dump_path.clone())
                    })
                    .collect();

                Finding::new(
                    "ApplicationCrashRule",
                    RootCause::ApplicationFault { process: process.clone() }, format!("{process} crashed {} times", crashes.len()),
                    (22.0 + crashes.len() as f32 * 6.0).min(55.0),
                )
                .explain(
                    "An application crashed repeatedly. This is not a system fault, but a process that keeps dying in the same way is often reacting to something underneath it                      — failing memory, disk errors, or an interfering security product.",
                )
                .recommend(
                    "If the crashes are confined to this one application, treat it as an application problem. If several unrelated programs are crashing, look at the hardware findings above first.",
                )
                .evidence_all(evidence)
                .seen_at(crashes.iter().map(|c| c.timestamp).max())
            })
            .collect()
    }
}

fn truncate(text: &str, limit: usize) -> String {
    let cleaned = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.chars().count() <= limit {
        return cleaned;
    }
    let cut: String = cleaned.chars().take(limit).collect();
    format!("{cut}…")
}

/// Every rule, in registration order. Both front-ends use this, so the two can
/// no longer drift apart.
pub fn all_rules() -> Vec<Box<dyn HeuristicRule>> {
    vec![
        Box::new(WheaRule),
        Box::new(DiskErrorRule),
        Box::new(BugCheckRule),
        Box::new(CrashAttributionRule),
        Box::new(PowerLossRule),
        Box::new(ApplicationCrashRule),
        Box::new(VulnerableDriverRule),
        Box::new(UnsignedDriverRule),
        Box::new(SensorContentionRule),
        Box::new(DeviceProblemRule),
        Box::new(DeviceReEnumerationRule),
        Box::new(ServiceFailureRule),
        Box::new(ReliabilityTrendRule),
        Box::new(ChangepointRule),
        Box::new(SecurityPostureRule),
        Box::new(FirmwareAgeRule),
    ]
}

#[cfg(test)]
mod tests;
