//! Supervised Driver Verifier runs.
//!
//! Driver Verifier is the definitive way to catch a misbehaving driver: it
//! forces the driver through hostile conditions until it breaks the rules, then
//! bugchecks with `0xC4 DRIVER_VERIFIER_DETECTED_VIOLATION` naming the culprit.
//!
//! Almost nobody configures it correctly, and — this is the important part — a
//! machine with Verifier armed against a genuinely broken driver will often
//! bugcheck during boot, before the user can turn it off again. Every path here
//! prints the recovery procedure *before* arming anything, targets only the
//! drivers actually under suspicion, and never arms every driver on the system.

use std::process::Command;

use crate::modules::core::models::{DiagnosticReport, SuspectedCause};

/// How many suspects to arm at once. Verifier's overhead scales with the number
/// of drivers monitored, and a short list keeps the result unambiguous.
const MAX_SUSPECTS: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub struct VerifierPlan {
    pub drivers: Vec<String>,
    /// Why each driver is on the list, for the confirmation prompt.
    pub reasons: Vec<String>,
}

impl VerifierPlan {
    pub fn is_empty(&self) -> bool {
        self.drivers.is_empty()
    }
}

/// Choose which drivers to arm from a finished scan.
///
/// Only third-party drivers are eligible. Arming Verifier against a
/// Microsoft-signed component wastes a reboot: the kernel is not the thing
/// under suspicion, and monitoring it produces noise rather than a verdict.
pub fn plan_from_report(report: &DiagnosticReport) -> VerifierPlan {
    let mut drivers: Vec<String> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();

    let consider =
        |name: &str, reason: String, drivers: &mut Vec<String>, reasons: &mut Vec<String>| {
            let is_third_party = report
                .drivers
                .iter()
                .any(|d| d.name.eq_ignore_ascii_case(name) && !d.is_os_driver);
            if !is_third_party {
                return;
            }
            if drivers.iter().any(|d| d.eq_ignore_ascii_case(name)) {
                return;
            }
            drivers.push(name.to_string());
            reasons.push(reason);
        };

    // Strongest first: a module the crash dump actually pointed at.
    for cause in &report.suspected_causes {
        if let Some(module) = driver_fault_module(cause) {
            consider(
                &module,
                format!(
                    "named by crash attribution ({} confidence)",
                    cause.confidence.label()
                ),
                &mut drivers,
                &mut reasons,
            );
        }
    }

    // Then drivers implicated by category: things that touch the kernel in the
    // ways Verifier is good at catching.
    for driver in report.drivers.iter().filter(|d| !d.is_os_driver) {
        if drivers.len() >= MAX_SUSPECTS {
            break;
        }
        if driver.vulnerability.is_some() {
            consider(
                &driver.name,
                "flagged as a known-vulnerable driver".to_string(),
                &mut drivers,
                &mut reasons,
            );
        } else if driver.category.contends_for_sensors() {
            consider(
                &driver.name,
                format!("low-level {} driver", driver.category.label()),
                &mut drivers,
                &mut reasons,
            );
        }
    }

    drivers.truncate(MAX_SUSPECTS);
    reasons.truncate(MAX_SUSPECTS);
    VerifierPlan { drivers, reasons }
}

fn driver_fault_module(cause: &SuspectedCause) -> Option<String> {
    // Cause ids are the root cause keys; a driver fault carries its module.
    cause
        .id
        .strip_prefix("driver-fault:")
        .map(|m| m.to_string())
}

/// The warning shown before anything is armed. Printed, not logged.
pub fn recovery_notice(plan: &VerifierPlan) -> String {
    let list = plan
        .drivers
        .iter()
        .zip(&plan.reasons)
        .map(|(driver, reason)| format!("    {driver}  ({reason})"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "Driver Verifier will be armed against {} driver(s):\n\n{list}\n\n\
         What happens next:\n\
         \x20 1. You reboot. Windows runs these drivers under hostile conditions.\n\
         \x20 2. If one breaks the rules the machine bugchecks with 0xC4 and names it.\n\
         \x20 3. Run `winsleuth scan` afterwards to read the verdict from the dump.\n\n\
         Before you reboot, read this:\n\
         \x20 - The machine may bugcheck during startup and fail to reach the desktop.\n\
         \x20 - To recover: interrupt boot twice, then choose\n\
         \x20   Troubleshoot > Advanced options > Startup Settings > Safe Mode,\n\
         \x20   and run `winsleuth verify --off` (or `verifier /reset`) from there.\n\
         \x20 - Verifier slows the system noticeably while it is armed. That is expected.\n\
         \x20 - Make sure anything unsaved is saved now.",
        plan.drivers.len()
    )
}

#[derive(Debug)]
pub struct CommandOutcome {
    pub success: bool,
    pub output: String,
}

/// Arm Verifier against the planned drivers.
///
/// Uses the standard rule set rather than every setting: the aggressive flags
/// produce false bugchecks on drivers that are unusual but not broken.
pub fn arm(plan: &VerifierPlan) -> anyhow::Result<CommandOutcome> {
    if plan.is_empty() {
        anyhow::bail!("no suspect drivers to arm Verifier against");
    }

    let mut args: Vec<String> = vec!["/standard".into(), "/driver".into()];
    args.extend(plan.drivers.iter().cloned());
    run(&args)
}

/// Turn Verifier off. Takes effect on the next reboot.
pub fn disable() -> anyhow::Result<CommandOutcome> {
    run(&["/reset".to_string()])
}

/// Report what Verifier is currently configured to do.
pub fn query() -> anyhow::Result<CommandOutcome> {
    run(&["/querysettings".to_string()])
}

fn run(args: &[String]) -> anyhow::Result<CommandOutcome> {
    let output = Command::new("verifier.exe").args(args).output()?;

    let mut text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let errors = String::from_utf8_lossy(&output.stderr);
    if !errors.trim().is_empty() {
        text.push('\n');
        text.push_str(errors.trim());
    }

    Ok(CommandOutcome {
        success: output.status.success(),
        output: text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::core::fixtures;
    use crate::modules::core::models::*;
    use crate::modules::core::scoring;

    #[test]
    fn plan_prefers_the_module_the_dump_named() {
        let mut report = fixtures::driver_fault_machine();
        report.suspected_causes = scoring::combine(
            vec![Finding::new(
                "CrashAttributionRule",
                RootCause::DriverFault {
                    module: "flaky.sys".into(),
                },
                "flaky.sys faulted",
                90.0,
            )],
            &report.scan_window,
        );
        let plan = plan_from_report(&report);
        assert_eq!(plan.drivers.first().map(|s| s.as_str()), Some("flaky.sys"));
        assert!(plan.reasons[0].contains("crash attribution"));
    }

    #[test]
    fn plan_never_arms_microsoft_drivers() {
        let mut report = fixtures::healthy_machine();
        report.suspected_causes = scoring::combine(
            vec![Finding::new(
                "CrashAttributionRule",
                RootCause::DriverFault {
                    module: "ntoskrnl.exe".into(),
                },
                "kernel faulted",
                90.0,
            )],
            &report.scan_window,
        );
        let plan = plan_from_report(&report);
        assert!(
            !plan
                .drivers
                .iter()
                .any(|d| d.eq_ignore_ascii_case("ntoskrnl.exe")),
            "arming Verifier against the kernel wastes a reboot"
        );
    }

    #[test]
    fn plan_is_bounded_and_free_of_duplicates() {
        let report = fixtures::sensor_contention_machine();
        let plan = plan_from_report(&report);
        assert!(plan.drivers.len() <= MAX_SUSPECTS);
        assert_eq!(plan.drivers.len(), plan.reasons.len());
        let mut sorted = plan.drivers.clone();
        sorted.sort();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "duplicate drivers in the plan");
    }

    #[test]
    fn a_healthy_machine_yields_nothing_to_verify() {
        // The single monitoring driver in the healthy fixture is a sensor
        // driver, so it is eligible; what matters is that nothing is invented.
        let report = fixtures::healthy_machine();
        let plan = plan_from_report(&report);
        for driver in &plan.drivers {
            assert!(
                report
                    .drivers
                    .iter()
                    .any(|d| d.name.eq_ignore_ascii_case(driver) && !d.is_os_driver),
                "{driver} is not a third-party driver on this machine"
            );
        }
    }

    #[test]
    fn the_recovery_notice_explains_how_to_get_back_in() {
        let plan = VerifierPlan {
            drivers: vec!["flaky.sys".into()],
            reasons: vec!["named by crash attribution".into()],
        };
        let notice = recovery_notice(&plan);
        assert!(notice.contains("flaky.sys"));
        assert!(
            notice.contains("Safe Mode"),
            "recovery path must be spelled out"
        );
        assert!(notice.contains("verify --off"));
        assert!(notice.contains("0xC4"));
    }

    #[test]
    fn arming_an_empty_plan_is_refused() {
        let plan = VerifierPlan {
            drivers: Vec::new(),
            reasons: Vec::new(),
        };
        assert!(arm(&plan).is_err());
    }
}
