//! One positive and one negative case per rule.
//!
//! The negative cases carry most of the weight: before this work every rule was
//! unverified, and several of them fired on a perfectly healthy machine.

use super::*;
use crate::modules::core::fixtures;
use chrono::Duration;

/// Run every registered rule and return the findings.
fn run_all(report: &DiagnosticReport) -> Vec<Finding> {
    all_rules()
        .iter()
        .flat_map(|rule| rule.evaluate(report))
        .collect()
}

fn rules_that_fired(report: &DiagnosticReport) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = all_rules()
        .iter()
        .filter(|rule| !rule.evaluate(report).is_empty())
        .map(|rule| rule.name())
        .collect();
    names.sort_unstable();
    names
}

// ---------------------------------------------------------------------------
// The headline case
// ---------------------------------------------------------------------------

#[test]
fn a_healthy_machine_produces_no_findings_at_all() {
    let report = fixtures::healthy_machine();
    let fired = rules_that_fired(&report);
    assert!(
        fired.is_empty(),
        "these rules fire on a healthy machine: {fired:?}"
    );
}

#[test]
fn every_rule_has_a_distinct_name() {
    let rules = all_rules();
    let mut names: Vec<&str> = rules.iter().map(|r| r.name()).collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(total, names.len(), "duplicate rule names");
    assert!(total >= 15, "expected the full rule set, found {total}");
}

#[test]
fn every_finding_carries_an_explanation_and_a_recommendation() {
    for report in [
        fixtures::hardware_fault_machine(),
        fixtures::driver_fault_machine(),
        fixtures::failing_disk_machine(),
        fixtures::regression_machine(),
        fixtures::vulnerable_driver_machine(),
        fixtures::sensor_contention_machine(),
    ] {
        for finding in run_all(&report) {
            assert!(!finding.title.is_empty(), "{} has no title", finding.rule);
            assert!(
                !finding.explanation.is_empty(),
                "{} has no explanation",
                finding.rule
            );
            assert!(
                !finding.recommendation.is_empty(),
                "{} has no recommendation",
                finding.rule
            );
            assert!(
                !finding.evidence.is_empty(),
                "{} has no evidence",
                finding.rule
            );
            assert!(
                finding.weight > 0.0 && finding.weight <= 100.0,
                "{} has weight {}",
                finding.rule,
                finding.weight
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------

#[test]
fn whea_rule_distinguishes_corrected_from_uncorrected() {
    let report = fixtures::hardware_fault_machine();
    let findings = WheaRule.evaluate(&report);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].title.contains("Uncorrected"));
    assert!(findings[0].weight > 85.0);
    assert_eq!(findings[0].root_cause, RootCause::HardwareError);

    // Corrected errors alone are a warning, not a crisis.
    let mut corrected_only = fixtures::healthy_machine();
    corrected_only.timeline.push(fixtures::event(
        "Microsoft-Windows-WHEA-Logger",
        17,
        EventLevel::Warning,
        Utc::now(),
    ));
    let findings = WheaRule.evaluate(&corrected_only);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].title.contains("Corrected"));
    assert!(findings[0].weight < 70.0);
}

#[test]
fn whea_rule_stays_silent_without_whea_events() {
    assert!(WheaRule.evaluate(&fixtures::healthy_machine()).is_empty());
}

#[test]
fn disk_rule_reports_one_finding_per_device() {
    let mut report = fixtures::failing_disk_machine();
    // Add a second failing disk; they must not be merged into one sentence.
    for hours in [3, 9, 21] {
        report.timeline.push(EventRecord {
            source: "Disk".into(),
            channel: "System".into(),
            event_id: 11,
            timestamp: Utc::now() - Duration::hours(hours),
            level: EventLevel::Error,
            message: "The driver detected a controller error on \\Device\\Harddisk2\\DR2.".into(),
        });
    }

    let findings = DiskErrorRule.evaluate(&report);
    assert_eq!(findings.len(), 2, "two failing disks are two findings");
    assert!(findings.iter().any(|f| f.title.contains("Harddisk1")));
    assert!(findings.iter().any(|f| f.title.contains("Harddisk2")));
    for finding in &findings {
        assert!(
            finding
                .commands
                .iter()
                .any(|c| c.command.contains("chkdsk"))
        );
    }
}

#[test]
fn disk_rule_ignores_unrelated_sources_and_ids() {
    let mut report = fixtures::healthy_machine();
    // A Disk source with a benign event id, and an unrelated source with a
    // storage-looking id.
    report
        .timeline
        .push(fixtures::event("Disk", 32, EventLevel::Error, Utc::now()));
    report
        .timeline
        .push(fixtures::event("Chrome", 7, EventLevel::Error, Utc::now()));
    assert!(DiskErrorRule.evaluate(&report).is_empty());
}

#[test]
fn firmware_age_only_matters_alongside_hardware_trouble() {
    // Old firmware plus WHEA errors is a lead.
    let report = fixtures::hardware_fault_machine();
    assert_eq!(FirmwareAgeRule.evaluate(&report).len(), 1);

    // Old firmware on a machine with no hardware errors is not a finding.
    let mut quiet = fixtures::healthy_machine();
    quiet.firmware.release_date = Some(Utc::now() - Duration::days(1800));
    assert!(FirmwareAgeRule.evaluate(&quiet).is_empty());
}

// ---------------------------------------------------------------------------
// Crashes
// ---------------------------------------------------------------------------

#[test]
fn bugcheck_rule_groups_by_stop_code_and_maps_the_root_cause() {
    let report = fixtures::hardware_fault_machine();
    let findings = BugCheckRule.evaluate(&report);

    assert_eq!(
        findings.len(),
        1,
        "two crashes with one stop code are one finding"
    );
    assert!(findings[0].title.contains("WHEA_UNCORRECTABLE_ERROR"));
    // A 0x124 must corroborate the WHEA finding, not stand apart from it.
    assert_eq!(findings[0].root_cause, RootCause::HardwareError);
    assert_eq!(findings[0].evidence.len(), 2);
}

#[test]
fn bugcheck_rule_separates_different_stop_codes() {
    let mut report = fixtures::healthy_machine();
    let now = Utc::now();
    report.crashes = vec![
        fixtures::crash(
            0x124,
            now - Duration::days(1),
            CrashAttribution::Undetermined,
            None,
        ),
        fixtures::crash(
            0x116,
            now - Duration::hours(2),
            CrashAttribution::Undetermined,
            None,
        ),
    ];

    let findings = BugCheckRule.evaluate(&report);
    assert_eq!(findings.len(), 2);
    assert!(
        findings
            .iter()
            .any(|f| f.root_cause == RootCause::HardwareError)
    );
    assert!(
        findings
            .iter()
            .any(|f| f.root_cause == RootCause::GraphicsTimeout)
    );
}

#[test]
fn attribution_rule_names_a_driver_only_when_the_dump_proved_it() {
    let report = fixtures::driver_fault_machine();
    let findings = CrashAttributionRule.evaluate(&report);

    assert_eq!(findings.len(), 1);
    assert!(findings[0].title.contains("flaky.sys"));
    assert_eq!(
        findings[0].root_cause,
        RootCause::DriverFault {
            module: "flaky.sys".into()
        }
    );
    // Repeated attribution is stronger than a single hit.
    assert!(findings[0].weight > 90.0);
}

#[test]
fn attribution_rule_says_nothing_when_attribution_is_undetermined() {
    // The old rule guessed here and published at score 95.
    let report = fixtures::hardware_fault_machine();
    assert!(
        CrashAttributionRule.evaluate(&report).is_empty(),
        "an unattributed crash must not name a driver"
    );

    let mut reported_only = fixtures::healthy_machine();
    reported_only.crashes = vec![fixtures::crash(
        0xD1,
        Utc::now(),
        CrashAttribution::DumpReported {
            module: "guess.sys".into(),
        },
        None,
    )];
    assert!(
        CrashAttributionRule.evaluate(&reported_only).is_empty(),
        "only a resolved image range is strong enough to name a culprit"
    );
}

#[test]
fn attribution_treats_a_microsoft_module_as_a_symptom() {
    let mut report = fixtures::healthy_machine();
    report.crashes = vec![fixtures::crash(
        0x50,
        Utc::now(),
        CrashAttribution::ModuleRange {
            module: "ntoskrnl.exe".into(),
        },
        Some(0xFFFF_F800_0100_1000),
    )];

    let findings = CrashAttributionRule.evaluate(&report);
    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].recommendation.contains("symptom"),
        "blaming the kernel itself would be useless advice: {}",
        findings[0].recommendation
    );
}

#[test]
fn power_loss_rule_ignores_shutdowns_that_left_a_dump() {
    let now = Utc::now();

    // A Kernel-Power 41 with a matching dump is a bugcheck, reported elsewhere.
    let mut with_dump = fixtures::healthy_machine();
    with_dump.timeline.push(fixtures::event(
        "Microsoft-Windows-Kernel-Power",
        41,
        EventLevel::Critical,
        now,
    ));
    with_dump.crashes = vec![fixtures::crash(
        0xD1,
        now,
        CrashAttribution::Undetermined,
        None,
    )];
    assert!(PowerLossRule.evaluate(&with_dump).is_empty());

    // The same event with no dump is a hard power loss.
    let mut without_dump = fixtures::healthy_machine();
    without_dump.timeline.push(fixtures::event(
        "Microsoft-Windows-Kernel-Power",
        41,
        EventLevel::Critical,
        now,
    ));
    let findings = PowerLossRule.evaluate(&without_dump);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].root_cause, RootCause::PowerLoss);
}

// ---------------------------------------------------------------------------
// Drivers
// ---------------------------------------------------------------------------

#[test]
fn vulnerable_driver_rule_flags_a_loaded_byovd_driver() {
    let report = fixtures::vulnerable_driver_machine();
    let findings = VulnerableDriverRule.evaluate(&report);

    assert_eq!(findings.len(), 1);
    assert!(findings[0].title.contains("RTCore64.sys"));
    assert_eq!(findings[0].root_cause, RootCause::VulnerableDriver);
    // HVCI being off must be surfaced as part of the evidence.
    assert!(
        findings[0]
            .evidence
            .iter()
            .any(|e| e.detail.contains("Memory Integrity")),
        "the mitigation state belongs in the evidence"
    );
}

#[test]
fn vulnerable_driver_rule_is_silent_on_an_ordinary_driver_set() {
    assert!(
        VulnerableDriverRule
            .evaluate(&fixtures::healthy_machine())
            .is_empty()
    );
}

#[test]
fn security_posture_only_reports_alongside_a_vulnerable_driver() {
    // Protections off but nothing vulnerable loaded: advisory, not a finding.
    let mut exposed = fixtures::healthy_machine();
    exposed.security.hvci_enabled = Some(false);
    assert!(SecurityPostureRule.evaluate(&exposed).is_empty());

    // Protections off with a vulnerable driver present: a real finding.
    let report = fixtures::vulnerable_driver_machine();
    assert_eq!(SecurityPostureRule.evaluate(&report).len(), 1);
}

#[test]
fn unsigned_rule_ignores_catalog_signed_and_unverifiable_drivers() {
    // The regression that produced the shipped example report.
    let report = fixtures::healthy_machine();
    assert!(
        UnsignedDriverRule.evaluate(&report).is_empty(),
        "catalog-signed Microsoft drivers must never be reported as unsigned"
    );

    // A file we could not verify is not evidence of anything.
    let mut unverifiable = fixtures::healthy_machine();
    unverifiable.drivers[0].signature = SignatureStatus::Unknown {
        reason: "locked".into(),
    };
    unverifiable.drivers[0].is_os_driver = false;
    assert!(UnsignedDriverRule.evaluate(&unverifiable).is_empty());

    // A genuinely unsigned driver is reported.
    let mut unsigned = fixtures::healthy_machine();
    unsigned.drivers.push({
        let mut d = fixtures::vendor_driver("rogue.sys", "Nobody", DriverCategory::Other, 0, 0);
        d.signature = SignatureStatus::Unsigned;
        d
    });
    let findings = UnsignedDriverRule.evaluate(&unsigned);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].title.contains('1'));
}

#[test]
fn sensor_contention_needs_more_than_one_tool() {
    // One monitoring driver is normal. The old rule fired on exactly this.
    assert!(
        SensorContentionRule
            .evaluate(&fixtures::healthy_machine())
            .is_empty(),
        "a single monitoring utility is not a conflict"
    );

    let report = fixtures::sensor_contention_machine();
    let findings = SensorContentionRule.evaluate(&report);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].root_cause, RootCause::SensorContention);
    assert!(findings[0].evidence.len() >= 3);
}

// ---------------------------------------------------------------------------
// Devices and services
// ---------------------------------------------------------------------------

#[test]
fn device_rule_ignores_devices_the_user_disabled() {
    let mut disabled = fixtures::healthy_machine();
    disabled.device_problems = vec![fixtures::device("Old Sound Card", 22)];
    assert!(
        DeviceProblemRule.evaluate(&disabled).is_empty(),
        "code 22 means the user disabled it"
    );

    let mut broken = fixtures::healthy_machine();
    broken.device_problems = vec![fixtures::device("USB Controller", 43)];
    let findings = DeviceProblemRule.evaluate(&broken);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].root_cause, RootCause::DeviceInstability);
}

#[test]
fn re_enumeration_rule_tolerates_ordinary_device_churn() {
    let now = Utc::now();

    // A handful of PnP events over a week is normal use.
    let mut quiet = fixtures::healthy_machine();
    for i in 0..6 {
        quiet.timeline.push(fixtures::event(
            "Microsoft-Windows-Kernel-PnP",
            410,
            EventLevel::Information,
            now - Duration::hours(i * 12),
        ));
    }
    assert!(DeviceReEnumerationRule.evaluate(&quiet).is_empty());

    // Sustained churn is a finding.
    let mut noisy = fixtures::healthy_machine();
    for i in 0..80 {
        noisy.timeline.push(fixtures::event(
            "Microsoft-Windows-Kernel-PnP",
            410,
            EventLevel::Information,
            now - Duration::minutes(i * 30),
        ));
    }
    assert_eq!(DeviceReEnumerationRule.evaluate(&noisy).len(), 1);
}

#[test]
fn service_rule_requires_corroboration_from_the_log() {
    // Stale exit codes on stopped services: what flooded the old report.
    let mut stale = fixtures::healthy_machine();
    stale.service_problems = vec![
        fixtures::service("SomeService", 1067, false),
        fixtures::service("AnotherService", 1053, false),
    ];
    assert!(
        ServiceFailureRule.evaluate(&stale).is_empty(),
        "an uncorroborated exit code is not a failure"
    );

    let mut real = fixtures::healthy_machine();
    real.service_problems = vec![fixtures::service("SomeService", 1067, true)];
    let findings = ServiceFailureRule.evaluate(&real);
    assert_eq!(findings.len(), 1);
    assert!(
        findings[0].evidence[0]
            .detail
            .contains("terminated unexpectedly")
    );
}

// ---------------------------------------------------------------------------
// Trends
// ---------------------------------------------------------------------------

#[test]
fn reliability_trend_needs_a_genuinely_elevated_rate() {
    assert!(
        ReliabilityTrendRule
            .evaluate(&fixtures::healthy_machine())
            .is_empty()
    );

    let mut noisy = fixtures::healthy_machine();
    let now = Utc::now();
    for i in 0..300 {
        noisy.timeline.push(fixtures::event(
            "Application Error",
            1000,
            EventLevel::Error,
            now - Duration::minutes(i * 20),
        ));
    }
    let findings = ReliabilityTrendRule.evaluate(&noisy);
    assert_eq!(findings.len(), 1);
    // It must present itself as context, not as a cause.
    assert!(findings[0].explanation.contains("context"));
}

#[test]
fn changepoint_rule_needs_a_change_to_point_at() {
    use crate::modules::analysis::changepoint;

    let mut report = fixtures::regression_machine();
    let crashes: Vec<_> = report.crashes.iter().map(|c| c.timestamp).collect();
    report.changepoint =
        changepoint::analyse(&crashes, &report.recent_changes, &report.scan_window);

    let findings = ChangepointRule.evaluate(&report);
    assert_eq!(findings.len(), 1);
    assert!(findings[0].explanation.contains("NVIDIA"));
    assert_eq!(findings[0].root_cause, RootCause::RecentRegression);

    // A changepoint with no nearby change is a date, not a lead.
    let mut no_changes = report.clone();
    no_changes.changepoint = changepoint::analyse(&crashes, &[], &no_changes.scan_window);
    assert!(ChangepointRule.evaluate(&no_changes).is_empty());

    // No analysis at all means nothing to report.
    let mut none = report.clone();
    none.changepoint = None;
    assert!(ChangepointRule.evaluate(&none).is_empty());
}

// ---------------------------------------------------------------------------
// End to end through the scorer
// ---------------------------------------------------------------------------

#[test]
fn corroborating_rules_collapse_into_one_ranked_cause() {
    use crate::modules::core::scoring;

    let report = fixtures::hardware_fault_machine();
    let causes = scoring::combine(run_all(&report), &report.scan_window);

    let hardware = causes
        .iter()
        .find(|c| c.id == "hardware-error")
        .expect("WHEA, the 0x124 stop code and old firmware must merge");

    assert!(
        hardware.contributing_rules.len() >= 3,
        "expected several rules to corroborate, got {:?}",
        hardware.contributing_rules
    );
    assert!(hardware.score > 90.0);
    assert_eq!(hardware.confidence, ConfidenceLevel::Certain);
    // It must be ranked first.
    assert_eq!(causes[0].id, "hardware-error");
}

#[test]
fn causes_are_returned_in_ranked_order() {
    use crate::modules::core::scoring;

    let report = fixtures::driver_fault_machine();
    let causes = scoring::combine(run_all(&report), &report.scan_window);
    assert!(!causes.is_empty());

    for pair in causes.windows(2) {
        assert!(
            pair[0].confidence > pair[1].confidence
                || (pair[0].confidence == pair[1].confidence && pair[0].score >= pair[1].score),
            "ranking is broken: {:?} before {:?}",
            (&pair[0].title, pair[0].confidence, pair[0].score),
            (&pair[1].title, pair[1].confidence, pair[1].score),
        );
    }
}

#[test]
fn a_healthy_machine_scores_to_an_empty_report() {
    use crate::modules::core::scoring;

    let report = fixtures::healthy_machine();
    let causes = scoring::combine(run_all(&report), &report.scan_window);
    assert!(
        causes.is_empty(),
        "healthy machine produced causes: {causes:?}"
    );
}
