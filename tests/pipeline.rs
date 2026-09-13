//! End-to-end tests across the whole pipeline.
//!
//! The unit tests cover each stage in isolation. These check the seams: that a
//! report travelling through correlation, changepoint analysis, the rules and
//! the scorer comes out the far side saying something true, and that every
//! renderer agrees with it.

use winsleuth::modules::analysis::{changepoint, correlation_engine, rules};
use winsleuth::modules::core::models::*;
use winsleuth::modules::core::{fixtures, scoring};
use winsleuth::modules::ui_layer::{bundle, html_report, reporting};
use winsleuth::modules::verifier;

/// Run the post-collection half of a scan: what the engine does once the
/// providers have returned.
fn analyse(mut report: DiagnosticReport) -> DiagnosticReport {
    report.correlations = correlation_engine::correlate(&report);

    let crash_times: Vec<_> = report
        .correlations
        .iter()
        .map(|w| w.crash.timestamp)
        .collect();
    report.changepoint =
        changepoint::analyse(&crash_times, &report.recent_changes, &report.scan_window);

    let findings: Vec<Finding> = rules::all_rules()
        .iter()
        .flat_map(|rule| rule.evaluate(&report))
        .collect();
    report.suspected_causes = scoring::combine(findings, &report.scan_window);

    report
}

#[test]
fn a_healthy_machine_produces_a_clean_report_in_every_format() {
    let report = analyse(fixtures::healthy_machine());

    assert!(
        report.suspected_causes.is_empty(),
        "a healthy machine must produce no causes, got: {:?}",
        report
            .suspected_causes
            .iter()
            .map(|c| &c.title)
            .collect::<Vec<_>>()
    );

    let text = reporting::render_text(&report);
    assert!(text.contains("No instability patterns were found"));

    let html = html_report::render(&report);
    assert!(html.contains("No instability patterns were found"));

    let json = reporting::export_json(&report);
    let parsed: DiagnosticReport = serde_json::from_str(&json).expect("JSON must round-trip");
    assert!(parsed.suspected_causes.is_empty());
}

#[test]
fn a_hardware_fault_produces_one_ranked_verdict_not_three() {
    let report = analyse(fixtures::hardware_fault_machine());

    let hardware = report
        .suspected_causes
        .iter()
        .find(|c| c.id == "hardware-error")
        .expect("WHEA events, the 0x124 stop code and old firmware must merge");

    assert!(
        hardware.contributing_rules.len() >= 3,
        "expected corroboration from several rules, got {:?}",
        hardware.contributing_rules
    );
    assert_eq!(hardware.confidence, ConfidenceLevel::Certain);
    assert_eq!(
        report.suspected_causes[0].id, "hardware-error",
        "the strongest cause must lead"
    );

    // The advice must point at hardware, not at reinstalling a driver.
    assert!(
        hardware.recommendation.to_lowercase().contains("stock"),
        "got: {}",
        hardware.recommendation
    );
}

#[test]
fn a_driver_fault_names_the_driver_and_offers_it_to_verifier() {
    let report = analyse(fixtures::driver_fault_machine());

    let cause = report
        .suspected_causes
        .iter()
        .find(|c| c.id.starts_with("driver-fault:"))
        .expect("the dump attributed both crashes to flaky.sys");
    assert!(cause.title.contains("flaky.sys"));

    // The verifier plan should pick up exactly that driver.
    let plan = verifier::plan_from_report(&report);
    assert!(
        plan.drivers
            .iter()
            .any(|d| d.eq_ignore_ascii_case("flaky.sys")),
        "the named culprit must be first in line for Driver Verifier: {:?}",
        plan.drivers
    );
    assert!(verifier::recovery_notice(&plan).contains("Safe Mode"));
}

#[test]
fn a_regression_is_reported_with_the_change_that_caused_it() {
    let report = analyse(fixtures::regression_machine());

    let analysis = report
        .changepoint
        .as_ref()
        .expect("a changepoint must be found");
    assert!(
        analysis.summary.contains("NVIDIA"),
        "got: {}",
        analysis.summary
    );

    let cause = report
        .suspected_causes
        .iter()
        .find(|c| c.id == "recent-regression")
        .expect("the regression must be reported as a cause");
    assert!(cause.evidence.iter().any(|e| e.detail.contains("NVIDIA")));

    // And it must reach the reader.
    assert!(reporting::render_text(&report).contains("WHEN IT CHANGED"));
    assert!(html_report::render(&report).contains("When it changed"));
}

#[test]
fn correlation_never_shrinks_the_timeline() {
    // The defect that made three rules under-report on crashed machines.
    let before = fixtures::hardware_fault_machine();
    let event_count = before.timeline.len();

    let after = analyse(before);
    assert_eq!(after.timeline.len(), event_count);
    assert!(
        !after.correlations.is_empty(),
        "crashes must still be correlated"
    );
}

#[test]
fn a_user_mode_dump_is_never_reported_as_a_system_crash() {
    let mut report = fixtures::healthy_machine();
    let now = chrono::Utc::now();

    for offset in [1, 5, 9] {
        report.crashes.push(CrashRecord {
            timestamp: now - chrono::Duration::hours(offset),
            bugcheck_code: 0xC000_0409,
            bugcheck_name: "STACK_BUFFER_OVERRUN".into(),
            parameters: [0; 4],
            faulting_module: Some("SomeApp.exe".into()),
            faulting_address: Some(0x41DAF2),
            attribution: CrashAttribution::ModuleRange {
                module: "SomeApp.exe".into(),
            },
            dump_path: "C:\\Users\\x\\AppData\\Local\\CrashDumps\\SomeApp.exe.1.dmp".into(),
            source: CrashSource::UserDump,
        });
    }

    let report = analyse(report);

    assert_eq!(report.system_crashes().count(), 0);
    assert_eq!(report.application_crashes().count(), 3);
    assert!(
        report.correlations.is_empty(),
        "application crashes must not get crash-correlation windows"
    );

    // No cause may describe this as the machine crashing.
    for cause in &report.suspected_causes {
        assert!(
            !cause.title.contains("System crash"),
            "a user-mode dump was reported as a system crash: {}",
            cause.title
        );
    }

    let text = reporting::render_text(&report);
    assert!(text.contains("APPLICATION CRASHES"));
    assert!(!text.contains("SYSTEM CRASHES"));
}

#[test]
fn a_vulnerable_driver_reaches_every_output() {
    let report = analyse(fixtures::vulnerable_driver_machine());

    let cause = &report.suspected_causes[0];
    assert_eq!(cause.id, "vulnerable-driver");
    // A file-name match plus disabled protections is strong, but short of
    // certain: only an exact hash match from the fetched corpus proves that
    // *this build* is the vulnerable one.
    assert!(
        cause.confidence >= ConfidenceLevel::High,
        "got {:?} at {:.0}",
        cause.confidence,
        cause.score
    );
    assert!(
        cause.contributing_rules.len() >= 2,
        "the disabled mitigations must corroborate: {:?}",
        cause.contributing_rules
    );
    assert!(!cause.commands.is_empty(), "the fix must be actionable");

    for rendered in [
        reporting::render_text(&report),
        html_report::render(&report),
        reporting::export_json(&report),
    ] {
        assert!(
            rendered.contains("RTCore64.sys"),
            "the driver must be named everywhere"
        );
    }
}

#[test]
fn every_cause_is_actionable_and_ranked() {
    for machine in [
        fixtures::hardware_fault_machine(),
        fixtures::driver_fault_machine(),
        fixtures::failing_disk_machine(),
        fixtures::regression_machine(),
        fixtures::vulnerable_driver_machine(),
        fixtures::sensor_contention_machine(),
    ] {
        let report = analyse(machine);

        for cause in &report.suspected_causes {
            assert!(!cause.title.is_empty());
            assert!(
                !cause.explanation.is_empty(),
                "{} has no explanation",
                cause.id
            );
            assert!(
                !cause.recommendation.is_empty(),
                "{} has no advice",
                cause.id
            );
            assert!(!cause.evidence.is_empty(), "{} has no evidence", cause.id);
            assert!(!cause.contributing_rules.is_empty());
            assert!(
                cause.score > 0.0 && cause.score <= 99.5,
                "{} scored {}",
                cause.id,
                cause.score
            );
        }

        for pair in report.suspected_causes.windows(2) {
            assert!(
                pair[0].confidence > pair[1].confidence
                    || (pair[0].confidence == pair[1].confidence && pair[0].score >= pair[1].score),
                "ranking broken between {:?} and {:?}",
                pair[0].title,
                pair[1].title
            );
        }
    }
}

#[test]
fn an_evidence_bundle_round_trips() {
    let report = analyse(fixtures::failing_disk_machine());
    let path = std::env::temp_dir().join("winsleuth_pipeline_bundle.zip");

    let result = bundle::build(&report, &path, false).expect("bundle must build");
    assert!(result.bytes > 0);

    let file = std::fs::File::open(&path).unwrap();
    let mut archive = zip::ZipArchive::new(file).expect("valid zip");

    let mut json = String::new();
    {
        use std::io::Read;
        archive
            .by_name("report.json")
            .unwrap()
            .read_to_string(&mut json)
            .unwrap();
    }
    let parsed: DiagnosticReport = serde_json::from_str(&json).expect("bundled JSON must parse");
    assert_eq!(parsed.suspected_causes.len(), report.suspected_causes.len());

    let _ = std::fs::remove_file(&path);
}

/// A real scan against this machine. Asserts invariants that must hold whatever
/// the machine's actual state is.
#[test]
fn a_live_scan_honours_its_own_contract() {
    use winsleuth::modules::core::engine::WinSleuthEngine;

    let window = ScanWindow::last_days(3);
    let engine = WinSleuthEngine::with_defaults(window);
    let report = engine.run_scan();

    // Nothing may be collected from outside the requested window.
    for event in &report.timeline {
        assert!(
            window.contains(event.timestamp),
            "{} at {} escaped the window",
            event.source,
            event.timestamp
        );
    }
    for crash in &report.crashes {
        assert!(window.contains(crash.timestamp));
    }
    for change in &report.recent_changes {
        assert!(window.contains(change.date));
    }

    // Causes are ranked.
    for pair in report.suspected_causes.windows(2) {
        assert!(pair[0].confidence >= pair[1].confidence);
    }

    // No Microsoft operating system driver may be reported as third-party. This
    // is the defect that produced the previously committed example report.
    for driver in report.third_party_drivers() {
        if let Some(signer) = driver.signature.signer() {
            assert!(
                !matches!(signer, "Microsoft Windows" | "Microsoft Windows Publisher"),
                "{} signed by {signer} was classed as third-party",
                driver.name
            );
        }
    }

    // Live-map attribution needs a live driver; saved-map attribution carries
    // the historical range and may legitimately name a removed driver.
    for crash in &report.crashes {
        if crash.source != CrashSource::KernelDump {
            continue;
        }
        if let CrashAttribution::ModuleRange { module } = &crash.attribution {
            assert!(
                report
                    .drivers
                    .iter()
                    .any(|d| d.name.eq_ignore_ascii_case(module)),
                "{module} was named as a culprit but is not a loaded driver"
            );
        }
        if let CrashAttribution::DumpModuleRange {
            module,
            base_address,
            size,
        } = &crash.attribution
        {
            let address = crash
                .faulting_address
                .expect("saved-range attribution requires an address");
            assert!(*size > 0);
            assert!(*base_address <= address);
            assert!(
                base_address
                    .checked_add(u64::from(*size))
                    .is_some_and(|end| address < end)
            );
            assert_eq!(crash.faulting_module.as_deref(), Some(module.as_str()));
        }
    }

    // Every renderer must survive whatever the machine actually looks like.
    assert!(!reporting::render_text(&report).is_empty());
    assert!(html_report::render(&report).starts_with("<!doctype html>"));
    let json = reporting::export_json(&report);
    serde_json::from_str::<DiagnosticReport>(&json).expect("live report must round-trip");
}

#[test]
fn historical_driver_attribution_survives_scoring_rendering_and_json() {
    let mut report = fixtures::healthy_machine();
    report.crashes.push(fixtures::crash(
        0xD1,
        report.generated_at,
        CrashAttribution::DumpModuleRange {
            module: "removed.sys".into(),
            base_address: 0xFFFF_F803_1234_0000,
            size: 0x10000,
        },
        Some(0xFFFF_F803_1234_5678),
    ));
    let report = analyse(report);
    let cause = report
        .suspected_causes
        .iter()
        .find(|cause| cause.id == "driver-fault:removed.sys")
        .expect("a removed driver must still be reported from historical evidence");
    assert!(cause.recommendation.contains("absent from the current"));
    assert!(reporting::render_text(&report).contains("removed.sys"));
    assert!(html_report::render(&report).contains("removed.sys"));
    let json = reporting::export_json(&report);
    let restored: DiagnosticReport = serde_json::from_str(&json).unwrap();
    assert_eq!(
        restored.crashes[0].attribution,
        report.crashes[0].attribution
    );
    assert!(
        !verifier::plan_from_report(&report)
            .drivers
            .iter()
            .any(|driver| driver.eq_ignore_ascii_case("removed.sys")),
        "a historical driver must not be armed unless currently installed"
    );
}

/// Regenerates the committed example reports from fixture data.
///
/// Run with `WINSLEUTH_WRITE_EXAMPLES=1 cargo test --test pipeline regenerate`.
/// Fixtures rather than the developer's own machine: the examples are then
/// deterministic, illustrate a machine with something actually wrong with it,
/// and carry nobody's hostname or software inventory.
#[test]
fn regenerate_example_reports() {
    if std::env::var("WINSLEUTH_WRITE_EXAMPLES").is_err() {
        return;
    }

    let mut report = fixtures::hardware_fault_machine();

    // Give the example something of everything worth showing.
    report.drivers.push({
        let mut driver = fixtures::vendor_driver(
            "RTCore64.sys",
            "MSI",
            DriverCategory::Monitoring,
            0xFFFF_F800_0800_0000,
            0x8000,
        );
        driver.vulnerability =
            winsleuth::modules::analysis::loldrivers::lookup("RTCore64.sys", None);
        driver
    });
    report.security.hvci_enabled = Some(false);
    report.security.driver_blocklist_enabled = Some(false);
    report.device_problems = vec![fixtures::device("USB Root Hub (USB 3.0)", 43)];

    let now = chrono::Utc::now();
    for hours in [4, 18, 39] {
        report.timeline.push(EventRecord {
            source: "Disk".into(),
            channel: "System".into(),
            event_id: 7,
            timestamp: now - chrono::Duration::hours(hours),
            level: EventLevel::Error,
            message: r"The device, \Device\Harddisk1\DR1, has a bad block.".into(),
        });
    }

    let report = analyse(report);
    let dir = std::path::Path::new("examples");
    std::fs::create_dir_all(dir).unwrap();

    reporting::write_utf8(
        &dir.join("example_report.txt"),
        &reporting::render_text(&report),
    )
    .unwrap();
    reporting::write_utf8(
        &dir.join("example_report.json"),
        &reporting::export_json(&report),
    )
    .unwrap();
    reporting::write_utf8(
        &dir.join("example_report.html"),
        &html_report::render(&report),
    )
    .unwrap();

    assert!(
        !report.suspected_causes.is_empty(),
        "the example must show findings"
    );
}
