//! Console and JSON rendering.
//!
//! The console report leads with the verdict. The previous version printed
//! several hundred drivers before reaching the analysis, which buried the one
//! part the user came for.

use std::io::Write;
use std::path::Path;

use crate::modules::core::models::*;
use crate::modules::core::store::ReportDiff;
use crate::modules::providers::device_inspector;

/// Write a report to disk as UTF-8.
///
/// The documented `scan --format json > report.json` produced UTF-16 with a
/// byte order mark under PowerShell, which most JSON parsers reject.
pub fn write_utf8(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(contents.as_bytes())
}

pub fn export_json(report: &DiagnosticReport) -> String {
    serde_json::to_string_pretty(report)
        .unwrap_or_else(|e| format!("{{\"error\":\"could not serialise report: {e}\"}}"))
}

pub fn render_text(report: &DiagnosticReport) -> String {
    let mut out = String::new();
    let line = "─".repeat(78);

    // ---- Header -----------------------------------------------------------
    out.push_str(&format!(
        "\nWinSleuth report — {}\n",
        report.system.hostname
    ));
    out.push_str(&format!("{line}\n"));
    out.push_str(&format!(
        "  {} ({})\n  {} {}\n  {}, {:.0} GB RAM\n  BIOS {} {} dated {}\n",
        report.system.os_caption,
        report.system.os_build,
        report.system.motherboard_vendor,
        report.system.motherboard_model,
        report.system.cpu_model,
        report.system.physical_memory_gb,
        report.firmware.vendor,
        report.firmware.version,
        report.firmware.date,
    ));
    out.push_str(&format!(
        "  Window: {} → {} ({} days)\n",
        report.scan_window.since.format("%Y-%m-%d %H:%M"),
        report.scan_window.until.format("%Y-%m-%d %H:%M"),
        report.scan_window.days(),
    ));

    if !report.elevated {
        out.push_str(
            "\n  ! Not running as Administrator. Crash dumps, service state and kernel\n    \
             module addresses are unavailable, so findings are incomplete.\n",
        );
    }

    // ---- The verdict, first ----------------------------------------------
    out.push_str(&format!("\nRANKED CAUSES\n{line}\n"));
    if report.suspected_causes.is_empty() {
        out.push_str("  No instability patterns were found in this window.\n");
        if !report.elevated {
            out.push_str(
                "  Note: an unelevated scan can miss the evidence entirely. Re-run as\n  \
                          Administrator before concluding the machine is healthy.\n",
            );
        }
    } else {
        for (index, cause) in report.suspected_causes.iter().enumerate() {
            out.push_str(&format!(
                "\n  {}. [{}] {}  ({:.0}/100)\n",
                index + 1,
                cause.confidence.label().to_uppercase(),
                cause.title,
                cause.score
            ));
            out.push_str(&wrap(&cause.explanation, 74, "     "));
            if !cause.evidence.is_empty() {
                out.push_str("\n     Evidence:\n");
                for item in cause.evidence.iter().take(8) {
                    let when = item
                        .timestamp
                        .map(|t| format!("{} ", t.format("%Y-%m-%d %H:%M")))
                        .unwrap_or_default();
                    out.push_str(&format!("       · {when}{}\n", item.detail));
                }
                if cause.evidence.len() > 8 {
                    out.push_str(&format!(
                        "       · … and {} more\n",
                        cause.evidence.len() - 8
                    ));
                }
            }

            out.push_str("\n     What to do:\n");
            out.push_str(&wrap(&cause.recommendation, 72, "       "));
            if !cause.commands.is_empty() {
                out.push('\n');
                for command in &cause.commands {
                    out.push_str(&format!("       $ {}\n", command.command));
                    out.push_str(&format!("         ({})\n", command.label));
                }
            }

            out.push_str(&format!(
                "     Corroborated by: {}\n",
                cause.contributing_rules.join(", ")
            ));
        }
    }

    // ---- Regression -------------------------------------------------------
    if let Some(analysis) = &report.changepoint {
        out.push_str(&format!("\nWHEN IT CHANGED\n{line}\n"));
        out.push_str(&wrap(&analysis.summary, 76, "  "));
        for change in analysis.suspect_changes.iter().take(8) {
            out.push_str(&format!(
                "    · {} — {} [{}]\n",
                change.date.format("%Y-%m-%d"),
                change.name,
                change.change_type.label()
            ));
        }
    }

    // ---- Crashes ----------------------------------------------------------
    // System crashes and application crashes are different problems and are
    // never listed together: 0xC0000409 from a user-mode dump is an exception
    // code, not a stop code.
    let system: Vec<&CrashRecord> = report.system_crashes().collect();
    if !system.is_empty() {
        out.push_str(&format!("\nSYSTEM CRASHES\n{line}\n"));
        for crash in system.iter().take(15) {
            out.push_str(&format!(
                "  {}  0x{:08X} {}\n",
                crash.timestamp.format("%Y-%m-%d %H:%M"),
                crash.bugcheck_code,
                crash.bugcheck_name
            ));
            match crash.attribution.module() {
                Some(module) => out.push_str(&format!(
                    "      culprit: {module} ({})\n",
                    crash.attribution.describe()
                )),
                None => out.push_str("      culprit: not established\n"),
            }
        }
    }

    let applications: Vec<&CrashRecord> = report.application_crashes().collect();
    if !applications.is_empty() {
        out.push_str(&format!("\nAPPLICATION CRASHES\n{line}\n"));
        out.push_str("  User-mode program crashes, not system faults.\n\n");
        for crash in applications.iter().take(15) {
            out.push_str(&format!(
                "  {}  {:<30} {}\n",
                crash.timestamp.format("%Y-%m-%d %H:%M"),
                crash.faulting_module.as_deref().unwrap_or("unknown"),
                crash.bugcheck_name
            ));
        }
    }

    // ---- Security ---------------------------------------------------------
    let weaknesses = report.security.weaknesses();
    if report.security.is_known() {
        out.push_str(&format!("\nKERNEL PROTECTIONS\n{line}\n"));
        out.push_str(&format!(
            "  Memory Integrity (HVCI): {}\n  Vulnerable driver blocklist: {}\n  Secure Boot: {}\n",
            tri(report.security.hvci_enabled),
            tri(report.security.driver_blocklist_enabled),
            tri(report.security.secure_boot),
        ));
        for weakness in &weaknesses {
            out.push_str(&format!("  ! {weakness}\n"));
        }
    }

    // ---- Devices and services --------------------------------------------
    if !report.device_problems.is_empty() {
        out.push_str(&format!("\nDEVICE PROBLEMS\n{line}\n"));
        for device in &report.device_problems {
            let marker = if device
                .problem_code
                .is_some_and(device_inspector::is_hardware_fault)
            {
                "!"
            } else {
                " "
            };
            out.push_str(&format!("  {marker} {} — {}\n", device.name, device.status));
        }
    }

    let corroborated: Vec<&ServiceState> = report
        .service_problems
        .iter()
        .filter(|s| s.corroborated_by_log)
        .collect();
    if !corroborated.is_empty() {
        out.push_str(&format!("\nSERVICE FAILURES\n{line}\n"));
        for service in corroborated {
            out.push_str(&format!(
                "  {} ({}) exit code {}\n",
                service.display_name, service.name, service.exit_code
            ));
        }
    }

    // ---- Third-party drivers ---------------------------------------------
    let third_party: Vec<&DriverInfo> = report.third_party_drivers().collect();
    out.push_str(&format!(
        "\nTHIRD-PARTY KERNEL DRIVERS ({})\n{line}\n",
        third_party.len()
    ));
    if third_party.is_empty() {
        out.push_str("  None. Every loaded kernel module is signed by Microsoft.\n");
    } else {
        for driver in &third_party {
            let flag = if driver.vulnerability.is_some() {
                "!!"
            } else {
                "  "
            };
            out.push_str(&format!(
                "{flag} {:<32} {:<12} {}\n",
                driver.name,
                driver.category.label(),
                driver.company
            ));
            out.push_str(&format!(
                "     v{}  {}\n",
                driver.version,
                driver.signature.label()
            ));
            if let Some(vulnerability) = &driver.vulnerability {
                out.push_str(&format!(
                    "     KNOWN VULNERABLE — matched on {}{}\n",
                    vulnerability.matched_on,
                    if vulnerability.cves.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", vulnerability.cves.join(", "))
                    }
                ));
            }
        }
    }
    out.push_str(&format!(
        "\n  {} Microsoft-signed OS drivers were checked and are not listed.\n",
        report.drivers.len() - third_party.len()
    ));

    // ---- Collection completeness -----------------------------------------
    let incomplete: Vec<&CollectionNote> = report.incomplete_collection().collect();
    if !incomplete.is_empty() {
        out.push_str(&format!("\nWHAT COULD NOT BE COLLECTED\n{line}\n"));
        for note in incomplete {
            out.push_str(&format!(
                "  {}: {}\n",
                note.provider,
                note.status.reason().unwrap_or("unknown reason")
            ));
        }
    }

    out.push_str(&format!(
        "\nScanned {} events, {} drivers, {} crash dump(s).\n",
        report.timeline.len(),
        report.drivers.len(),
        report.crashes.len()
    ));

    out
}

fn tri(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "on",
        Some(false) => "OFF",
        None => "could not be determined",
    }
}

/// Wrap prose to a width, prefixing every line.
fn wrap(text: &str, width: usize, prefix: &str) -> String {
    if text.trim().is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let mut line = String::new();

    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            out.push_str(prefix);
            out.push_str(&line);
            out.push('\n');
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push_str(prefix);
        out.push_str(&line);
        out.push('\n');
    }
    out
}

pub fn render_diff(diff: &ReportDiff) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "\nChanges between {} and {}\n{}\n",
        diff.from.format("%Y-%m-%d %H:%M"),
        diff.to.format("%Y-%m-%d %H:%M"),
        "─".repeat(78)
    ));

    if diff.is_empty() {
        out.push_str("  Nothing changed.\n");
        return out;
    }

    let section = |out: &mut String, title: &str, items: &[String]| {
        if items.is_empty() {
            return;
        }
        out.push_str(&format!("\n  {title}\n"));
        for item in items {
            out.push_str(&format!("    · {item}\n"));
        }
    };

    section(&mut out, "New causes", &diff.causes_new);
    section(&mut out, "Causes no longer present", &diff.causes_resolved);
    section(&mut out, "Drivers added", &diff.drivers_added);
    section(&mut out, "Drivers removed", &diff.drivers_removed);

    if !diff.drivers_changed.is_empty() {
        out.push_str("\n  Driver versions changed\n");
        for change in &diff.drivers_changed {
            out.push_str(&format!(
                "    · {}: {} → {}\n",
                change.name, change.from, change.to
            ));
        }
    }

    section(&mut out, "New device problems", &diff.devices_new_problems);
    section(&mut out, "Device problems resolved", &diff.devices_resolved);

    out.push_str(&format!(
        "\n  Crashes: {} → {}\n",
        diff.crash_count_before, diff.crash_count_after
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::analysis::rules;
    use crate::modules::core::fixtures;
    use crate::modules::core::scoring;

    fn scored(mut report: DiagnosticReport) -> DiagnosticReport {
        let findings: Vec<Finding> = rules::all_rules()
            .iter()
            .flat_map(|rule| rule.evaluate(&report))
            .collect();
        report.suspected_causes = scoring::combine(findings, &report.scan_window);
        report
    }

    #[test]
    fn a_healthy_report_says_so_without_dumping_the_driver_list() {
        let report = scored(fixtures::healthy_machine());
        let text = render_text(&report);
        assert!(text.contains("No instability patterns were found"));
        // Microsoft drivers must never appear in the third-party section — this
        // is the shipped example report's defect.
        assert!(!text.contains("afd.sys"), "OS drivers must not be listed");
        assert!(!text.contains("beep.sys"));
        assert!(text.contains("Microsoft-signed OS drivers were checked"));
    }

    #[test]
    fn the_verdict_comes_before_the_inventory() {
        let report = scored(fixtures::hardware_fault_machine());
        let text = render_text(&report);
        let causes_at = text.find("RANKED CAUSES").expect("causes section");
        let drivers_at = text
            .find("THIRD-PARTY KERNEL DRIVERS")
            .expect("driver section");
        assert!(causes_at < drivers_at, "the analysis must lead");
    }

    #[test]
    fn causes_are_numbered_in_ranked_order_with_their_confidence() {
        let report = scored(fixtures::hardware_fault_machine());
        let text = render_text(&report);
        assert!(
            text.contains("1. [CERTAIN]") || text.contains("1. [HIGH]"),
            "{text}"
        );
        assert!(text.contains("Corroborated by:"));
        assert!(text.contains("What to do:"));
    }

    #[test]
    fn an_unelevated_report_warns_rather_than_claiming_health() {
        let mut report = scored(fixtures::healthy_machine());
        report.elevated = false;
        let text = render_text(&report);
        assert!(text.contains("Not running as Administrator"));
        assert!(
            text.contains("before concluding the machine is healthy"),
            "an unelevated clean result must be qualified"
        );
    }

    #[test]
    fn a_vulnerable_driver_is_called_out_in_the_listing() {
        let report = scored(fixtures::vulnerable_driver_machine());
        let text = render_text(&report);
        assert!(text.contains("RTCore64.sys"));
        assert!(text.contains("KNOWN VULNERABLE"));
        assert!(text.contains("CVE-2019-16098"));
    }

    #[test]
    fn crashes_report_honestly_when_no_culprit_was_established() {
        let report = scored(fixtures::hardware_fault_machine());
        let text = render_text(&report);
        assert!(text.contains("culprit: not established"));
    }

    #[test]
    fn json_round_trips() {
        let report = scored(fixtures::driver_fault_machine());
        let json = export_json(&report);
        let parsed: DiagnosticReport = serde_json::from_str(&json).expect("must round-trip");
        assert_eq!(parsed.suspected_causes.len(), report.suspected_causes.len());
        assert_eq!(parsed.drivers.len(), report.drivers.len());
        assert_eq!(parsed.crashes.len(), report.crashes.len());
    }

    #[test]
    fn utf8_is_written_without_a_byte_order_mark() {
        let dir = std::env::temp_dir();
        let path = dir.join("winsleuth_utf8_probe.json");
        write_utf8(&path, "{\"ok\":true}").unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_ne!(&bytes[..3.min(bytes.len())], b"\xEF\xBB\xBF", "BOM written");
        assert_eq!(String::from_utf8(bytes).unwrap(), "{\"ok\":true}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrapping_preserves_every_word() {
        let text = "The quick brown fox jumps over the lazy dog repeatedly and without pause.";
        let wrapped = wrap(text, 20, "  ");
        for word in text.split_whitespace() {
            assert!(wrapped.contains(word), "lost {word}");
        }
        for line in wrapped.lines() {
            assert!(line.starts_with("  "));
            assert!(line.chars().count() <= 24, "line too long: {line}");
        }
        assert!(wrap("", 20, "  ").is_empty());
    }

    #[test]
    fn diff_rendering_reports_no_change_plainly() {
        let diff = ReportDiff {
            from: chrono::Utc::now(),
            to: chrono::Utc::now(),
            ..Default::default()
        };
        assert!(render_diff(&diff).contains("Nothing changed"));
    }
}
