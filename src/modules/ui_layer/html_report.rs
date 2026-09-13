//! Self-contained HTML report.
//!
//! One file, no external requests, safe to email or attach to a forum post.
//! Everything the text report says, plus a crash timeline that is legible at a
//! glance.

use crate::modules::core::models::*;
use crate::modules::providers::device_inspector;

/// Escape text for HTML. Report content includes driver paths, event messages
/// and vendor strings, none of which can be trusted to be markup-safe.
fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(character),
        }
    }
    out
}

fn confidence_class(level: ConfidenceLevel) -> &'static str {
    match level {
        ConfidenceLevel::Certain => "certain",
        ConfidenceLevel::High => "high",
        ConfidenceLevel::Moderate => "moderate",
        ConfidenceLevel::Low => "low",
    }
}

pub fn render(report: &DiagnosticReport) -> String {
    let mut body = String::new();

    body.push_str(&header(report));
    body.push_str(&causes(report));
    body.push_str(&regression(report));
    body.push_str(&crashes(report));
    body.push_str(&protections(report));
    body.push_str(&devices_and_services(report));
    body.push_str(&drivers(report));
    body.push_str(&gaps(report));

    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>WinSleuth — {host}</title>\n<style>{css}</style>\n</head>\n<body>\n\
         <main>{body}</main>\n</body>\n</html>\n",
        host = esc(&report.system.hostname),
        css = CSS,
        body = body
    )
}

fn header(report: &DiagnosticReport) -> String {
    let warning = if report.elevated {
        String::new()
    } else {
        "<p class=\"warn\">This scan ran without Administrator rights. Crash dumps, service \
         state and kernel module addresses were unavailable, so these findings are \
         incomplete.</p>"
            .to_string()
    };

    format!(
        "<header>\n<p class=\"eyebrow\">WinSleuth report</p>\n<h1>{host}</h1>\n\
         <dl class=\"facts\">\
         <div><dt>System</dt><dd>{os} <span class=\"dim\">{build}</span></dd></div>\
         <div><dt>Board</dt><dd>{vendor} {model}</dd></div>\
         <div><dt>Processor</dt><dd>{cpu}</dd></div>\
         <div><dt>Memory</dt><dd>{mem:.0} GB</dd></div>\
         <div><dt>Firmware</dt><dd>{fw_vendor} {fw_version} <span class=\"dim\">{fw_date}</span></dd></div>\
         <div><dt>Window</dt><dd>{since} → {until} <span class=\"dim\">({days} days)</span></dd></div>\
         </dl>\n{warning}\n</header>\n",
        host = esc(&report.system.hostname),
        os = esc(&report.system.os_caption),
        build = esc(&report.system.os_build),
        vendor = esc(&report.system.motherboard_vendor),
        model = esc(&report.system.motherboard_model),
        cpu = esc(&report.system.cpu_model),
        mem = report.system.physical_memory_gb,
        fw_vendor = esc(&report.firmware.vendor),
        fw_version = esc(&report.firmware.version),
        fw_date = esc(&report.firmware.date),
        since = report.scan_window.since.format("%Y-%m-%d %H:%M"),
        until = report.scan_window.until.format("%Y-%m-%d %H:%M"),
        days = report.scan_window.days(),
        warning = warning,
    )
}

fn causes(report: &DiagnosticReport) -> String {
    if report.suspected_causes.is_empty() {
        let qualifier = if report.elevated {
            ""
        } else {
            " An unelevated scan can miss the evidence entirely — re-run as Administrator \
             before concluding the machine is healthy."
        };
        return format!(
            "<section><h2>Ranked causes</h2><p class=\"empty\">No instability patterns were \
             found in this window.{qualifier}</p></section>"
        );
    }

    let mut out = String::from("<section><h2>Ranked causes</h2>");

    for (index, cause) in report.suspected_causes.iter().enumerate() {
        out.push_str(&format!(
            "<article class=\"cause {class}\">\
             <div class=\"cause-head\">\
             <span class=\"rank\">{rank}</span>\
             <h3>{title}</h3>\
             <span class=\"badge\">{confidence}</span>\
             <span class=\"score\">{score:.0}</span>\
             </div>\
             <p>{explanation}</p>",
            class = confidence_class(cause.confidence),
            rank = index + 1,
            title = esc(&cause.title),
            confidence = cause.confidence.label(),
            score = cause.score,
            explanation = esc(&cause.explanation),
        ));
        if !cause.evidence.is_empty() {
            out.push_str("<details open><summary>Evidence</summary><ul class=\"evidence\">");
            for item in &cause.evidence {
                let when = item
                    .timestamp
                    .map(|t| format!("<time>{}</time> ", t.format("%Y-%m-%d %H:%M")))
                    .unwrap_or_default();
                out.push_str(&format!("<li>{when}{}</li>", esc(&item.detail)));
            }
            out.push_str("</ul></details>");
        }

        out.push_str(&format!(
            "<div class=\"action\"><h4>What to do</h4><p>{}</p>",
            esc(&cause.recommendation)
        ));
        if !cause.commands.is_empty() {
            out.push_str("<ul class=\"commands\">");
            for command in &cause.commands {
                out.push_str(&format!(
                    "<li><code>{}</code><span class=\"dim\">{}</span></li>",
                    esc(&command.command),
                    esc(&command.label)
                ));
            }
            out.push_str("</ul>");
        }
        out.push_str("</div>");
        out.push_str(&format!(
            "<p class=\"rules\">Corroborated by {}</p></article>",
            esc(&cause.contributing_rules.join(", "))
        ));
    }

    out.push_str("</section>");
    out
}

fn regression(report: &DiagnosticReport) -> String {
    let Some(analysis) = &report.changepoint else {
        return String::new();
    };

    let mut out = format!(
        "<section><h2>When it changed</h2><p class=\"lede\">{}</p>",
        esc(&analysis.summary)
    );

    if !analysis.suspect_changes.is_empty() {
        out.push_str(
            "<table><thead><tr><th>Date</th><th>Change</th><th>Type</th></tr></thead><tbody>",
        );
        for change in &analysis.suspect_changes {
            out.push_str(&format!(
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td></tr>",
                change.date.format("%Y-%m-%d"),
                esc(&change.name),
                change.change_type.label()
            ));
        }
        out.push_str("</tbody></table>");
    }

    out.push_str("</section>");
    out
}

fn crashes(report: &DiagnosticReport) -> String {
    let mut out = String::new();
    out.push_str(&system_crashes(report));
    out.push_str(&application_crashes(report));
    out
}

/// User-mode program crashes. Kept apart from system crashes because a
/// `0xC0000409` exception code is not a stop code, and presenting the two in
/// one table told the reader the machine had blue-screened when it had not.
fn application_crashes(report: &DiagnosticReport) -> String {
    let applications: Vec<&CrashRecord> = report.application_crashes().collect();
    if applications.is_empty() {
        return String::new();
    }

    let mut out = String::from(
        "<section><h2>Application crashes</h2>\
         <p class=\"dim\">User-mode program crashes, not system faults.</p>\
         <div class=\"scroll\"><table>\
         <thead><tr><th>When</th><th>Program</th><th>Exception</th></tr></thead><tbody>",
    );

    for crash in applications {
        out.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">0x{:08X} {}</td></tr>",
            crash.timestamp.format("%Y-%m-%d %H:%M"),
            esc(crash.faulting_module.as_deref().unwrap_or("unknown")),
            crash.bugcheck_code,
            esc(&crash.bugcheck_name),
        ));
    }

    out.push_str("</tbody></table></div></section>");
    out
}

fn system_crashes(report: &DiagnosticReport) -> String {
    let system: Vec<&CrashRecord> = report.system_crashes().collect();
    if system.is_empty() {
        return String::new();
    }

    let mut out = String::from(
        "<section><h2>System crashes</h2><div class=\"scroll\"><table>\
         <thead><tr><th>When</th><th>Stop code</th><th>Culprit</th><th>Basis</th></tr></thead><tbody>",
    );

    for crash in system {
        let culprit = crash
            .attribution
            .module()
            .map(esc)
            .unwrap_or_else(|| "<span class=\"dim\">not established</span>".to_string());
        out.push_str(&format!(
            "<tr><td class=\"mono\">{when}</td>\
             <td class=\"mono\">0x{code:08X} {name}</td>\
             <td>{culprit}</td><td class=\"dim\">{basis}</td></tr>",
            when = crash.timestamp.format("%Y-%m-%d %H:%M"),
            code = crash.bugcheck_code,
            name = esc(&crash.bugcheck_name),
            culprit = culprit,
            basis = esc(crash.attribution.describe()),
        ));
    }

    out.push_str("</tbody></table></div></section>");
    out
}

fn protections(report: &DiagnosticReport) -> String {
    if !report.security.is_known() {
        return String::new();
    }

    let row = |label: &str, value: Option<bool>| {
        let (text, class) = match value {
            Some(true) => ("On", "ok"),
            Some(false) => ("Off", "bad"),
            None => ("Unknown", "dim"),
        };
        format!("<div><dt>{label}</dt><dd class=\"{class}\">{text}</dd></div>")
    };

    format!(
        "<section><h2>Kernel protections</h2><dl class=\"facts\">{}{}{}{}</dl></section>",
        row("Memory Integrity (HVCI)", report.security.hvci_enabled),
        row(
            "Vulnerable driver blocklist",
            report.security.driver_blocklist_enabled
        ),
        row("Secure Boot", report.security.secure_boot),
        row("Virtualisation-based security", report.security.vbs_enabled),
    )
}

fn devices_and_services(report: &DiagnosticReport) -> String {
    let mut out = String::new();

    if !report.device_problems.is_empty() {
        out.push_str(
            "<section><h2>Device problems</h2><div class=\"scroll\"><table><thead><tr>\
                      <th>Device</th><th>Problem</th><th>Instance</th></tr></thead><tbody>",
        );
        for device in &report.device_problems {
            let fault = device
                .problem_code
                .is_some_and(device_inspector::is_hardware_fault);
            out.push_str(&format!(
                "<tr class=\"{}\"><td>{}</td><td>{}</td><td class=\"mono dim\">{}</td></tr>",
                if fault { "bad" } else { "" },
                esc(&device.name),
                esc(&device.status),
                esc(&device.device_id),
            ));
        }
        out.push_str("</tbody></table></div></section>");
    }

    let failures: Vec<&ServiceState> = report
        .service_problems
        .iter()
        .filter(|s| s.corroborated_by_log)
        .collect();
    if !failures.is_empty() {
        out.push_str("<section><h2>Service failures</h2><ul>");
        for service in failures {
            out.push_str(&format!(
                "<li>{} <span class=\"dim\">({})</span> — exit code {}</li>",
                esc(&service.display_name),
                esc(&service.name),
                service.exit_code
            ));
        }
        out.push_str("</ul></section>");
    }

    out
}

fn drivers(report: &DiagnosticReport) -> String {
    let third_party: Vec<&DriverInfo> = report.third_party_drivers().collect();
    let os_count = report.drivers.len() - third_party.len();

    let mut out = format!(
        "<section><h2>Third-party kernel drivers <span class=\"count\">{}</span></h2>",
        third_party.len()
    );

    if third_party.is_empty() {
        out.push_str("<p class=\"empty\">Every loaded kernel module is signed by Microsoft.</p>");
    } else {
        out.push_str(
            "<div class=\"scroll\"><table><thead><tr><th>Driver</th><th>Category</th>\
             <th>Publisher</th><th>Version</th><th>Signature</th></tr></thead><tbody>",
        );
        for driver in &third_party {
            let flagged = driver.vulnerability.is_some();
            out.push_str(&format!(
                "<tr class=\"{}\"><td class=\"mono\">{}</td><td>{}</td><td>{}</td>\
                 <td class=\"mono\">{}</td><td class=\"dim\">{}</td></tr>",
                if flagged { "bad" } else { "" },
                esc(&driver.name),
                driver.category.label(),
                esc(&driver.company),
                esc(&driver.version),
                esc(&driver.signature.label()),
            ));
            if let Some(vulnerability) = &driver.vulnerability {
                out.push_str(&format!(
                    "<tr class=\"detail\"><td colspan=\"5\"><strong>Known vulnerable</strong> \
                     — matched on {}{}. {}</td></tr>",
                    esc(&vulnerability.matched_on),
                    if vulnerability.cves.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", esc(&vulnerability.cves.join(", ")))
                    },
                    esc(&vulnerability.description),
                ));
            }
        }
        out.push_str("</tbody></table></div>");
    }

    out.push_str(&format!(
        "<p class=\"dim\">{os_count} Microsoft-signed operating system drivers were checked \
         and are not listed.</p></section>"
    ));
    out
}

fn gaps(report: &DiagnosticReport) -> String {
    let incomplete: Vec<&CollectionNote> = report.incomplete_collection().collect();

    let mut out = String::from("<section><h2>Scan coverage</h2>");
    if incomplete.is_empty() {
        out.push_str("<p class=\"empty\">Everything was collected successfully.</p>");
    } else {
        out.push_str("<ul>");
        for note in incomplete {
            out.push_str(&format!(
                "<li><strong>{}</strong> — {}</li>",
                esc(&note.provider),
                esc(note.status.reason().unwrap_or("unknown reason"))
            ));
        }
        out.push_str("</ul>");
    }

    out.push_str(&format!(
        "<p class=\"dim\">{} events, {} drivers, {} crash dump(s) examined. \
         Generated {}.</p></section>",
        report.timeline.len(),
        report.drivers.len(),
        report.crashes.len(),
        report.generated_at.format("%Y-%m-%d %H:%M UTC"),
    ));
    out
}

const CSS: &str = r#"
:root {
  --ground: #f6f7f9; --surface: #fff; --sunk: #eef1f5;
  --ink: #151a22; --muted: #5b6675; --faint: #8b95a3;
  --rule: #dce2e9; --accent: #1b4f9c;
  --certain: #a32118; --high: #96590f; --moderate: #3f6485; --low: #6b7280;
  --ok: #1c6a4e; --bad: #a32118;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ground: #0e1218; --surface: #151b23; --sunk: #1a212b;
    --ink: #e3e8ef; --muted: #97a3b2; --faint: #6e7b8b;
    --rule: #26303c; --accent: #74aaf2;
    --certain: #f08c80; --high: #e0a85f; --moderate: #92b6d8; --low: #8b95a3;
    --ok: #63c098; --bad: #f08c80;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--ground); color: var(--ink);
  font: 15px/1.6 "Segoe UI", system-ui, -apple-system, sans-serif;
}
main { max-width: 60rem; margin: 0 auto; padding: 2rem 1.25rem 5rem; }
header { border-bottom: 2px solid var(--ink); padding-bottom: 1.5rem; }
.eyebrow {
  margin: 0; font-size: .7rem; letter-spacing: .16em; text-transform: uppercase;
  color: var(--muted);
}
h1 { margin: .25rem 0 1rem; font-size: clamp(1.9rem, 5vw, 2.8rem); letter-spacing: -.02em; }
h2 {
  font-size: 1.3rem; letter-spacing: -.015em; margin: 0 0 1rem;
  padding-bottom: .4rem; border-bottom: 1px solid var(--rule);
}
h3 { margin: 0; font-size: 1.05rem; letter-spacing: -.01em; }
h4 { margin: 0 0 .3rem; font-size: .72rem; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); }
section { margin-top: 2.75rem; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: .5rem 1.5rem; margin: 0; }
.facts div { display: flex; gap: .5rem; align-items: baseline; }
.facts dt { font-size: .72rem; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); min-width: 8.5rem; }
.facts dd { margin: 0; }
.dim { color: var(--muted); }
.ok { color: var(--ok); font-weight: 600; }
.bad > td:first-child, .bad { color: var(--bad); }
.warn {
  margin: 1.25rem 0 0; padding: .8rem 1rem; border-left: 3px solid var(--high);
  background: var(--sunk); border-radius: 2px;
}
.empty { color: var(--muted); }
.lede { font-size: 1.05rem; }
.count { font-size: .8rem; color: var(--muted); font-weight: 400; }
.cause {
  background: var(--surface); border: 1px solid var(--rule); border-left: 3px solid var(--low);
  border-radius: 3px; padding: 1.1rem 1.25rem; margin-bottom: 1rem;
}
.cause.certain { border-left-color: var(--certain); }
.cause.high { border-left-color: var(--high); }
.cause.moderate { border-left-color: var(--moderate); }
.cause-head { display: flex; align-items: baseline; gap: .7rem; flex-wrap: wrap; margin-bottom: .5rem; }
.rank { font-variant-numeric: tabular-nums; color: var(--faint); font-weight: 600; }
.cause-head h3 { flex: 1; min-width: 14rem; }
.badge {
  font-size: .64rem; letter-spacing: .11em; text-transform: uppercase; font-weight: 700;
  padding: .15rem .45rem; border-radius: 2px; background: var(--sunk);
}
.certain .badge { color: var(--certain); }
.high .badge { color: var(--high); }
.moderate .badge { color: var(--moderate); }
.low .badge { color: var(--low); }
.score { font-variant-numeric: tabular-nums; font-weight: 600; color: var(--muted); }
.cause p { margin: 0 0 .7rem; }
details { margin: .6rem 0; }
summary { cursor: pointer; font-size: .8rem; color: var(--accent); }
.evidence { margin: .5rem 0 0; padding-left: 1.1rem; font-size: .92rem; }
.evidence li { margin-bottom: .2rem; }
time { font-family: ui-monospace, Consolas, monospace; font-size: .82rem; color: var(--faint); }
.action { background: var(--sunk); border-radius: 2px; padding: .75rem .9rem; margin-top: .8rem; }
.commands { list-style: none; margin: .5rem 0 0; padding: 0; }
.commands li { display: flex; flex-direction: column; gap: .1rem; margin-bottom: .5rem; }
code {
  font-family: ui-monospace, Consolas, monospace; font-size: .85rem;
  background: var(--surface); padding: .25rem .45rem; border-radius: 2px;
  border: 1px solid var(--rule); overflow-wrap: anywhere;
}
.commands .dim { font-size: .78rem; }
.rules { font-size: .76rem; color: var(--faint); margin: .7rem 0 0; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { text-align: left; padding: .45rem .7rem; border-bottom: 1px solid var(--rule); vertical-align: top; }
thead th {
  font-size: .68rem; letter-spacing: .1em; text-transform: uppercase;
  color: var(--muted); background: var(--sunk);
}
tr.detail td { font-size: .85rem; color: var(--muted); background: var(--sunk); }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: .84rem; }
ul { padding-left: 1.2rem; }
"#;

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
    fn produces_a_self_contained_document() {
        let html = render(&scored(fixtures::hardware_fault_machine()));
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("</html>"));
        // No external requests: the page must work from an email attachment.
        assert!(!html.contains("http://"), "external reference in report");
        assert!(!html.contains("https://"), "external reference in report");
        assert!(!html.contains("<script"), "no scripting is needed");
        assert!(html.contains("<style>"));
    }

    #[test]
    fn content_is_escaped() {
        let mut report = fixtures::healthy_machine();
        report.system.hostname = "<script>alert(1)</script>".into();
        report.drivers.push({
            let mut d = fixtures::vendor_driver(
                "evil\".sys",
                "<img src=x onerror=alert(1)>",
                DriverCategory::Other,
                0,
                0,
            );
            d.signature = SignatureStatus::Unsigned;
            d
        });
        let html = render(&scored(report));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn ranked_causes_appear_before_the_driver_inventory() {
        let html = render(&scored(fixtures::driver_fault_machine()));
        let causes = html.find("Ranked causes").expect("causes heading");
        let drivers = html
            .find("Third-party kernel drivers")
            .expect("drivers heading");
        assert!(causes < drivers);
    }

    #[test]
    fn a_healthy_machine_renders_an_explicit_all_clear() {
        let html = render(&scored(fixtures::healthy_machine()));
        assert!(html.contains("No instability patterns were found"));
        // The OS drivers that the shipped example report wrongly listed as
        // unsigned third-party components must not appear in the table.
        assert!(!html.contains("afd.sys"), "OS drivers must not be listed");
        assert!(!html.contains("beep.sys"));
        assert!(html.contains("Microsoft-signed operating system drivers were checked"));
    }

    #[test]
    fn a_machine_with_no_third_party_drivers_says_so() {
        let mut report = fixtures::healthy_machine();
        report.drivers.retain(|d| d.is_os_driver);
        let html = render(&scored(report));
        assert!(html.contains("Every loaded kernel module is signed by Microsoft"));
    }

    #[test]
    fn an_unelevated_scan_is_visibly_qualified() {
        let mut report = scored(fixtures::healthy_machine());
        report.elevated = false;
        let html = render(&report);
        assert!(html.contains("without Administrator rights"));
        assert!(html.contains("re-run as Administrator"));
    }

    #[test]
    fn vulnerable_drivers_are_marked_in_the_table() {
        let html = render(&scored(fixtures::vulnerable_driver_machine()));
        assert!(html.contains("RTCore64.sys"));
        assert!(html.contains("Known vulnerable"));
        assert!(html.contains("CVE-2019-16098"));
    }

    #[test]
    fn both_themes_define_every_colour_token() {
        // A token defined only inside the dark block renders unreadable in the
        // default light view, and vice versa.
        let light_block = CSS.split("@media").next().unwrap();
        let dark_block = CSS
            .split("@media (prefers-color-scheme: dark)")
            .nth(1)
            .unwrap();
        for token in [
            "--ground",
            "--surface",
            "--sunk",
            "--ink",
            "--muted",
            "--faint",
            "--rule",
            "--accent",
            "--certain",
            "--high",
            "--moderate",
            "--low",
            "--ok",
            "--bad",
        ] {
            assert!(
                light_block.contains(token),
                "{token} missing from the light palette"
            );
            assert!(
                dark_block.contains(token),
                "{token} missing from the dark palette"
            );
        }
    }
}
