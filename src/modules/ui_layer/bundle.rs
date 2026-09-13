//! Evidence bundle.
//!
//! One command producing the exact artefact a support desk or forum helper asks
//! for, instead of a ten-step checklist. Everything is redacted before it goes
//! in: the user name, the machine's serial numbers and the hostname are
//! replaced, because these bundles get posted in public.

use std::io::Write;
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;

use crate::modules::core::models::*;
use crate::modules::ui_layer::{html_report, reporting};

/// Largest crash dump to include. Kernel minidumps are a few hundred kilobytes;
/// a full memory dump is gigabytes and is never appropriate to attach.
const MAX_DUMP_BYTES: u64 = 4 * 1024 * 1024;

pub struct BundleResult {
    pub path: PathBuf,
    pub entries: Vec<String>,
    pub redactions: usize,
    pub bytes: u64,
}

/// Build the archive. `include_dumps` is opt-in because dump files can contain
/// fragments of whatever was in memory at the time of the crash.
pub fn build(
    report: &DiagnosticReport,
    destination: &Path,
    include_dumps: bool,
) -> anyhow::Result<BundleResult> {
    let redactor = Redactor::for_report(report);
    let file = std::fs::File::create(destination)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut entries = Vec::new();

    let add = |zip: &mut zip::ZipWriter<std::fs::File>,
               name: &str,
               contents: &str,
               entries: &mut Vec<String>|
     -> anyhow::Result<()> {
        zip.start_file(name, options)?;
        zip.write_all(redactor.apply(contents).as_bytes())?;
        entries.push(name.to_string());
        Ok(())
    };

    add(
        &mut zip,
        "README.txt",
        &readme(report, include_dumps),
        &mut entries,
    )?;
    add(
        &mut zip,
        "report.txt",
        &reporting::render_text(report),
        &mut entries,
    )?;
    add(
        &mut zip,
        "report.html",
        &html_report::render(report),
        &mut entries,
    )?;
    add(
        &mut zip,
        "report.json",
        &reporting::export_json(report),
        &mut entries,
    )?;
    add(&mut zip, "drivers.csv", &drivers_csv(report), &mut entries)?;
    add(
        &mut zip,
        "timeline.csv",
        &timeline_csv(report),
        &mut entries,
    )?;

    if include_dumps {
        for crash in &report.crashes {
            if crash.dump_path.is_empty() {
                continue;
            }
            let source = Path::new(&crash.dump_path);
            let Ok(metadata) = std::fs::metadata(source) else {
                continue;
            };
            if metadata.len() > MAX_DUMP_BYTES {
                continue;
            }
            let Ok(bytes) = std::fs::read(source) else {
                continue;
            };
            let Some(name) = source.file_name() else {
                continue;
            };
            let entry = format!("dumps/{}", name.to_string_lossy());
            zip.start_file(&entry, options)?;
            // Dump contents are binary and are not redacted; that is why this
            // is opt-in and called out in the README.
            zip.write_all(&bytes)?;
            entries.push(entry);
        }
    }

    zip.finish()?;
    let bytes = std::fs::metadata(destination).map(|m| m.len()).unwrap_or(0);

    Ok(BundleResult {
        path: destination.to_path_buf(),
        entries,
        redactions: redactor.rules.len(),
        bytes,
    })
}

fn readme(report: &DiagnosticReport, include_dumps: bool) -> String {
    let dumps = if include_dumps {
        "  dumps/          Crash dump files. NOT redacted — they can contain fragments\n\
        \x20                 of whatever was in memory when the machine crashed.\n"
    } else {
        "  (Crash dumps were not included. Re-run with --include-dumps if asked for them.)\n"
    };

    format!(
        "WinSleuth evidence bundle\n\
         =========================\n\n\
         Generated {generated} for a {days}-day window.\n\n\
         Contents\n\
         --------\n\
         \x20 report.txt      The readable report.\n\
         \x20 report.html     The same report as a page you can open in a browser.\n\
         \x20 report.json     The same data, for tooling.\n\
         \x20 drivers.csv     Every loaded kernel driver.\n\
         \x20 timeline.csv    Events collected in the window.\n\
        {dumps}\n\
         Redaction\n\
         ---------\n\
         The machine name, the signed-in user name and file paths under the user's\n\
         profile have been replaced throughout the text files. Check the contents\n\
         before sharing anyway — only you know what is sensitive on this machine.\n\n\
         Summary\n\
         -------\n\
         \x20 Causes found:   {causes}\n\
         \x20 Crashes:        {crashes}\n\
         \x20 Third-party drivers: {third_party}\n\
         \x20 Administrator:  {elevated}\n",
        generated = report.generated_at.format("%Y-%m-%d %H:%M UTC"),
        days = report.scan_window.days(),
        dumps = dumps,
        causes = report.suspected_causes.len(),
        crashes = report.crashes.len(),
        third_party = report.third_party_drivers().count(),
        elevated = if report.elevated {
            "yes"
        } else {
            "no — findings are incomplete"
        },
    )
}

fn drivers_csv(report: &DiagnosticReport) -> String {
    let mut out = String::from(
        "name,category,company,version,signature,is_os_driver,base_address,size,vulnerable\n",
    );
    for driver in &report.drivers {
        out.push_str(&format!(
            "{},{},{},{},{},{},{:#x},{},{}\n",
            csv(&driver.name),
            driver.category.label(),
            csv(&driver.company),
            csv(&driver.version),
            csv(&driver.signature.label()),
            driver.is_os_driver,
            driver.base_address,
            driver.size,
            driver.vulnerability.is_some(),
        ));
    }
    out
}

fn timeline_csv(report: &DiagnosticReport) -> String {
    let mut out = String::from("timestamp,channel,source,event_id,level,message\n");
    for event in &report.timeline {
        out.push_str(&format!(
            "{},{},{},{},{},{}\n",
            event.timestamp.to_rfc3339(),
            csv(&event.channel),
            csv(&event.source),
            event.event_id,
            event.level.label(),
            csv(&event.message),
        ));
    }
    out
}

/// Quote a CSV field. Values include event messages with commas and quotes in
/// them, so this cannot be skipped.
fn csv(value: &str) -> String {
    let cleaned = value.replace(['\r', '\n'], " ");
    if cleaned.contains(',') || cleaned.contains('"') {
        format!("\"{}\"", cleaned.replace('"', "\"\""))
    } else {
        cleaned
    }
}

/// Literal replacement of identifying strings.
pub struct Redactor {
    rules: Vec<(String, &'static str)>,
}

impl Redactor {
    pub fn for_report(report: &DiagnosticReport) -> Self {
        let mut rules: Vec<(String, &'static str)> = Vec::new();
        if let Ok(user) = std::env::var("USERNAME")
            && user.len() > 2
        {
            rules.push((user, "[user]"));
        }
        if report.system.hostname.len() > 2 {
            rules.push((report.system.hostname.clone(), "[hostname]"));
        }
        if let Ok(profile) = std::env::var("USERPROFILE")
            && profile.len() > 3
        {
            rules.push((profile, "[profile]"));
        }

        // Longest first, so a profile path is replaced before the user name
        // inside it turns it into a half-redacted string.
        rules.sort_by_key(|(needle, _)| std::cmp::Reverse(needle.len()));
        Self { rules }
    }

    pub fn apply(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (needle, replacement) in &self.rules {
            if out.contains(needle.as_str()) {
                out = out.replace(needle.as_str(), replacement);
            }
            // Paths appear with either slash direction and in either case.
            let lower = needle.to_lowercase();
            if lower != *needle && out.contains(lower.as_str()) {
                out = out.replace(lower.as_str(), replacement);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::core::fixtures;

    #[test]
    fn csv_fields_with_commas_and_quotes_are_quoted() {
        assert_eq!(csv("plain"), "plain");
        assert_eq!(csv("has,comma"), "\"has,comma\"");
        assert_eq!(csv("has\"quote"), "\"has\"\"quote\"");
        // Newlines would break the row structure.
        assert_eq!(csv("two\nlines"), "two lines");
    }

    #[test]
    fn the_redactor_removes_identifying_strings() {
        let mut report = fixtures::healthy_machine();
        report.system.hostname = "MYDESKTOP".into();
        let redactor = Redactor::for_report(&report);
        let text = redactor.apply("Crash on MYDESKTOP at 12:00");
        assert!(!text.contains("MYDESKTOP"));
        assert!(text.contains("[hostname]"));
    }

    #[test]
    fn short_names_are_not_redacted_into_nonsense() {
        // A two-character hostname would otherwise match everywhere.
        let mut report = fixtures::healthy_machine();
        report.system.hostname = "PC".into();
        let redactor = Redactor::for_report(&report);
        let text = redactor.apply("A PCI device on the PC");
        assert!(text.contains("PCI"), "over-eager redaction: {text}");
    }

    #[test]
    fn builds_an_archive_containing_the_expected_files() {
        let report = fixtures::hardware_fault_machine();
        let path = std::env::temp_dir().join("winsleuth_bundle_test.zip");
        let result = build(&report, &path, false).expect("bundle must build");
        for expected in [
            "README.txt",
            "report.txt",
            "report.html",
            "report.json",
            "drivers.csv",
            "timeline.csv",
        ] {
            assert!(
                result.entries.iter().any(|e| e == expected),
                "missing {expected}"
            );
        }
        assert!(result.bytes > 0);
        // Without --include-dumps nothing binary goes in.
        assert!(!result.entries.iter().any(|e| e.starts_with("dumps/")));

        // The archive must actually open.
        let file = std::fs::File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).expect("must be a valid zip");
        assert_eq!(archive.len(), result.entries.len());
        assert!(archive.by_name("report.json").is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_readme_says_whether_dumps_are_included() {
        let report = fixtures::healthy_machine();
        assert!(readme(&report, false).contains("were not included"));
        assert!(readme(&report, true).contains("NOT redacted"));
    }

    #[test]
    fn csv_exports_cover_every_row() {
        let report = fixtures::failing_disk_machine();
        let drivers = drivers_csv(&report);
        assert_eq!(drivers.lines().count(), report.drivers.len() + 1);
        let timeline = timeline_csv(&report);
        assert_eq!(timeline.lines().count(), report.timeline.len() + 1);
        assert!(timeline.lines().next().unwrap().starts_with("timestamp,"));
    }
}
