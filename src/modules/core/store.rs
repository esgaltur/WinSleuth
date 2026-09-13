//! Local history of scans, and the diff between two of them.
//!
//! Snapshots live under `%LOCALAPPDATA%\WinSleuth\snapshots` as one JSON file
//! per scan. Nothing leaves the machine.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::modules::core::models::*;

pub fn data_dir() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("WinSleuth")
}

pub fn snapshot_dir() -> PathBuf {
    data_dir().join("snapshots")
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub path: PathBuf,
    pub taken_at: DateTime<Utc>,
}

/// Write a scan to the history. Returns the file it was written to.
pub fn save(report: &DiagnosticReport) -> anyhow::Result<PathBuf> {
    let dir = snapshot_dir();
    std::fs::create_dir_all(&dir)?;

    let path = dir.join(format!(
        "scan-{}.json",
        report.generated_at.format("%Y%m%dT%H%M%SZ")
    ));
    std::fs::write(&path, serde_json::to_string(report)?)?;
    Ok(path)
}

/// Every stored snapshot, newest first.
pub fn list() -> Vec<Snapshot> {
    let Ok(entries) = std::fs::read_dir(snapshot_dir()) else {
        return Vec::new();
    };

    let mut snapshots: Vec<Snapshot> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .filter_map(|path| {
            let taken_at = parse_snapshot_time(&path)?;
            Some(Snapshot { path, taken_at })
        })
        .collect();

    snapshots.sort_by_key(|s| std::cmp::Reverse(s.taken_at));
    snapshots
}

fn parse_snapshot_time(path: &Path) -> Option<DateTime<Utc>> {
    let stem = path.file_stem()?.to_string_lossy();
    let raw = stem.strip_prefix("scan-")?;
    DateTime::parse_from_str(&format!("{raw}+0000"), "%Y%m%dT%H%M%SZ%z")
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

pub fn load(path: &Path) -> anyhow::Result<DiagnosticReport> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

/// Load the newest snapshot taken strictly before `before`, if any.
pub fn previous(before: DateTime<Utc>) -> Option<(Snapshot, DiagnosticReport)> {
    list()
        .into_iter()
        .find(|s| s.taken_at < before)
        .and_then(|s| load(&s.path).ok().map(|r| (s, r)))
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReportDiff {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub drivers_added: Vec<String>,
    pub drivers_removed: Vec<String>,
    pub drivers_changed: Vec<DriverVersionChange>,
    pub devices_new_problems: Vec<String>,
    pub devices_resolved: Vec<String>,
    pub causes_new: Vec<String>,
    pub causes_resolved: Vec<String>,
    pub crash_count_before: usize,
    pub crash_count_after: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverVersionChange {
    pub name: String,
    pub from: String,
    pub to: String,
}

impl ReportDiff {
    pub fn is_empty(&self) -> bool {
        self.drivers_added.is_empty()
            && self.drivers_removed.is_empty()
            && self.drivers_changed.is_empty()
            && self.devices_new_problems.is_empty()
            && self.devices_resolved.is_empty()
            && self.causes_new.is_empty()
            && self.causes_resolved.is_empty()
    }
}

/// Compare two scans. `before` is expected to be the older of the two.
pub fn diff(before: &DiagnosticReport, after: &DiagnosticReport) -> ReportDiff {
    let mut result = ReportDiff {
        from: before.generated_at,
        to: after.generated_at,
        crash_count_before: before.crashes.len(),
        crash_count_after: after.crashes.len(),
        ..Default::default()
    };

    let key = |d: &DriverInfo| d.name.to_lowercase();

    for driver in &after.drivers {
        match before.drivers.iter().find(|d| key(d) == key(driver)) {
            None => result.drivers_added.push(driver.name.clone()),
            Some(old) if old.version != driver.version => {
                result.drivers_changed.push(DriverVersionChange {
                    name: driver.name.clone(),
                    from: old.version.clone(),
                    to: driver.version.clone(),
                });
            }
            Some(_) => {}
        }
    }

    for driver in &before.drivers {
        if !after.drivers.iter().any(|d| key(d) == key(driver)) {
            result.drivers_removed.push(driver.name.clone());
        }
    }

    for device in &after.device_problems {
        if !before
            .device_problems
            .iter()
            .any(|d| d.device_id == device.device_id)
        {
            result
                .devices_new_problems
                .push(format!("{} ({})", device.name, device.problem_name));
        }
    }
    for device in &before.device_problems {
        if !after
            .device_problems
            .iter()
            .any(|d| d.device_id == device.device_id)
        {
            result.devices_resolved.push(device.name.clone());
        }
    }

    for cause in &after.suspected_causes {
        if !before.suspected_causes.iter().any(|c| c.id == cause.id) {
            result.causes_new.push(cause.title.clone());
        }
    }
    for cause in &before.suspected_causes {
        if !after.suspected_causes.iter().any(|c| c.id == cause.id) {
            result.causes_resolved.push(cause.title.clone());
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn driver(name: &str, version: &str) -> DriverInfo {
        DriverInfo {
            name: name.into(),
            path: format!("C:\\Windows\\System32\\drivers\\{name}"),
            version: version.into(),
            publisher: String::new(),
            description: String::new(),
            company: String::new(),
            hash: None,
            base_address: 0,
            size: 0,
            signature: SignatureStatus::Catalog {
                signer: "Microsoft Windows".into(),
            },
            is_os_driver: true,
            category: DriverCategory::Other,
            vulnerability: None,
        }
    }

    #[test]
    fn diff_reports_driver_movement_in_both_directions() {
        let window = ScanWindow::last_days(7);
        let mut before = DiagnosticReport::empty(window);
        let mut after = DiagnosticReport::empty(window);
        before.drivers = vec![driver("a.sys", "1.0"), driver("gone.sys", "2.0")];
        after.drivers = vec![driver("a.sys", "1.1"), driver("new.sys", "3.0")];
        let d = diff(&before, &after);
        assert_eq!(d.drivers_added, vec!["new.sys"]);
        assert_eq!(d.drivers_removed, vec!["gone.sys"]);
        assert_eq!(d.drivers_changed.len(), 1);
        assert_eq!(d.drivers_changed[0].from, "1.0");
        assert_eq!(d.drivers_changed[0].to, "1.1");
        assert!(!d.is_empty());
    }

    #[test]
    fn an_unchanged_system_diffs_to_nothing() {
        let window = ScanWindow::last_days(7);
        let mut before = DiagnosticReport::empty(window);
        before.drivers = vec![driver("a.sys", "1.0")];
        let after = before.clone();
        assert!(diff(&before, &after).is_empty());
    }

    #[test]
    fn diff_tracks_causes_appearing_and_clearing() {
        let window = ScanWindow::last_days(7);
        let mut before = DiagnosticReport::empty(window);
        let mut after = DiagnosticReport::empty(window);
        let cause = |id: &str, title: &str| SuspectedCause {
            id: id.into(),
            title: title.into(),
            score: 80.0,
            confidence: ConfidenceLevel::High,
            evidence: Vec::new(),
            explanation: String::new(),
            recommendation: String::new(),
            commands: Vec::new(),
            contributing_rules: Vec::new(),
        };
        before.suspected_causes = vec![cause("storage-failure", "Disk errors")];
        after.suspected_causes = vec![cause("hardware-error", "WHEA errors")];
        let d = diff(&before, &after);
        assert_eq!(d.causes_new, vec!["WHEA errors"]);
        assert_eq!(d.causes_resolved, vec!["Disk errors"]);
    }

    #[test]
    fn snapshot_names_round_trip_through_their_timestamp() {
        let path = PathBuf::from("scan-20260814T221105Z.json");
        let parsed = parse_snapshot_time(&path).expect("must parse");
        assert_eq!(
            parsed.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-08-14 22:11:05"
        );
        assert!(parse_snapshot_time(&PathBuf::from("not-a-snapshot.json")).is_none());
    }
}
