#![allow(non_camel_case_types)]
//! Recent system changes: Windows updates, installed software, driver packages.
//!
//! The previous implementation enumerated `Win32_Product`. That WMI class makes
//! the Windows Installer run a consistency check against every registered MSI
//! and will reconfigure or self-repair packages as a side effect. It takes
//! minutes, floods the Application log with MsiInstaller events, and — for a
//! tool whose entire job is diagnosing instability — mutates the system it is
//! supposed to be observing, then reports its own noise back as evidence.
//!
//! The uninstall registry keys carry the same information, including
//! `InstallDate`, and cost milliseconds.

use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;
use windows_registry::{CURRENT_USER, LOCAL_MACHINE};
use wmi::WMIConnection;

use crate::modules::core::models::*;
use crate::modules::core::traits::ChangeProvider;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_QuickFixEngineering {
    description: Option<String>,
    hot_fix_id: String,
    installed_on: Option<String>,
}

/// Uninstall keys, in the order they are searched.
const UNINSTALL_KEYS: &[(&str, bool)] = &[
    (
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        true,
    ),
    (
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        true,
    ),
    (
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        false,
    ),
];

pub struct WindowsChangeTracker;

impl ChangeProvider for WindowsChangeTracker {
    fn collect_recent_changes(&self, window: &ScanWindow) -> Collected<Vec<SystemChange>> {
        let mut changes = Vec::new();
        let mut degraded: Vec<&str> = Vec::new();
        match collect_hotfixes(window) {
            Some(mut hotfixes) => changes.append(&mut hotfixes),
            None => degraded.push("Windows Update history"),
        }

        changes.append(&mut collect_software(window));
        changes.append(&mut collect_driver_packages(window));
        changes.sort_by_key(|c| std::cmp::Reverse(c.date));
        changes.dedup_by(|a, b| a.name == b.name && a.date == b.date);
        let status = if degraded.is_empty() {
            CollectionStatus::Complete
        } else {
            CollectionStatus::Partial {
                reason: format!("could not read {}", degraded.join(", ")),
            }
        };

        Collected {
            value: changes,
            status,
        }
    }
}

fn collect_hotfixes(window: &ScanWindow) -> Option<Vec<SystemChange>> {
    let connection = WMIConnection::new().ok()?;
    let hotfixes = connection.query::<Win32_QuickFixEngineering>().ok()?;

    Some(
        hotfixes
            .into_iter()
            .filter_map(|hotfix| {
                let date = parse_date(hotfix.installed_on.as_deref()?)?;
                window.contains(date).then(|| SystemChange {
                    name: match hotfix.description.as_deref() {
                        Some(d) if !d.is_empty() => format!("{} ({})", d, hotfix.hot_fix_id),
                        _ => hotfix.hot_fix_id.clone(),
                    },
                    date,
                    change_type: ChangeType::WindowsUpdate,
                    version: Some(hotfix.hot_fix_id),
                })
            })
            .collect(),
    )
}

fn collect_software(window: &ScanWindow) -> Vec<SystemChange> {
    let mut changes = Vec::new();

    for (path, machine) in UNINSTALL_KEYS {
        let root = if *machine {
            LOCAL_MACHINE
        } else {
            CURRENT_USER
        };
        let Ok(key) = root.open(path) else { continue };
        let Ok(subkeys) = key.keys() else { continue };
        for name in subkeys {
            let Ok(entry) = key.open(&name) else { continue };

            // Updates and patches are listed here too; they are not separate
            // installs and would double-count against the hotfix list.
            if entry.get_u32("SystemComponent").unwrap_or(0) == 1 {
                continue;
            }
            let Ok(display_name) = entry.get_string("DisplayName") else {
                continue;
            };
            if display_name.trim().is_empty() {
                continue;
            }

            let Some(date) = entry
                .get_string("InstallDate")
                .ok()
                .and_then(|d| parse_date(&d))
            else {
                continue;
            };
            if !window.contains(date) {
                continue;
            }

            let version = entry.get_string("DisplayVersion").ok();
            changes.push(SystemChange {
                name: display_name,
                date,
                change_type: ChangeType::Software,
                version,
            });
        }
    }

    changes
}

/// Third-party driver packages. Each installed package leaves an `oem*.inf` in
/// the Windows INF directory whose modification time is the install time.
fn collect_driver_packages(window: &ScanWindow) -> Vec<SystemChange> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let Ok(entries) = std::fs::read_dir(format!("{root}\\INF")) else {
        return Vec::new();
    };

    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy().to_lowercase();
            if !name.starts_with("oem") || !name.ends_with(".inf") {
                return None;
            }

            let modified = entry.metadata().ok()?.modified().ok()?;
            let date = DateTime::<Utc>::from(modified);
            if !window.contains(date) {
                return None;
            }

            // The INF's own Provider line names the vendor far more usefully
            // than "oem42.inf" does.
            let label = inf_description(&path).unwrap_or_else(|| name.clone());

            Some(SystemChange {
                name: format!("Driver package: {label}"),
                date,
                change_type: ChangeType::Driver,
                version: None,
            })
        })
        .collect()
}

fn inf_description(path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut provider = None;
    let mut class = None;

    for line in text.lines().take(200) {
        let line = line.trim();
        let lower = line.to_lowercase();
        if provider.is_none() && lower.starts_with("provider") {
            provider = line.split_once('=').map(|(_, v)| clean_inf_value(v));
        }
        if class.is_none() && lower.starts_with("class ") || lower.starts_with("class=") {
            class = line.split_once('=').map(|(_, v)| clean_inf_value(v));
        }
        if provider.is_some() && class.is_some() {
            break;
        }
    }

    match (provider, class) {
        (Some(p), Some(c)) if !p.is_empty() && !c.is_empty() => Some(format!("{p} ({c})")),
        (Some(p), _) if !p.is_empty() => Some(p),
        _ => None,
    }
}

fn clean_inf_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_start_matches('%')
        .trim_end_matches('%')
        .to_string()
}

/// Parse the date formats Windows uses for install dates.
///
/// `InstallDate` in the uninstall keys is `YYYYMMDD`. `Win32_QuickFixEngineering`
/// reports the locale's short date, most often `M/D/YYYY`.
pub(crate) fn parse_date(raw: &str) -> Option<DateTime<Utc>> {
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }

    if text.contains('/') {
        let parts: Vec<&str> = text.split('/').collect();
        if parts.len() != 3 {
            return None;
        }
        let month = parts[0].trim().parse::<u32>().ok()?;
        let day = parts[1].trim().parse::<u32>().ok()?;
        let mut year = parts[2]
            .trim()
            .get(..4)
            .unwrap_or(parts[2].trim())
            .parse::<i32>()
            .ok()?;
        if year < 100 {
            year += 2000;
        }
        return Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).single();
    }

    // YYYYMMDD, sometimes with a WMI time suffix.
    let digits: String = text.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.len() < 8 {
        return None;
    }
    let year = digits[0..4].parse::<i32>().ok()?;
    let month = digits[4..6].parse::<u32>().ok()?;
    let day = digits[6..8].parse::<u32>().ok()?;
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).single()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_date_formats_windows_reports() {
        let ymd = parse_date("20260814").expect("YYYYMMDD");
        assert_eq!(ymd.format("%Y-%m-%d").to_string(), "2026-08-14");
        let slash = parse_date("8/14/2026").expect("M/D/YYYY");
        assert_eq!(slash.format("%Y-%m-%d").to_string(), "2026-08-14");

        // WMI sometimes appends a time and offset.
        let wmi = parse_date("20260814000000.000000+000").expect("WMI datetime");
        assert_eq!(wmi.format("%Y-%m-%d").to_string(), "2026-08-14");
    }

    #[test]
    fn rejects_junk_rather_than_defaulting_to_now() {
        assert!(parse_date("").is_none());
        assert!(parse_date("   ").is_none());
        assert!(parse_date("not a date").is_none());
        assert!(parse_date("2026").is_none());
        // An impossible date must not be coerced into a real one.
        assert!(parse_date("20261345").is_none());
    }

    #[test]
    fn changes_are_bounded_by_the_scan_window() {
        let window = ScanWindow::last_days(7);
        let collected = WindowsChangeTracker.collect_recent_changes(&window);
        for change in &collected.value {
            assert!(
                window.contains(change.date),
                "{} dated {} escaped the window",
                change.name,
                change.date
            );
        }

        // A wider window can only ever include more.
        let wide = WindowsChangeTracker.collect_recent_changes(&ScanWindow::last_days(365));
        assert!(wide.value.len() >= collected.value.len());
    }

    #[test]
    fn changes_are_sorted_newest_first() {
        let collected = WindowsChangeTracker.collect_recent_changes(&ScanWindow::last_days(365));
        for pair in collected.value.windows(2) {
            assert!(pair[0].date >= pair[1].date, "changes are not ordered");
        }
    }
}
