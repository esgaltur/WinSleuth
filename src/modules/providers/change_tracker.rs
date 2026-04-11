use crate::modules::core::models::SystemChange;
use crate::modules::core::traits::ChangeProvider;
use wmi::WMIConnection;
use serde::Deserialize;
use chrono::{DateTime, Utc, Duration, TimeZone};

#[allow(non_camel_case_types)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_QuickFixEngineering {
    description: String,
    hot_fix_id: String,
    installed_on: String,
}

#[allow(non_camel_case_types)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_Product {
    name: String,
    install_date: String,
    version: String,
}

pub struct WindowsChangeTracker;

impl ChangeProvider for WindowsChangeTracker {
    fn collect_recent_changes(&self, days: i64) -> Vec<SystemChange> {
        let mut changes = Vec::new();
        let cutoff = Utc::now() - Duration::days(days);

        if let Ok(wmi_con) = WMIConnection::new() {
            // 1. Windows Updates
            if let Ok(updates) = wmi_con.query::<Win32_QuickFixEngineering>() {
                for update in updates {
                    if let Some(date) = parse_wmi_date(&update.installed_on) {
                        if date >= cutoff {
                            changes.push(SystemChange {
                                name: format!("Update: {} ({})", update.description, update.hot_fix_id),
                                date,
                                change_type: "Update".to_string(),
                            });
                        }
                    }
                }
            }

            // 2. Software Installations (Win32_Product can be slow, but it's the standard way)
            // In a real production app, we might also check Registry (Uninstall keys)
            if let Ok(products) = wmi_con.query::<Win32_Product>() {
                for product in products {
                    if let Some(date) = parse_wmi_date(&product.install_date) {
                        if date >= cutoff {
                            changes.push(SystemChange {
                                name: format!("Software: {} (v{})", product.name, product.version),
                                date,
                                change_type: "Software".to_string(),
                            });
                        }
                    }
                }
            }
        }

        changes.sort_by(|a, b| b.date.cmp(&a.date));
        changes
    }
}

fn parse_wmi_date(s: &str) -> Option<DateTime<Utc>> {
    // WMI InstalledOn is often "MM/DD/YYYY" or "YYYYMMDD..."
    // or sometimes just a hex value (which we don't handle yet)
    let s = s.trim();
    if s.is_empty() { return None; }

    if s.contains('/') {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() == 3 {
            let month = parts[0].parse::<u32>().ok()?;
            let day = parts[1].parse::<u32>().ok()?;
            let mut year = parts[2].parse::<i32>().ok()?;
            if year < 100 { year += 2000; } // Handle 2-digit years if they appear
            return Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).single();
        }
    } else if s.len() >= 8 {
        // Handle YYYYMMDD
        let year = s[0..4].parse::<i32>().ok()?;
        let month = s[4..6].parse::<u32>().ok()?;
        let day = s[6..8].parse::<u32>().ok()?;
        if month >= 1 && month <= 12 && day >= 1 && day <= 31 {
            return Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).single();
        }
    }
    None
}
