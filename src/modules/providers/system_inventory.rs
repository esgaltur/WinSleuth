#![allow(non_camel_case_types)]
//! Host identity: OS build, board, CPU, memory and boot time.
//!
//! Boot time provides system context in reports. Kernel crash attribution uses
//! the module map saved in the dump, independently of the current boot.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sysinfo::System;
use wmi::WMIConnection;

use crate::modules::core::models::*;
use crate::modules::core::traits::SystemInventoryProvider;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_BaseBoard {
    manufacturer: Option<String>,
    product: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_OperatingSystem {
    caption: Option<String>,
    build_number: Option<String>,
    version: Option<String>,
}

pub struct WindowsSystemInventory;

impl SystemInventoryProvider for WindowsSystemInventory {
    fn collect_system_identity(&self) -> Collected<SystemIdentity> {
        let mut identity = SystemIdentity {
            hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),
            cpu_model: cpu_model(),
            physical_memory_gb: total_memory_gb(),
            last_boot: boot_time(),
            motherboard_vendor: "Unknown".to_string(),
            motherboard_model: "Unknown".to_string(),
            os_caption: System::long_os_version().unwrap_or_else(|| "Windows".to_string()),
            os_build: System::kernel_version().unwrap_or_default(),
        };
        let mut degraded = false;
        match WMIConnection::new() {
            Ok(connection) => {
                if let Ok(boards) = connection.query::<Win32_BaseBoard>()
                    && let Some(board) = boards.into_iter().next()
                {
                    identity.motherboard_vendor =
                        board.manufacturer.unwrap_or_else(|| "Unknown".to_string());
                    identity.motherboard_model =
                        board.product.unwrap_or_else(|| "Unknown".to_string());
                }

                if let Ok(systems) = connection.query::<Win32_OperatingSystem>()
                    && let Some(os) = systems.into_iter().next()
                {
                    if let Some(caption) = os.caption.filter(|c| !c.is_empty()) {
                        identity.os_caption = caption.trim().to_string();
                    }
                    identity.os_build = match (os.version, os.build_number) {
                        (Some(v), Some(b)) if !v.is_empty() => format!("{v} (build {b})"),
                        (Some(v), None) => v,
                        (None, Some(b)) => b,
                        _ => identity.os_build,
                    };
                }
            }
            Err(_) => degraded = true,
        }

        let status = if degraded {
            CollectionStatus::Partial {
                reason: "WMI unavailable; board details missing".into(),
            }
        } else {
            CollectionStatus::Complete
        };

        Collected {
            value: identity,
            status,
        }
    }
}

fn cpu_model() -> String {
    let mut system = System::new();
    system.refresh_cpu_list(sysinfo::CpuRefreshKind::nothing());
    system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().trim().to_string())
        .filter(|brand| !brand.is_empty())
        .unwrap_or_else(|| "Unknown CPU".to_string())
}

fn total_memory_gb() -> f32 {
    let mut system = System::new();
    system.refresh_memory();
    system.total_memory() as f32 / 1_073_741_824.0
}

pub fn boot_time() -> Option<DateTime<Utc>> {
    let seconds = System::boot_time();
    (seconds > 0)
        .then(|| DateTime::from_timestamp(seconds as i64, 0))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_populated_with_plausible_values() {
        let collected = WindowsSystemInventory.collect_system_identity();
        let identity = collected.value;
        assert!(!identity.hostname.is_empty());
        assert!(!identity.cpu_model.is_empty());
        assert_ne!(
            identity.cpu_model, "Unknown CPU",
            "CPU brand should resolve on Windows"
        );
        assert!(
            identity.physical_memory_gb > 0.4,
            "implausible memory total {}",
            identity.physical_memory_gb
        );
        assert!(identity.os_caption.to_lowercase().contains("windows"));
    }

    #[test]
    fn boot_time_is_in_the_past_and_recent_enough_to_be_real() {
        let boot = boot_time().expect("boot time must resolve");
        let now = Utc::now();
        assert!(boot < now, "boot time is in the future");
        // Uptime beyond a couple of years would indicate a unit mix-up.
        assert!((now - boot).num_days() < 730, "implausible uptime");
    }
}
