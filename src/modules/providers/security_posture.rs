//! Kernel security posture.
//!
//! Pairs with the vulnerable-driver check: knowing that a machine has a
//! known-vulnerable driver loaded is one thing, knowing that Memory Integrity
//! is switched off — so nothing is stopping it being abused — is what makes the
//! finding actionable.
//!
//! Every field is `Option<bool>`, because "we could not determine this" is a
//! distinct and honest answer from "it is off".

use serde::Deserialize;
use windows_registry::LOCAL_MACHINE;
use wmi::WMIConnection;

use crate::modules::core::models::*;
use crate::modules::core::traits::SecurityPostureProvider;

#[allow(non_camel_case_types)]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_DeviceGuard {
    /// 1 = credential guard, 2 = HVCI (memory integrity).
    security_services_running: Option<Vec<u32>>,
    /// 0 = VBS off, 1 = enabled but not running, 2 = running.
    virtualization_based_security_status: Option<u32>,
}

const HVCI_SERVICE: u32 = 2;

pub struct WindowsSecurityPosture;

impl SecurityPostureProvider for WindowsSecurityPosture {
    fn collect_posture(&self) -> Collected<SecurityPosture> {
        let mut posture = SecurityPosture {
            secure_boot: read_flag(
                "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                "UEFISecureBootEnabled",
            ),
            test_signing: read_flag("SYSTEM\\CurrentControlSet\\Control\\CI", "TestSigning"),
            driver_blocklist_enabled: read_flag(
                "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
                "VulnerableDriverBlocklistEnable",
            ),
            ..Default::default()
        };

        // The registry policy value says what was *asked for*; Win32_DeviceGuard
        // says what is actually running. Prefer the running state.
        let mut degraded = None;
        match device_guard_state() {
            Some((hvci, vbs)) => {
                posture.hvci_enabled = Some(hvci);
                posture.vbs_enabled = Some(vbs);
            }
            None => {
                posture.hvci_enabled = read_flag(
                    "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                    "Enabled",
                );
                degraded = Some("Device Guard state read from policy rather than running state");
            }
        }

        posture.kernel_dma_protection = read_flag(
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelDmaProtection",
            "Enabled",
        );
        match degraded {
            Some(reason) => Collected::partial(posture, reason),
            None => Collected::complete(posture),
        }
    }
}

/// Returns `(hvci_running, vbs_running)`.
fn device_guard_state() -> Option<(bool, bool)> {
    let connection =
        WMIConnection::with_namespace_path("root\\Microsoft\\Windows\\DeviceGuard").ok()?;
    let entries = connection.query::<Win32_DeviceGuard>().ok()?;
    let guard = entries.into_iter().next()?;

    let hvci = guard
        .security_services_running
        .map(|services| services.contains(&HVCI_SERVICE))
        .unwrap_or(false);
    let vbs = guard.virtualization_based_security_status.unwrap_or(0) == 2;

    Some((hvci, vbs))
}

fn read_flag(path: &str, value: &str) -> Option<bool> {
    let key = LOCAL_MACHINE.open(path).ok()?;
    Some(key.get_u32(value).ok()? != 0)
}

impl SecurityPosture {
    /// A short list of the mitigations that are off, for the report.
    pub fn weaknesses(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        if self.hvci_enabled == Some(false) {
            gaps.push("Memory Integrity (HVCI) is off");
        }
        if self.driver_blocklist_enabled == Some(false) {
            gaps.push("the Microsoft vulnerable driver blocklist is off");
        }
        if self.secure_boot == Some(false) {
            gaps.push("Secure Boot is off");
        }
        if self.test_signing == Some(true) {
            gaps.push("test signing is enabled, so unsigned drivers can load");
        }
        gaps
    }

    /// Whether anything at all could be determined.
    pub fn is_known(&self) -> bool {
        self.hvci_enabled.is_some()
            || self.vbs_enabled.is_some()
            || self.secure_boot.is_some()
            || self.driver_blocklist_enabled.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weaknesses_only_lists_things_known_to_be_off() {
        let unknown = SecurityPosture::default();
        assert!(
            unknown.weaknesses().is_empty(),
            "unknown must not be reported as off"
        );
        assert!(!unknown.is_known());
        let bad = SecurityPosture {
            hvci_enabled: Some(false),
            secure_boot: Some(false),
            test_signing: Some(true),
            driver_blocklist_enabled: Some(false),
            ..Default::default()
        };
        assert_eq!(bad.weaknesses().len(), 4);
        assert!(bad.is_known());
        let good = SecurityPosture {
            hvci_enabled: Some(true),
            secure_boot: Some(true),
            test_signing: Some(false),
            driver_blocklist_enabled: Some(true),
            vbs_enabled: Some(true),
            kernel_dma_protection: Some(true),
        };
        assert!(good.weaknesses().is_empty());
    }

    #[test]
    fn live_posture_resolves_at_least_one_setting() {
        let collected = WindowsSecurityPosture.collect_posture();
        assert!(
            collected.value.is_known(),
            "no security setting could be read at all: {:?}",
            collected.value
        );
    }
}
