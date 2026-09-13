//! Service failure detection.
//!
//! The previous implementation collected every service whose
//! `dwWin32ExitCode` was non-zero. On a stock Windows install that is dozens of
//! services that simply stopped normally and retain a stale last-exit code, so
//! "System Service Failures" was reported at Moderate confidence on a perfectly
//! healthy machine.
//!
//! A service is a candidate here only when it is actually stopped *and* holds a
//! genuine failure code. Even then it is not reported until the Service Control
//! Manager also logged a failure for it — that corroboration is applied by the
//! engine against the collected timeline.

use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_STOPPED,
    SERVICE_WIN32,
};
use windows::core::PCWSTR;

use crate::modules::core::models::*;
use crate::modules::core::traits::ServiceProvider;

/// Exit codes that mean "nothing went wrong".
///
/// * `0`    - success.
/// * `1077` - `ERROR_SERVICE_NEVER_STARTED`; the service has simply not run.
/// * `1062` - `ERROR_SERVICE_NOT_ACTIVE`.
/// * `1063` - the service was started outside the control manager.
const BENIGN_EXIT_CODES: &[u32] = &[0, 1077, 1062, 1063];

pub struct WindowsServiceInspector;

impl ServiceProvider for WindowsServiceInspector {
    fn collect_problematic_services(&self, _window: &ScanWindow) -> Collected<Vec<ServiceState>> {
        let mut results = Vec::new();
        unsafe {
            let manager = match OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) {
                Ok(handle) if !handle.is_invalid() => handle,
                _ => {
                    return Collected::failed(
                        results,
                        "the service control manager could not be opened (Administrator required)",
                    );
                }
            };
            let mut resume = 0u32;
            loop {
                let mut needed = 0u32;
                let mut returned = 0u32;

                // Size probe. This is expected to fail with ERROR_MORE_DATA.
                let _ = EnumServicesStatusExW(
                    manager,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    None,
                    &mut needed,
                    &mut returned,
                    Some(&mut resume),
                    PCWSTR::null(),
                );
                if needed == 0 {
                    break;
                }

                let mut buffer = vec![0u8; needed as usize];
                let complete = EnumServicesStatusExW(
                    manager,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    Some(&mut buffer),
                    &mut needed,
                    &mut returned,
                    Some(&mut resume),
                    PCWSTR::null(),
                )
                .is_ok();
                if returned > 0 {
                    let services = std::slice::from_raw_parts(
                        buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                        returned as usize,
                    );
                    for service in services {
                        if let Some(state) = candidate(service) {
                            results.push(state);
                        }
                    }
                }

                // A successful call means the enumeration finished; otherwise
                // there is another page behind the resume handle.
                if complete || returned == 0 {
                    break;
                }
            }

            let _ = CloseServiceHandle(manager);
        }

        results.sort_by(|a, b| a.name.cmp(&b.name));
        Collected::complete(results)
    }
}

/// Decide whether one enumerated service looks like a real failure.
unsafe fn candidate(service: &ENUM_SERVICE_STATUS_PROCESSW) -> Option<ServiceState> {
    unsafe {
        let status = service.ServiceStatusProcess;
        let exit_code = status.dwWin32ExitCode;

        // A running service is not a failure however stale its last exit code.
        if status.dwCurrentState != SERVICE_STOPPED {
            return None;
        }
        if BENIGN_EXIT_CODES.contains(&exit_code) && status.dwServiceSpecificExitCode == 0 {
            return None;
        }

        Some(ServiceState {
            name: service.lpServiceName.to_string().unwrap_or_default(),
            display_name: service.lpDisplayName.to_string().unwrap_or_default(),
            status: "Stopped".to_string(),
            exit_code,
            service_specific_exit_code: status.dwServiceSpecificExitCode,
            // Filled in by the engine from Service Control Manager events.
            corroborated_by_log: false,
        })
    }
}

/// Human-readable form of the Win32 error codes services report most often.
pub fn describe_exit_code(code: u32) -> String {
    let text = match code {
        1 => "incorrect function",
        2 => "the system cannot find the file specified",
        5 => "access denied",
        1053 => "the service did not respond to the start request in time",
        1054 => "the service could not create its thread",
        1056 => "an instance of the service is already running",
        1058 => "the service is disabled",
        1064 => "the service threw an unhandled exception",
        1067 => "the process terminated unexpectedly",
        1068 => "a dependency service failed to start",
        1069 => "the service did not start because of a logon failure",
        1070 => "the service hung on starting",
        1072 => "the service is marked for deletion",
        1079 => "the service account differs from other services in the same process",
        1290 => "the service start failed because of a service-specific error",
        _ => return format!("Win32 error {code}"),
    };
    format!("{text} ({code})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_exit_codes_cover_the_ones_that_flooded_the_report() {
        assert!(BENIGN_EXIT_CODES.contains(&0));
        assert!(BENIGN_EXIT_CODES.contains(&1077));
        assert!(!BENIGN_EXIT_CODES.contains(&1067));
        assert!(!BENIGN_EXIT_CODES.contains(&1053));
    }

    #[test]
    fn exit_codes_are_explained_rather_than_printed_raw() {
        assert!(describe_exit_code(1067).contains("terminated unexpectedly"));
        assert!(describe_exit_code(1053).contains("did not respond"));
        assert!(describe_exit_code(999_999).contains("999999"));
    }

    #[test]
    fn a_healthy_machine_yields_few_candidates() {
        let collected =
            WindowsServiceInspector.collect_problematic_services(&ScanWindow::last_days(7));
        if let CollectionStatus::Failed { reason } = &collected.status {
            eprintln!("service manager unavailable ({reason}); skipping");
            return;
        }

        // Before the fix this routinely returned dozens on a healthy box.
        assert!(
            collected.value.len() < 25,
            "{} services flagged; the filter is too loose: {:?}",
            collected.value.len(),
            collected.value.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
        for service in &collected.value {
            assert_eq!(service.status, "Stopped");
            assert!(
                !BENIGN_EXIT_CODES.contains(&service.exit_code)
                    || service.service_specific_exit_code != 0,
                "{} carries benign code {}",
                service.name,
                service.exit_code
            );
            assert!(
                !service.corroborated_by_log,
                "corroboration is the engine's job"
            );
        }
    }
}
