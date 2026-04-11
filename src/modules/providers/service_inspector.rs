use windows::Win32::System::Services::*;
use crate::modules::core::models::ServiceState;
use crate::modules::core::traits::ServiceProvider;
use windows::core::PCWSTR;

pub struct WindowsServiceInspector;

impl ServiceProvider for WindowsServiceInspector {
    fn collect_problematic_services(&self) -> Vec<ServiceState> {
        let mut results = Vec::new();

        unsafe {
            let sc_handle = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE).unwrap_or_default();
            if sc_handle.is_invalid() {
                return results;
            }

            let mut bytes_needed = 0;
            let mut services_returned = 0;
            let mut resume_handle = 0;

            // First call to get required buffer size
            let _ = EnumServicesStatusExW(
                sc_handle,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                None,
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                PCWSTR::null(),
            );

            let mut buffer = vec![0u8; bytes_needed as usize];
            if EnumServicesStatusExW(
                sc_handle,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(&mut buffer),
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                PCWSTR::null(),
            ).is_ok() {
                let services = std::slice::from_raw_parts(
                    buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                    services_returned as usize,
                );

                for service in services {
                    let exit_code = service.ServiceStatusProcess.dwWin32ExitCode;

                    if exit_code != 0 {
                        let name = service.lpServiceName.to_string().unwrap_or_default();
                        let display_name = service.lpDisplayName.to_string().unwrap_or_default();
                        
                        results.push(ServiceState {
                            name,
                            display_name,
                            status: format!("{:?}", service.ServiceStatusProcess.dwCurrentState),
                            exit_code,
                        });
                    }
                }
            }

            let _ = CloseServiceHandle(sc_handle);
        }

        results
    }
}
