use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::HSTRING;

/// Whether this process holds an elevated token.
///
/// Without this check an unelevated run silently loses the service control
/// manager enumeration, the minidump directory and several WMI classes, and
/// then prints "No significant instability patterns detected" — a false
/// negative that stops the user looking any further.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// Relaunch the current executable with the `runas` verb, which raises the UAC
/// prompt. Returns `Ok(true)` when the elevated process was started and this
/// one should exit.
pub fn relaunch_elevated(args: &[String]) -> anyhow::Result<bool> {
    let exe = std::env::current_exe()?;
    let params = args
        .iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let verb = HSTRING::from("runas");
    let file = HSTRING::from(exe.as_os_str());
    let params_w = HSTRING::from(params.as_str());

    let result = unsafe { ShellExecuteW(None, &verb, &file, &params_w, None, SW_SHOWNORMAL) };

    // ShellExecuteW returns a value greater than 32 on success. Anything at or
    // below that is an error code — most often the user declining the prompt.
    Ok(result.0 as usize > 32)
}

/// A short note describing what a scan will be missing at the current
/// privilege level, or `None` when everything is reachable.
pub fn degradation_notice() -> Option<&'static str> {
    if is_elevated() {
        None
    } else {
        Some(
            "Not running as Administrator. Crash dumps, service state and parts of the \
             System event log will be unavailable, and findings will be incomplete.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_check_is_consistent_with_its_notice() {
        // The notice must agree with the check whichever way the test runs.
        assert_eq!(is_elevated(), degradation_notice().is_none());
    }
}
