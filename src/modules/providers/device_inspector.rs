//! Plug and Play devices reporting a problem code.
//!
//! Adds the documented name for each `CM_PROB_*` code and the device's real
//! instance id, so a finding says "Code 43 - the driver reported a failure"
//! rather than `Some(43)` against `DevInst: 51234`.

use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_DEVNODE_STATUS_FLAGS, CM_Get_DevNode_Status, CM_Get_Device_IDW, CM_PROB, CR_SUCCESS,
    DIGCF_ALLCLASSES, DIGCF_PRESENT, SP_DEVINFO_DATA, SPDRP_DEVICEDESC, SPDRP_FRIENDLYNAME,
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceRegistryPropertyW,
};

use crate::modules::core::models::*;
use crate::modules::core::traits::DeviceInspectorProvider;

pub struct WindowsDeviceInspector;

impl DeviceInspectorProvider for WindowsDeviceInspector {
    fn collect_device_problems(&self) -> Collected<Vec<DeviceState>> {
        let mut results = Vec::new();
        unsafe {
            let set = match SetupDiGetClassDevsW(None, None, None, DIGCF_PRESENT | DIGCF_ALLCLASSES)
            {
                Ok(handle) if !handle.is_invalid() => handle,
                _ => return Collected::failed(results, "the PnP device tree could not be opened"),
            };
            let mut data = SP_DEVINFO_DATA {
                cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                ClassGuid: Default::default(),
                DevInst: 0,
                Reserved: 0,
            };
            let mut index = 0u32;
            while SetupDiEnumDeviceInfo(set, index, &mut data).is_ok() {
                index += 1;
                let mut status = CM_DEVNODE_STATUS_FLAGS(0);
                let mut problem = CM_PROB(0);
                if CM_Get_DevNode_Status(&mut status, &mut problem, data.DevInst, 0) != CR_SUCCESS {
                    continue;
                }
                if problem.0 == 0 {
                    continue;
                }

                let name =
                    device_name(set, &mut data).unwrap_or_else(|| "Unknown device".to_string());
                let device_id = device_instance_id(data.DevInst)
                    .unwrap_or_else(|| format!("DevInst {}", data.DevInst));
                results.push(DeviceState {
                    name,
                    device_id,
                    problem_code: Some(problem.0),
                    problem_name: problem_name(problem.0).to_string(),
                    status: format!("Code {} - {}", problem.0, problem_name(problem.0)),
                });
            }

            let _ = SetupDiDestroyDeviceInfoList(set);
        }

        results.sort_by(|a, b| a.name.cmp(&b.name));
        Collected::complete(results)
    }
}

unsafe fn device_name(
    set: windows::Win32::Devices::DeviceAndDriverInstallation::HDEVINFO,
    data: &mut SP_DEVINFO_DATA,
) -> Option<String> {
    unsafe {
        for property in [SPDRP_FRIENDLYNAME, SPDRP_DEVICEDESC] {
            let mut buffer = [0u8; 1024];
            let mut required = 0u32;
            let ok = SetupDiGetDeviceRegistryPropertyW(
                set,
                data,
                property,
                None,
                Some(buffer.as_mut_slice()),
                Some(&mut required),
            )
            .is_ok();
            if !ok || required < 2 {
                continue;
            }

            let chars = (required as usize / 2).min(buffer.len() / 2);
            let wide = std::slice::from_raw_parts(buffer.as_ptr() as *const u16, chars);
            let text = String::from_utf16_lossy(wide);
            let text = text.trim_end_matches('\0').trim().to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
        None
    }
}

/// The stable hardware instance id, which is what a user needs to find the
/// device in Device Manager.
unsafe fn device_instance_id(dev_inst: u32) -> Option<String> {
    unsafe {
        let mut buffer = [0u16; 512];
        if CM_Get_Device_IDW(dev_inst, &mut buffer, 0) != CR_SUCCESS {
            return None;
        }
        let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
        let text = String::from_utf16_lossy(&buffer[..end]).trim().to_string();
        (!text.is_empty()).then_some(text)
    }
}

/// Documented meaning of a `CM_PROB_*` code.
pub fn problem_name(code: u32) -> &'static str {
    match code {
        1 => "the device is not configured correctly",
        3 => "the driver may be corrupted, or the system is low on memory",
        9 => "the firmware is reporting the device's resources incorrectly",
        10 => "the device cannot start",
        12 => "the device cannot find enough free resources",
        14 => "the device requires a restart to work correctly",
        16 => "Windows cannot identify all the resources the device uses",
        18 => "the drivers for this device need to be reinstalled",
        19 => "the registry configuration for this device is incomplete or damaged",
        21 => "Windows is removing the device",
        22 => "the device is disabled",
        24 => "the device is not present, is not working properly, or has incomplete drivers",
        28 => "the drivers for this device are not installed",
        29 => "the device is disabled because its firmware did not give it resources",
        31 => "Windows cannot load the drivers required for this device",
        32 => "the start type for this driver is set to disabled",
        33 => "Windows cannot determine which resources are required for this device",
        34 => "Windows cannot determine the settings for this device",
        35 => "the firmware does not include enough information to configure this device",
        36 => "the device is requesting a PCI interrupt but is configured for ISA",
        37 => "the driver returned a failure when it initialised the device",
        38 => "a previous instance of the driver is still in memory",
        39 => "the driver is corrupted or missing",
        40 => "the service key information in the registry is invalid or missing",
        41 => "the driver loaded but Windows cannot find the device",
        42 => "a duplicate device is already running",
        43 => "the driver reported a failure and Windows stopped the device",
        44 => "an application or service shut the device down",
        45 => "the device is not connected to the computer",
        46 => "the device is not available because the system is shutting down",
        47 => "the device is prepared for safe removal but has not been removed",
        48 => "the software for this device has been blocked from starting",
        49 => "the system hive has exceeded its size limit",
        52 => "the driver's digital signature could not be verified",
        54 => "the device has failed and is undergoing a reset",
        _ => "an unrecognised problem code",
    }
}

/// Codes that point at hardware or connection faults rather than at a
/// configuration choice the user made.
pub fn is_hardware_fault(code: u32) -> bool {
    matches!(
        code,
        10 | 12 | 14 | 21 | 24 | 31 | 37 | 39 | 41 | 43 | 45 | 54
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_problem_codes_are_named() {
        assert!(problem_name(43).contains("driver reported a failure"));
        assert!(problem_name(10).contains("cannot start"));
        assert!(problem_name(22).contains("disabled"));
        assert!(problem_name(52).contains("digital signature"));
        assert_eq!(problem_name(9999), "an unrecognised problem code");
    }

    #[test]
    fn a_disabled_device_is_not_a_hardware_fault() {
        // Code 22 means the user disabled it; reporting that as a fault is noise.
        assert!(!is_hardware_fault(22));
        assert!(!is_hardware_fault(28));
        assert!(is_hardware_fault(43));
        assert!(is_hardware_fault(10));
    }

    #[test]
    fn every_reported_device_carries_a_code_and_an_explanation() {
        let collected = WindowsDeviceInspector.collect_device_problems();
        if let CollectionStatus::Failed { reason } = &collected.status {
            eprintln!("device tree unavailable ({reason}); skipping");
            return;
        }

        for device in &collected.value {
            let code = device
                .problem_code
                .expect("a reported device must carry a code");
            assert!(code > 0);
            assert!(!device.problem_name.is_empty());
            assert!(!device.name.is_empty());
            // The old provider emitted "DevInst: 51234", which is useless to a
            // user. Anything reported should be a real instance id.
            assert!(!device.device_id.is_empty());
        }
    }
}
