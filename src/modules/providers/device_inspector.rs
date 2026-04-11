use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiGetClassDevsW, SetupDiEnumDeviceInfo, SP_DEVINFO_DATA, DIGCF_PRESENT, DIGCF_ALLCLASSES,
    SetupDiGetDeviceRegistryPropertyW, SPDRP_FRIENDLYNAME, SPDRP_DEVICEDESC, SetupDiDestroyDeviceInfoList,
    CM_Get_DevNode_Status, CM_DEVNODE_STATUS_FLAGS, CM_PROB, CR_SUCCESS
};
use crate::modules::core::models::DeviceState;
use crate::modules::core::traits::DeviceInspectorProvider;

pub struct WindowsDeviceInspector;

impl DeviceInspectorProvider for WindowsDeviceInspector {
    fn collect_device_problems(&self) -> Vec<DeviceState> {
        let mut results = Vec::new();
        
        unsafe {
            let dev_info = SetupDiGetClassDevsW(None, None, None, DIGCF_PRESENT | DIGCF_ALLCLASSES).unwrap_or_default();
            if dev_info.is_invalid() {
                return results;
            }

            let mut dev_data = SP_DEVINFO_DATA {
                cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                ClassGuid: Default::default(),
                DevInst: 0,
                Reserved: 0,
            };

            let mut index = 0;
            while SetupDiEnumDeviceInfo(dev_info, index, &mut dev_data).is_ok() {
                let mut status = CM_DEVNODE_STATUS_FLAGS(0);
                let mut problem_num = CM_PROB(0);

                if CM_Get_DevNode_Status(&mut status, &mut problem_num, dev_data.DevInst, 0) == CR_SUCCESS {
                    if problem_num.0 > 0 {
                        let mut buffer = [0u8; 1024];
                        let mut req_size = 0;

                        let mut name = "Unknown Device".to_string();
                        if SetupDiGetDeviceRegistryPropertyW(
                            dev_info,
                            &mut dev_data,
                            SPDRP_FRIENDLYNAME,
                            None,
                            Some(buffer.as_mut_slice()),
                            Some(&mut req_size),
                        ).is_ok() || SetupDiGetDeviceRegistryPropertyW(
                            dev_info,
                            &mut dev_data,
                            SPDRP_DEVICEDESC,
                            None,
                            Some(buffer.as_mut_slice()),
                            Some(&mut req_size),
                        ).is_ok() {
                            let name_u16: &[u16] = std::slice::from_raw_parts(
                                buffer.as_ptr() as *const u16,
                                req_size as usize / 2,
                            );
                            name = String::from_utf16_lossy(name_u16).trim_matches('\0').to_string();
                        }

                        results.push(DeviceState {
                            name,
                            device_id: format!("DevInst: {}", dev_data.DevInst),
                            problem_code: Some(problem_num.0),
                            status: format!("Device has problem code {}", problem_num.0),
                        });
                    }
                }
                index += 1;
            }

            let _ = SetupDiDestroyDeviceInfoList(dev_info);
        }

        results
    }
}
