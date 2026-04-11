#![allow(non_camel_case_types)]
use crate::modules::core::models::{DriverInfo, DriverCategory};
use crate::modules::core::traits::DriverInventoryProvider;
use wmi::WMIConnection;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use sha2::{Sha256, Digest};
use hex;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA_0,
    WINTRUST_DATA_REVOCATION_CHECKS,
};
use windows::Win32::Foundation::{HWND, HANDLE};
use windows::core::{HSTRING, PCWSTR, PWSTR};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_SystemDriver {
    name: String,
    display_name: Option<String>,
    service_type: String,
    path_name: Option<String>,
}

use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW};

pub struct WindowsDriverInventory;

impl DriverInventoryProvider for WindowsDriverInventory {
    fn collect_drivers(&self) -> Vec<DriverInfo> {
        let mut drivers = Vec::new();

        // Method 1: WMI for the master list of running drivers
        if let Ok(wmi_con) = WMIConnection::new() {
            let query = "SELECT Name, DisplayName, ServiceType, PathName FROM Win32_SystemDriver WHERE State = 'Running'";
            if let Ok(system_drivers) = wmi_con.raw_query::<Win32_SystemDriver>(query) {
                for driver in system_drivers {
                    if !driver.service_type.contains("Kernel") && !driver.service_type.contains("File System") {
                        continue;
                    }
                    
                    let clean_path = driver.path_name.clone().unwrap_or_default()
                        .replace("\\SystemRoot", "C:\\Windows")
                        .replace("\\??\\", "")
                        .trim_matches('"')
                        .to_string();
                    
                    if clean_path.is_empty() { continue; }

                    let name = std::path::Path::new(&clean_path).file_name().unwrap_or_default().to_string_lossy().to_string();
                    
                    let is_os_driver = clean_path.to_lowercase().contains("windows\\system32\\drivers") || 
                                       clean_path.to_lowercase().contains("system32\\driverstore") ||
                                       clean_path.to_lowercase().contains("windows\\winsxs") ||
                                       name.to_lowercase() == "ntoskrnl.exe" ||
                                       name.to_lowercase() == "hal.dll";

                    let category = categorize_driver(&driver.name, &driver.display_name.as_ref().unwrap_or(&driver.name), &clean_path);
                    
                    let (version, company) = get_version_info(&clean_path);
                    let signed = is_file_signed(&clean_path);

                    drivers.push(DriverInfo {
                        name: clean_path.clone(),
                        version,
                        publisher: driver.display_name.unwrap_or_else(|| driver.name.clone()),
                        description: format!("Loaded kernel module: {}", driver.name),
                        company,
                        hash: get_file_hash(&clean_path).unwrap_or_else(|_| "HASH_LOCKED".to_string()),
                        base_address: 0,
                        size: 0,
                        signed,
                        is_os_driver,
                        category,
                    });
                }
            }
        }

        // Method 2: PSAPI to enrich with base addresses
        let mut driver_addresses = [0 as *mut std::ffi::c_void; 1024];
        let mut cb_needed = 0;
        unsafe {
            if EnumDeviceDrivers(driver_addresses.as_mut_ptr(), size_of_val(&driver_addresses) as u32, &mut cb_needed).is_ok() {
                let count = cb_needed as usize / size_of::<*mut std::ffi::c_void>();
                for i in 0..count {
                    let mut path_buffer = [0u16; 1024];
                    let len = GetDeviceDriverFileNameW(driver_addresses[i], &mut path_buffer);
                    if len > 0 {
                        let path = String::from_utf16_lossy(&path_buffer[..len as usize])
                            .replace("\\SystemRoot", "C:\\Windows")
                            .replace("\\??\\", "");
                        
                        let raw_addr = driver_addresses[i];
                        if let Some(existing) = drivers.iter_mut().find(|d: &&mut DriverInfo| d.name.to_lowercase() == path.to_lowercase()) {
                            existing.base_address = raw_addr as u64;
                        } else {
                            // If it's a core module not seen by WMI (like ntoskrnl itself sometimes)
                            let name = std::path::Path::new(&path).file_name().unwrap_or_default().to_string_lossy().to_string();
                            let is_os_driver = path.to_lowercase().contains("windows\\system32") || 
                                               name.to_lowercase() == "ntoskrnl.exe";
                            
                            let (version, company) = get_version_info(&path);
                            let signed = is_file_signed(&path);

                            drivers.push(DriverInfo {
                                name: path.clone(),
                                version,
                                publisher: name.clone(),
                                description: format!("Loaded kernel module: {}", name),
                                company,
                                hash: "N/A".to_string(),
                                base_address: driver_addresses[i] as u64,
                                size: 0,
                                signed,
                                is_os_driver,
                                category: DriverCategory::Other,
                            });
                        }
                    }
                }
            }
        }
        
        drivers
    }
}

fn get_file_hash(path: &str) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    
    Ok(hex::encode(hasher.finalize()))
}

fn get_version_info(path: &str) -> (String, String) {
    let mut version = "N/A".to_string();
    let mut company = "Unknown".to_string();
    
    let path_w = HSTRING::from(path);
    unsafe {
        let size = GetFileVersionInfoSizeW(&path_w, None);
        if size > 0 {
            let mut buffer = vec![0u8; size as usize];
            if GetFileVersionInfoW(&path_w, Some(0), size, buffer.as_mut_ptr() as *mut _).is_ok() {
                let query_value = |sub_block_path: &str| -> Option<String> {
                    let sub_block = HSTRING::from(sub_block_path);
                    let mut value_ptr = std::ptr::null_mut();
                    let mut value_len = 0;
                    if VerQueryValueW(buffer.as_ptr() as *const _, &sub_block, &mut value_ptr, &mut value_len).as_bool() && value_len > 0 {
                        Some(String::from_utf16_lossy(std::slice::from_raw_parts(value_ptr as *const u16, value_len as usize)).trim_matches('\0').to_string())
                    } else {
                        None
                    }
                };

                if let Some(v) = query_value("\\StringFileInfo\\040904b0\\FileVersion") {
                    version = v;
                }
                if let Some(c) = query_value("\\StringFileInfo\\040904b0\\CompanyName") {
                    company = c;
                }
            }
        }
    }
    (version, company)
}

fn is_file_signed(path: &str) -> bool {
    let path_w = HSTRING::from(path);
    let file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path_w.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WINTRUST_DATA_REVOCATION_CHECKS(WTD_REVOCATION_CHECK_NONE.0),
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &file_info as *const _ as *mut _ },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: HANDLE::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: Default::default(),
        dwUIContext: Default::default(),
        pSignatureSettings: std::ptr::null_mut(),
    };

    unsafe {
        let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let result = WinVerifyTrust(HWND(std::ptr::null_mut()), &mut action_guid, &mut data as *mut _ as *mut _);
        result == 0
    }
}

fn categorize_driver(name: &str, display: &str, path: &str) -> DriverCategory {
    let text = format!("{} {} {}", name, display, path).to_lowercase();
    
    // Expanded keyword list from expert criteria
    if text.contains("rgb") || text.contains("lighting") || text.contains("aura") || text.contains("icue") || text.contains("corsair") || text.contains("razer") || text.contains("steelseries") {
        DriverCategory::Rgb
    } else if text.contains("fan") || text.contains("monitor") || text.contains("hwinfo") || text.contains("aida") || text.contains("rtcore") || text.contains("winring0") {
        DriverCategory::Monitoring
    } else if text.contains("overclock") || text.contains("afterburner") || text.contains("ryzenmaster") || text.contains("xtu") || text.contains("nvlddmkm") {
        // GPU drivers often categorized as "Other" but important for instability
        if text.contains("nvlddmkm") || text.contains("amdfendr") { DriverCategory::Other } else { DriverCategory::Overclocking }
    } else if text.contains("antivirus") || text.contains("defender") || text.contains("kaspersky") || text.contains("security") || text.contains("sentinel") || text.contains("crowdstrike") {
        DriverCategory::Antivirus
    } else if text.contains("network") || text.contains("ndis") || text.contains("vpn") || text.contains("wi-fi") || text.contains("intel(r) ethernet") {
        DriverCategory::Network
    } else if text.contains("disk") || text.contains("storage") || text.contains("scsi") || text.contains("nvme") || text.contains("ahci") || text.contains("raid") || text.contains("vmware") {
        DriverCategory::Storage
    } else if text.contains("usb") || text.contains("xhci") {
        DriverCategory::Usb
    } else {
        DriverCategory::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorize_driver() {
        assert_eq!(categorize_driver("hwinfo64.sys", "HWiNFO64 Driver", "C:\\temp\\hwinfo64.sys"), DriverCategory::Monitoring);
        assert_eq!(categorize_driver("AMDRyzenMasterDriver.sys", "AMD Ryzen Master", "C:\\bin\\AMDRyzenMasterDriver.sys"), DriverCategory::Overclocking);
        assert_eq!(categorize_driver("CorsairLLAccess64.sys", "Corsair Link", "C:\\drivers\\CorsairLLAccess64.sys"), DriverCategory::Rgb);
        assert_eq!(categorize_driver("nvlddmkm.sys", "NVIDIA Windows Kernel Mode Driver", "C:\\windows\\system32\\nvlddmkm.sys"), DriverCategory::Other);
    }
}
