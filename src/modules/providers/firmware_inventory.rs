#![allow(non_camel_case_types)]
use crate::modules::core::models::FirmwareInfo;
use crate::modules::core::traits::FirmwareInventoryProvider;
use wmi::WMIConnection;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_BIOS {
    manufacturer: String,
    version: String,
    release_date: String,
}

pub struct WindowsFirmwareInventory;

impl FirmwareInventoryProvider for WindowsFirmwareInventory {
    fn collect_firmware_info(&self) -> FirmwareInfo {
        let mut vendor = "Unknown".to_string();
        let mut version = "Unknown".to_string();
        let mut date = "Unknown".to_string();

        if let Ok(wmi_con) = WMIConnection::new() {
            if let Ok(bioses) = wmi_con.query::<Win32_BIOS>() {
                if let Some(bios) = bioses.first() {
                    vendor = bios.manufacturer.clone();
                    version = bios.version.clone();
                    date = bios.release_date.clone();
                }
            }
        }

        FirmwareInfo {
            vendor,
            version,
            date,
        }
    }
}
