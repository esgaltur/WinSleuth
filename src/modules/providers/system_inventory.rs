#![allow(non_camel_case_types)]
use sysinfo::System;
use crate::modules::core::models::SystemIdentity;
use crate::modules::core::traits::SystemInventoryProvider;
use wmi::WMIConnection;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_BaseBoard {
    manufacturer: String,
    product: String,
}

pub struct WindowsSystemInventory;

impl SystemInventoryProvider for WindowsSystemInventory {
    fn collect_system_identity(&self) -> SystemIdentity {
        let mut sys = System::new_all();
        sys.refresh_all();

        let mut motherboard_vendor = "Unknown".to_string();
        let mut motherboard_model = "Unknown".to_string();

        if let Ok(wmi_con) = WMIConnection::new() {
            if let Ok(boards) = wmi_con.query::<Win32_BaseBoard>() {
                if let Some(board) = boards.first() {
                    motherboard_vendor = board.manufacturer.clone();
                    motherboard_model = board.product.clone();
                }
            }
        }

        SystemIdentity {
            motherboard_vendor,
            motherboard_model,
            cpu_model: sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_else(|| "Unknown CPU".to_string()),
        }
    }
}
