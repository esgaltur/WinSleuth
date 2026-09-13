#![allow(non_camel_case_types)]
//! BIOS/UEFI details.
//!
//! The release date is parsed rather than passed through as the raw WMI
//! datetime string, so rules can reason about firmware age — old firmware on a
//! platform with known AGESA or microcode problems is a real lead.

use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;
use wmi::WMIConnection;

use crate::modules::core::models::*;
use crate::modules::core::traits::FirmwareInventoryProvider;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_BIOS {
    manufacturer: Option<String>,
    #[serde(rename = "SMBIOSBIOSVersion")]
    smbios_bios_version: Option<String>,
    version: Option<String>,
    release_date: Option<String>,
}

pub struct WindowsFirmwareInventory;

impl FirmwareInventoryProvider for WindowsFirmwareInventory {
    fn collect_firmware_info(&self) -> Collected<FirmwareInfo> {
        let Ok(connection) = WMIConnection::new() else {
            return Collected::failed(FirmwareInfo::default(), "WMI unavailable");
        };
        let Ok(entries) = connection.query::<Win32_BIOS>() else {
            return Collected::failed(FirmwareInfo::default(), "Win32_BIOS query failed");
        };
        let Some(bios) = entries.into_iter().next() else {
            return Collected::failed(FirmwareInfo::default(), "no BIOS record returned");
        };
        let raw_date = bios.release_date.unwrap_or_default();
        let release_date = parse_wmi_datetime(&raw_date);

        // SMBIOSBIOSVersion is the string vendors actually put on their support
        // pages; Version is an internal identifier such as "ALASKA - 1072009".
        let version = bios
            .smbios_bios_version
            .filter(|v| !v.trim().is_empty())
            .or(bios.version)
            .unwrap_or_else(|| "Unknown".to_string());

        Collected::complete(FirmwareInfo {
            vendor: bios.manufacturer.unwrap_or_else(|| "Unknown".to_string()),
            version,
            date: release_date
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| raw_date.clone()),
            release_date,
        })
    }
}

/// Parse the CIM datetime format: `yyyymmddHHMMSS.mmmmmmsUUU`.
pub(crate) fn parse_wmi_datetime(raw: &str) -> Option<DateTime<Utc>> {
    let text = raw.trim();
    if text.len() < 8 || !text[..8].chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let year = text[0..4].parse::<i32>().ok()?;
    let month = text[4..6].parse::<u32>().ok()?;
    let day = text[6..8].parse::<u32>().ok()?;

    let (hour, minute, second) =
        if text.len() >= 14 && text[8..14].chars().all(|c| c.is_ascii_digit()) {
            (
                text[8..10].parse::<u32>().ok()?,
                text[10..12].parse::<u32>().ok()?,
                text[12..14].parse::<u32>().ok()?,
            )
        } else {
            (0, 0, 0)
        };

    Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
        .single()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_cim_datetime_format() {
        let parsed = parse_wmi_datetime("20210810000000.000000+000").expect("must parse");
        assert_eq!(parsed.format("%Y-%m-%d").to_string(), "2021-08-10");
        let with_time = parse_wmi_datetime("20260814221105.000000+000").expect("must parse");
        assert_eq!(
            with_time.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-08-14 22:11:05"
        );

        // Date only.
        assert!(parse_wmi_datetime("20260814").is_some());
    }

    #[test]
    fn rejects_unparseable_dates() {
        assert!(parse_wmi_datetime("").is_none());
        assert!(parse_wmi_datetime("not a date").is_none());
        assert!(parse_wmi_datetime("2026").is_none());
        assert!(parse_wmi_datetime("20261345000000.000000+000").is_none());
    }

    #[test]
    fn firmware_age_is_derived_from_the_parsed_date() {
        let info = FirmwareInfo {
            vendor: "Test".into(),
            version: "1.0".into(),
            date: "2021-08-10".into(),
            release_date: parse_wmi_datetime("20210810000000.000000+000"),
        };
        let age = info.age_years().expect("age must be derivable");
        assert!(age > 4.0, "expected a multi-year age, got {age}");

        // Without a parsed date there is no age, rather than a wrong one.
        let unknown = FirmwareInfo::default();
        assert!(unknown.age_years().is_none());
    }

    #[test]
    fn live_firmware_reports_a_usable_version() {
        let collected = WindowsFirmwareInventory.collect_firmware_info();
        if !collected.status.is_complete() {
            eprintln!("firmware unavailable; skipping");
            return;
        }
        assert!(!collected.value.vendor.is_empty());
        assert!(!collected.value.version.is_empty());
        // The raw CIM string must not leak into the formatted date.
        assert!(!collected.value.date.contains(".000000"));
    }
}
