use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemIdentity {
    pub motherboard_vendor: String,
    pub motherboard_model: String,
    pub cpu_model: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FirmwareInfo {
    pub vendor: String,
    pub version: String,
    pub date: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DriverInfo {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub description: String,
    pub company: String,
    pub hash: String,
    pub base_address: u64,
    pub size: u32,
    pub signed: bool,
    pub is_os_driver: bool,
    pub category: DriverCategory,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum DriverCategory {
    Monitoring,
    Rgb,
    Overclocking,
    Antivirus,
    Network,
    Storage,
    Usb,
    Other,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceState {
    pub name: String,
    pub device_id: String,
    pub problem_code: Option<u32>,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EventRecord {
    pub source: String,
    pub event_id: u32,
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CrashRecord {
    pub timestamp: DateTime<Utc>,
    pub bugcheck_code: String,
    pub parameters: Vec<String>,
    pub faulting_module: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SuspectedCause {
    pub title: String,
    pub score: f32,
    pub confidence: ConfidenceLevel,
    pub evidence: Vec<String>,
    pub explanation: String,
    pub recommendation: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, PartialOrd)]
pub enum ConfidenceLevel {
    Low,
    Moderate,
    High,
    Certain,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceState {
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub exit_code: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemChange {
    pub name: String,
    pub date: DateTime<Utc>,
    pub change_type: String, // "Update", "Software", "Driver"
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiagnosticReport {
    pub system: SystemIdentity,
    pub firmware: FirmwareInfo,
    pub crashes: Vec<CrashRecord>,
    pub drivers: Vec<DriverInfo>,
    pub device_problems: Vec<DeviceState>,
    pub service_problems: Vec<ServiceState>,
    pub recent_changes: Vec<SystemChange>,
    pub suspected_causes: Vec<SuspectedCause>,
    pub timeline: Vec<EventRecord>,
}
