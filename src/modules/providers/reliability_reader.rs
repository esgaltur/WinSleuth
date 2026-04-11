#![allow(non_camel_case_types)]
use crate::modules::core::models::EventRecord;
use crate::modules::core::traits::EventLogProvider;
use wmi::{WMIConnection, WMIDateTime};
use serde::Deserialize;
use chrono::Utc;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32ReliabilityRecords {
    message: Option<String>,
    source_name: String,
    time_generated: WMIDateTime,
    event_identifier: u32,
}

pub struct WindowsReliabilityReader;

impl EventLogProvider for WindowsReliabilityReader {
    fn collect_events(&self) -> Vec<EventRecord> {
        let mut records = Vec::new();

        if let Ok(wmi_con) = WMIConnection::new() {
            let query = "SELECT Message, SourceName, TimeGenerated, EventIdentifier FROM Win32_ReliabilityRecords";
            if let Ok(rel_records) = wmi_con.raw_query::<Win32ReliabilityRecords>(query) {
                for record in rel_records.into_iter().take(100) {
                    records.push(EventRecord {
                        source: record.source_name,
                        event_id: record.event_identifier,
                        timestamp: record.time_generated.0.with_timezone(&Utc),
                        level: "Reliability".to_string(),
                        message: record.message.unwrap_or_default(),
                    });
                }
            }
        }

        records
    }
}
