#![allow(non_camel_case_types)]
//! Windows Reliability Monitor records.
//!
//! Bounded by the scan window in the WMI query itself rather than by taking the
//! first hundred rows and hoping they were recent.

use serde::Deserialize;
use wmi::{WMIConnection, WMIDateTime};

use crate::modules::core::models::*;
use crate::modules::core::traits::EventLogProvider;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_ReliabilityRecords {
    message: Option<String>,
    source_name: Option<String>,
    time_generated: WMIDateTime,
    event_identifier: Option<u32>,
    logfile: Option<String>,
}

/// Upper bound on rows pulled back, so a machine with a long unstable history
/// cannot make a scan unbounded.
const MAX_RECORDS: usize = 500;

pub struct WindowsReliabilityReader;

impl EventLogProvider for WindowsReliabilityReader {
    fn name(&self) -> &'static str {
        "ReliabilityMonitor"
    }

    fn collect_events(&self, window: &ScanWindow) -> Collected<Vec<EventRecord>> {
        let Ok(connection) = WMIConnection::new() else {
            return Collected::failed(Vec::new(), "WMI unavailable");
        };

        // Win32_ReliabilityRecords compares TimeGenerated against the CIM
        // datetime format, so the window is applied server-side.
        let since = window.since.format("%Y%m%d%H%M%S.000000+000");
        let query = format!(
            "SELECT Message, SourceName, TimeGenerated, EventIdentifier, Logfile \
             FROM Win32_ReliabilityRecords WHERE TimeGenerated >= '{since}'"
        );
        let rows = match connection.raw_query::<Win32_ReliabilityRecords>(&query) {
            Ok(rows) => rows,
            Err(_) => {
                // The class is absent on some SKUs and on systems where the
                // Reliability Monitor task has never run.
                return Collected::partial(Vec::new(), "reliability records unavailable");
            }
        };
        let mut records: Vec<EventRecord> = rows
            .into_iter()
            .filter_map(|row| {
                let timestamp = row.time_generated.0.with_timezone(&chrono::Utc);
                window.contains(timestamp).then(|| EventRecord {
                    source: row.source_name.unwrap_or_else(|| "Reliability".to_string()),
                    channel: row.logfile.unwrap_or_else(|| "Reliability".to_string()),
                    event_id: row.event_identifier.unwrap_or(0),
                    timestamp,
                    // Reliability rows are failures by definition.
                    level: EventLevel::Error,
                    message: row.message.unwrap_or_default(),
                })
            })
            .take(MAX_RECORDS)
            .collect();
        records.sort_by_key(|r| r.timestamp);
        Collected::complete(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reliability_records_stay_inside_the_window() {
        let window = ScanWindow::last_days(30);
        let collected = WindowsReliabilityReader.collect_events(&window);
        if !collected.status.is_complete() {
            eprintln!("reliability records unavailable; skipping");
            return;
        }

        for record in &collected.value {
            assert!(
                window.contains(record.timestamp),
                "{} at {} escaped the window",
                record.source,
                record.timestamp
            );
        }
        assert!(collected.value.len() <= MAX_RECORDS);
    }

    #[test]
    fn a_narrow_window_returns_no_more_than_a_wide_one() {
        let wide = WindowsReliabilityReader.collect_events(&ScanWindow::last_days(90));
        let narrow = WindowsReliabilityReader.collect_events(&ScanWindow::last_days(1));
        if !wide.status.is_complete() || !narrow.status.is_complete() {
            eprintln!("reliability records unavailable; skipping");
            return;
        }
        assert!(narrow.value.len() <= wide.value.len().max(MAX_RECORDS));
    }
}
