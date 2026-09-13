//! Crash correlation.
//!
//! The previous implementation built a filtered subset of the timeline and then
//! *overwrote* `report.timeline` with it. Every rule runs afterwards, so
//! `DiskErrorRule`, `DeviceReEnumerationRule` and `ReliabilityScoreRule`
//! silently evaluated against a truncated log — and they under-reported
//! precisely on machines that had crashed, the only machines anyone runs this
//! on.
//!
//! Correlation now produces `CrashWindow`s *alongside* the timeline. The
//! timeline stays the immutable record of what was collected.

use std::collections::HashSet;

use chrono::Duration;

use crate::modules::core::models::*;

/// How far either side of a crash to gather context.
const WINDOW_MINUTES: i64 = 5;

/// Build one `CrashWindow` per crash, plus one for each crash marker in the log
/// that has no corresponding dump.
pub fn correlate(report: &DiagnosticReport) -> Vec<CrashWindow> {
    // Only system crashes get a correlation window. A user-mode application
    // dump is not the machine going down and does not deserve one.
    let mut windows: Vec<CrashWindow> = report
        .crashes
        .iter()
        .filter(|crash| crash.source.is_system_crash())
        .map(|crash| build_window(crash.clone(), &report.timeline))
        .collect();

    // A machine can lose power or bugcheck without leaving a readable dump. The
    // event log still marks it, and that is worth correlating.
    for event in report.timeline.iter().filter(|e| e.is_crash_marker()) {
        let already_covered = windows
            .iter()
            .any(|w| (w.crash.timestamp - event.timestamp).num_minutes().abs() <= WINDOW_MINUTES);
        if already_covered {
            continue;
        }

        let crash = CrashRecord {
            timestamp: event.timestamp,
            bugcheck_code: 0,
            bugcheck_name: if event.is_bugcheck() {
                "BUGCHECK (no dump available)".to_string()
            } else {
                "UNEXPECTED_SHUTDOWN".to_string()
            },
            parameters: [0; 4],
            faulting_module: None,
            faulting_address: None,
            attribution: CrashAttribution::Undetermined,
            dump_path: String::new(),
            source: CrashSource::EventLog,
        };
        windows.push(build_window(crash, &report.timeline));
    }

    windows.sort_by_key(|w| std::cmp::Reverse(w.crash.timestamp));
    windows
}

fn build_window(crash: CrashRecord, timeline: &[EventRecord]) -> CrashWindow {
    let span = Duration::minutes(WINDOW_MINUTES);
    let mut preceding = Vec::new();
    let mut following = Vec::new();
    let mut seen = HashSet::new();

    for event in timeline {
        if !seen.insert(event.dedup_key()) {
            continue;
        }
        let delta = event.timestamp - crash.timestamp;
        if delta > span || delta < -span {
            continue;
        }
        if event.timestamp <= crash.timestamp {
            preceding.push(event.clone());
        } else {
            following.push(event.clone());
        }
    }

    // Nearest-first: the event immediately before a crash is the interesting one.
    preceding.sort_by_key(|e| std::cmp::Reverse(e.timestamp));
    following.sort_by_key(|e| e.timestamp);

    CrashWindow {
        crash,
        window_minutes: WINDOW_MINUTES,
        preceding,
        following,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn event(
        source: &str,
        id: u32,
        offset_minutes: i64,
        base: chrono::DateTime<Utc>,
    ) -> EventRecord {
        EventRecord {
            source: source.into(),
            channel: "System".into(),
            event_id: id,
            timestamp: base + Duration::minutes(offset_minutes),
            level: EventLevel::Error,
            message: String::new(),
        }
    }

    fn crash(base: chrono::DateTime<Utc>) -> CrashRecord {
        CrashRecord {
            timestamp: base,
            bugcheck_code: 0xD1,
            bugcheck_name: "DRIVER_IRQL_NOT_LESS_OR_EQUAL".into(),
            parameters: [0; 4],
            faulting_module: None,
            faulting_address: None,
            attribution: CrashAttribution::Undetermined,
            dump_path: "C:\\Windows\\Minidump\\a.dmp".into(),
            source: CrashSource::KernelDump,
        }
    }

    #[test]
    fn correlation_leaves_the_timeline_untouched() {
        let base = Utc::now();
        let mut report = DiagnosticReport::empty(ScanWindow::last_days(7));
        report.crashes = vec![crash(base)];
        report.timeline = vec![
            event("Disk", 7, -1, base),
            event("Ntfs", 55, -600, base), // far outside the window
            event("WHEA-Logger", 17, 2, base),
        ];
        let before = report.timeline.len();
        let windows = correlate(&report);
        assert_eq!(
            report.timeline.len(),
            before,
            "the timeline must not be mutated"
        );
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].preceding.len(), 1);
        assert_eq!(windows[0].following.len(), 1);
        // The distant event is excluded from the window but still in the timeline.
        assert!(report.timeline.iter().any(|e| e.source == "Ntfs"));
    }

    #[test]
    fn events_are_not_duplicated_across_multiple_crashes() {
        let base = Utc::now();
        let mut report = DiagnosticReport::empty(ScanWindow::last_days(7));
        // Two crashes an hour apart, so their windows do not overlap.
        report.crashes = vec![crash(base), crash(base - Duration::hours(1))];
        report.timeline = vec![event("Disk", 7, -1, base)];
        let windows = correlate(&report);
        assert_eq!(windows.len(), 2);
        let total: usize = windows
            .iter()
            .map(|w| w.preceding.len() + w.following.len())
            .sum();
        assert_eq!(total, 1, "one event must not be copied into both windows");
    }

    #[test]
    fn identical_events_within_one_window_are_collapsed() {
        let base = Utc::now();
        let mut report = DiagnosticReport::empty(ScanWindow::last_days(7));
        report.crashes = vec![crash(base)];
        // The same record arriving from two channels.
        report.timeline = vec![event("Disk", 7, -1, base), event("Disk", 7, -1, base)];
        let windows = correlate(&report);
        assert_eq!(windows[0].preceding.len(), 1);
    }

    #[test]
    fn crash_markers_without_a_dump_still_produce_a_window() {
        let base = Utc::now();
        let mut report = DiagnosticReport::empty(ScanWindow::last_days(7));
        report.timeline = vec![
            EventRecord {
                source: "Microsoft-Windows-Kernel-Power".into(),
                channel: "System".into(),
                event_id: 41,
                timestamp: base,
                level: EventLevel::Critical,
                message: String::new(),
            },
            event("Disk", 7, -2, base),
        ];
        let windows = correlate(&report);
        assert_eq!(
            windows.len(),
            1,
            "a Kernel-Power 41 with no dump must be correlated"
        );
        assert_eq!(windows[0].crash.source, CrashSource::EventLog);
        assert_eq!(windows[0].crash.bugcheck_name, "UNEXPECTED_SHUTDOWN");
        assert_eq!(windows[0].preceding.len(), 2);
    }

    #[test]
    fn a_log_marker_matching_a_dump_does_not_create_a_second_window() {
        let base = Utc::now();
        let mut report = DiagnosticReport::empty(ScanWindow::last_days(7));
        report.crashes = vec![crash(base)];
        report.timeline = vec![EventRecord {
            source: "Microsoft-Windows-WER-SystemErrorReporting".into(),
            channel: "System".into(),
            event_id: 1001,
            timestamp: base + Duration::minutes(1),
            level: EventLevel::Error,
            message: String::new(),
        }];
        let windows = correlate(&report);
        assert_eq!(
            windows.len(),
            1,
            "the dump and its log marker are one crash"
        );
    }

    #[test]
    fn a_clean_machine_correlates_to_nothing() {
        let report = DiagnosticReport::empty(ScanWindow::last_days(7));
        assert!(correlate(&report).is_empty());
    }
}
