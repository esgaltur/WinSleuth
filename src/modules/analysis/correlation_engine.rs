use crate::modules::core::models::DiagnosticReport;

pub fn correlate_events(report: &mut DiagnosticReport) {
    // Basic correlation: Identify event bursts around crashes
    let mut correlated_events = Vec::new();

    for crash in &report.crashes {
        // Find events that happened within 5 minutes before or after the crash
        for event in &report.timeline {
            let time_diff = crash.timestamp.signed_duration_since(event.timestamp).num_minutes().abs();
            if time_diff <= 5 {
                correlated_events.push(event.clone());
            }
        }
    }

    // Add back WHEA and critical Kernel-Power events regardless of crash time
    for event in &report.timeline {
        if event.source.contains("WHEA") || event.event_id == 41 || event.event_id == 1001 {
            correlated_events.push(event.clone());
        }
    }

    // Sort to prepare for deduplication
    correlated_events.sort_by_key(|e| e.timestamp);
    
    // De-duplicate based on timestamp and event_id
    correlated_events.dedup_by(|a, b| a.timestamp == b.timestamp && a.event_id == b.event_id);

    if !correlated_events.is_empty() {
        report.timeline = correlated_events;
    }
}
