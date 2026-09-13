//! Event log collection via the modern Windows Event Log API.
//!
//! The previous implementation used `ReadEventLogW`, the pre-Vista API. That
//! had three consequences: only the three legacy logs were reachable, so every
//! `Microsoft-Windows-*` channel was invisible; there was no server-side
//! filtering, so each call walked the entire System log (and `monitor` did that
//! every five seconds); and insertion strings were concatenated raw, producing
//! messages like `"1 | 4 | 0x0"` instead of prose.
//!
//! `EvtQuery` fixes all three. The XPath predicate bounds the query by time at
//! the server, which is also what makes `--days` mean something, and
//! `EvtFormatMessage` renders the provider's real message text.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EvtClose, EvtFormatMessage, EvtFormatMessageEvent, EvtNext,
    EvtOpenPublisherMetadata, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
    EvtQueryTolerateQueryErrors, EvtRender, EvtRenderEventXml,
};
use windows::core::HSTRING;

use crate::modules::core::models::*;
use crate::modules::core::traits::EventLogProvider;

/// A channel to query, with the level predicate appropriate to it.
struct ChannelSpec {
    path: &'static str,
    /// XPath level clause, or empty to accept every level.
    levels: &'static str,
    /// Upper bound on records taken from this channel, newest first.
    cap: usize,
}

const CHANNELS: &[ChannelSpec] = &[
    // Critical, Error and Warning. Warnings matter here because disk and PnP
    // problems are frequently logged as warnings.
    ChannelSpec {
        path: "System",
        levels: "(Level=1 or Level=2 or Level=3)",
        cap: 4000,
    },
    ChannelSpec {
        path: "Application",
        levels: "(Level=1 or Level=2)",
        cap: 1500,
    },
    // Modern channels the legacy API could not see at all.
    ChannelSpec {
        path: "Microsoft-Windows-Kernel-PnP/Configuration",
        levels: "",
        cap: 1500,
    },
    ChannelSpec {
        path: "Microsoft-Windows-WHEA-Logger/Errors",
        levels: "",
        cap: 500,
    },
    ChannelSpec {
        path: "Microsoft-Windows-StorDiag/Operational",
        levels: "",
        cap: 500,
    },
    ChannelSpec {
        path: "Microsoft-Windows-Kernel-Power/Thermal-Operational",
        levels: "",
        cap: 500,
    },
];

/// Number of event handles fetched per `EvtNext` call.
const BATCH: usize = 64;

pub struct WindowsEventLogReader {
    /// Publisher metadata handles are expensive to open and are reused across
    /// every event from the same provider.
    metadata_cache: Mutex<HashMap<String, isize>>,
}

impl WindowsEventLogReader {
    pub fn new() -> Self {
        Self {
            metadata_cache: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for WindowsEventLogReader {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WindowsEventLogReader {
    fn drop(&mut self) {
        if let Ok(cache) = self.metadata_cache.lock() {
            for handle in cache.values() {
                if *handle != 0 {
                    unsafe {
                        let _ = EvtClose(EVT_HANDLE(*handle));
                    }
                }
            }
        }
    }
}

impl EventLogProvider for WindowsEventLogReader {
    fn name(&self) -> &'static str {
        "EventLog"
    }

    fn collect_events(&self, window: &ScanWindow) -> Collected<Vec<EventRecord>> {
        let mut records = Vec::new();
        let mut unavailable: Vec<&str> = Vec::new();
        for spec in CHANNELS {
            match self.query_channel(spec, window) {
                Ok(mut events) => records.append(&mut events),
                Err(_) => unavailable.push(spec.path),
            }
        }

        // One event can legitimately arrive from two channels; keep one copy.
        let mut seen = std::collections::HashSet::new();
        records.retain(|r| seen.insert(r.dedup_key()));
        records.sort_by_key(|r| r.timestamp);

        // "System" going missing means the scan is blind; a specialised channel
        // being absent on this SKU is normal.
        let status = if unavailable.contains(&"System") {
            CollectionStatus::Failed {
                reason: "the System event log could not be queried (Administrator required)".into(),
            }
        } else if unavailable.is_empty() {
            CollectionStatus::Complete
        } else {
            CollectionStatus::Partial {
                reason: format!(
                    "channels not present on this system: {}",
                    unavailable.join(", ")
                ),
            }
        };

        Collected {
            value: records,
            status,
        }
    }
}

impl WindowsEventLogReader {
    fn query_channel(
        &self,
        spec: &ChannelSpec,
        window: &ScanWindow,
    ) -> Result<Vec<EventRecord>, windows::core::Error> {
        let query = build_query(spec.levels, window);
        let channel_w = HSTRING::from(spec.path);
        let query_w = HSTRING::from(query.as_str());
        let handle = unsafe {
            EvtQuery(
                None,
                &channel_w,
                &query_w,
                // Reverse direction gives newest first, so a cap keeps the most
                // relevant records rather than the oldest ones.
                (EvtQueryChannelPath.0 | EvtQueryReverseDirection.0 | EvtQueryTolerateQueryErrors.0)
                    as u32,
            )?
        };
        let mut records = Vec::new();
        let mut buffer = vec![0u16; 16 * 1024];

        'outer: loop {
            let mut events = [0isize; BATCH];
            let mut returned = 0u32;
            let more = unsafe { EvtNext(handle, &mut events, 0, 0, &mut returned).is_ok() };
            if !more || returned == 0 {
                break;
            }

            for slot in events.iter().take(returned as usize) {
                let event = EVT_HANDLE(*slot);
                if let Some(xml) = render_xml(event, &mut buffer)
                    && let Some(parsed) = parse_event_xml(&xml)
                    && window.contains(parsed.timestamp)
                {
                    let message = self
                        .format_message(event, &parsed.provider)
                        .unwrap_or_else(|| parsed.data.join(" | "));
                    records.push(EventRecord {
                        source: parsed.provider,
                        channel: if parsed.channel.is_empty() {
                            spec.path.to_string()
                        } else {
                            parsed.channel
                        },
                        event_id: parsed.event_id,
                        timestamp: parsed.timestamp,
                        level: EventLevel::from_win32(parsed.level),
                        message,
                    });
                }
                unsafe {
                    let _ = EvtClose(event);
                }

                if records.len() >= spec.cap {
                    break 'outer;
                }
            }
        }

        unsafe {
            let _ = EvtClose(handle);
        }
        Ok(records)
    }

    /// Render the provider's real message text, the thing the legacy API could
    /// not do.
    fn format_message(&self, event: EVT_HANDLE, provider: &str) -> Option<String> {
        let metadata = self.publisher_metadata(provider)?;
        let mut needed = 0u32;
        unsafe {
            // First call reports the required buffer length.
            let _ = EvtFormatMessage(
                Some(EVT_HANDLE(metadata)),
                Some(event),
                0,
                None,
                EvtFormatMessageEvent.0,
                None,
                &mut needed,
            );
            if needed == 0 || needed > 64 * 1024 {
                return None;
            }

            let mut buffer = vec![0u16; needed as usize];
            EvtFormatMessage(
                Some(EVT_HANDLE(metadata)),
                Some(event),
                0,
                None,
                EvtFormatMessageEvent.0,
                Some(&mut buffer),
                &mut needed,
            )
            .ok()?;
            let text = String::from_utf16_lossy(&buffer[..(needed as usize).saturating_sub(1)]);
            let text = text.trim().replace(['\r', '\n'], " ");
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            (!text.is_empty()).then_some(text)
        }
    }

    fn publisher_metadata(&self, provider: &str) -> Option<isize> {
        let mut cache = self.metadata_cache.lock().ok()?;
        if let Some(handle) = cache.get(provider) {
            return (*handle != 0).then_some(*handle);
        }

        let provider_w = HSTRING::from(provider);
        let handle = unsafe { EvtOpenPublisherMetadata(None, &provider_w, None, 0, 0) }
            .map(|h| h.0)
            .unwrap_or(0);
        cache.insert(provider.to_string(), handle);
        (handle != 0).then_some(handle)
    }
}

/// Build the XPath predicate. `timediff` bounds the query at the server, so the
/// scan window is honoured before any record crosses the API boundary.
fn build_query(levels: &str, window: &ScanWindow) -> String {
    let millis = (window.until - window.since).num_milliseconds().max(1);
    if levels.is_empty() {
        format!("*[System[TimeCreated[timediff(@SystemTime) <= {millis}]]]")
    } else {
        format!("*[System[{levels} and TimeCreated[timediff(@SystemTime) <= {millis}]]]")
    }
}

fn render_xml(event: EVT_HANDLE, buffer: &mut Vec<u16>) -> Option<String> {
    unsafe {
        let mut used = 0u32;
        let mut properties = 0u32;
        let byte_capacity = (buffer.len() * 2) as u32;
        let ok = EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            byte_capacity,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut used,
            &mut properties,
        )
        .is_ok();
        if !ok {
            // `used` now holds the required size in bytes; grow and retry once.
            if used == 0 || used > 4 * 1024 * 1024 {
                return None;
            }
            buffer.resize((used as usize / 2) + 1, 0);
            EvtRender(
                None,
                event,
                EvtRenderEventXml.0,
                (buffer.len() * 2) as u32,
                Some(buffer.as_mut_ptr() as *mut _),
                &mut used,
                &mut properties,
            )
            .ok()?;
        }

        let chars = (used as usize / 2).min(buffer.len());
        let text = String::from_utf16_lossy(&buffer[..chars]);
        Some(text.trim_end_matches('\0').to_string())
    }
}

// ---------------------------------------------------------------------------
// XML extraction
//
// Pure functions over the fixed Event schema, so they are testable without
// Windows in the loop.
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub(crate) struct ParsedEvent {
    pub provider: String,
    pub channel: String,
    pub event_id: u32,
    pub level: u32,
    pub timestamp: DateTime<Utc>,
    pub data: Vec<String>,
}

/// Turn rendered event XML straight into an `EventRecord`. Used by the live
/// monitor, which has no publisher metadata cache to render prose messages with
/// and falls back to the event's own data values.
pub fn parse_into_record(xml: &str) -> Option<EventRecord> {
    let parsed = parse_event_xml(xml)?;
    Some(EventRecord {
        source: parsed.provider,
        channel: parsed.channel,
        event_id: parsed.event_id,
        timestamp: parsed.timestamp,
        level: EventLevel::from_win32(parsed.level),
        message: parsed.data.join(" | "),
    })
}

pub(crate) fn parse_event_xml(xml: &str) -> Option<ParsedEvent> {
    let provider = attribute_of_element(xml, "Provider", "Name").unwrap_or_default();
    let system_time = attribute_of_element(xml, "TimeCreated", "SystemTime")?;
    let timestamp = system_time.parse::<DateTime<Utc>>().ok()?;

    let event_id = element_text(xml, "EventID")?.trim().parse::<u32>().ok()?;
    let level = element_text(xml, "Level")
        .and_then(|t| t.trim().parse::<u32>().ok())
        .unwrap_or(4);
    let channel = element_text(xml, "Channel").unwrap_or_default();

    Some(ParsedEvent {
        provider,
        channel,
        event_id,
        level,
        timestamp,
        data: data_values(xml),
    })
}

/// Read `attr` from `<name ... attr="value" .../>`.
fn attribute_of_element(xml: &str, element: &str, attribute: &str) -> Option<String> {
    let open = format!("<{element}");
    let start = xml.find(&open)?;
    let rest = &xml[start..];
    let end = rest.find('>')?;
    let tag = &rest[..end];

    let needle = format!("{attribute}=\"");
    let attr_start = tag.find(&needle)? + needle.len();
    let attr_end = tag[attr_start..].find('"')? + attr_start;
    Some(tag[attr_start..attr_end].to_string())
}

/// Read the text of `<name ...>text</name>`, tolerating attributes on the tag.
fn element_text(xml: &str, element: &str) -> Option<String> {
    let open = format!("<{element}");
    let start = xml.find(&open)?;
    let rest = &xml[start..];
    let content_start = rest.find('>')? + 1;
    // Self-closing element carries no text.
    if rest[..content_start].ends_with("/>") {
        return None;
    }
    let close = format!("</{element}>");
    let content_end = rest[content_start..].find(&close)? + content_start;
    Some(unescape(&rest[content_start..content_end]))
}

/// Collect `<Data>` values so a message is still available when the provider's
/// message resource is missing.
fn data_values(xml: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut cursor = 0usize;

    while let Some(found) = xml[cursor..].find("<Data") {
        let start = cursor + found;
        let Some(open_end) = xml[start..].find('>') else {
            break;
        };
        let content_start = start + open_end + 1;
        if xml[start..content_start].ends_with("/>") {
            cursor = content_start;
            continue;
        }
        let Some(close) = xml[content_start..].find("</Data>") else {
            break;
        };
        let content_end = content_start + close;
        let value = unescape(&xml[content_start..content_end]);
        if !value.trim().is_empty() {
            values.push(value);
        }
        cursor = content_end + "</Data>".len();
    }

    values
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUGCHECK_XML: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-WER-SystemErrorReporting" Guid="{abc}" EventSourceName="BugCheck"/>
<EventID Qualifiers="16384">1001</EventID><Version>0</Version><Level>2</Level><Task>0</Task>
<TimeCreated SystemTime="2026-08-14T22:11:05.1234567Z"/><EventRecordID>90210</EventRecordID>
<Channel>System</Channel><Computer>WORKBENCH</Computer><Security/></System>
<EventData><Data>0x000000d1 (0xfffff80312345678, 0x0000000000000002, 0x0000000000000000, 0xfffff8031234abcd)</Data>
<Data>C:\Windows\Minidump\081426-9109-01.dmp</Data><Data>be1c8b1e</Data></EventData></Event>"#;

    #[test]
    fn parses_a_real_bugcheck_event() {
        let parsed = parse_event_xml(BUGCHECK_XML).expect("must parse");
        assert_eq!(
            parsed.provider,
            "Microsoft-Windows-WER-SystemErrorReporting"
        );
        assert_eq!(
            parsed.event_id, 1001,
            "Qualifiers must not be mistaken for the ID"
        );
        assert_eq!(parsed.level, 2);
        assert_eq!(parsed.channel, "System");
        assert_eq!(
            parsed.timestamp.to_rfc3339(),
            "2026-08-14T22:11:05.123456700+00:00"
        );
        assert_eq!(parsed.data.len(), 3);
        assert!(parsed.data[0].starts_with("0x000000d1"));
    }

    #[test]
    fn handles_self_closing_and_escaped_content() {
        let xml = r#"<Event><System><Provider Name="Disk"/><EventID>7</EventID><Level>3</Level>
<TimeCreated SystemTime="2026-09-01T00:00:00.0000000Z"/><Channel>System</Channel><Security/></System>
<EventData><Data>\Device\Harddisk0 &amp; bad block</Data><Data/></EventData></Event>"#;
        let parsed = parse_event_xml(xml).expect("must parse");
        assert_eq!(parsed.provider, "Disk");
        assert_eq!(parsed.event_id, 7);
        assert_eq!(parsed.level, 3);
        // The empty self-closing <Data/> must not become an empty string entry.
        assert_eq!(parsed.data, vec![r"\Device\Harddisk0 & bad block"]);
    }

    #[test]
    fn rejects_xml_without_the_fields_it_needs() {
        assert!(parse_event_xml("<Event><System/></Event>").is_none());
        assert!(parse_event_xml("not xml at all").is_none());
        // A malformed timestamp must not be silently treated as "now".
        let bad_time = r#"<Event><System><Provider Name="X"/><EventID>1</EventID>
<TimeCreated SystemTime="whenever"/></System></Event>"#;
        assert!(parse_event_xml(bad_time).is_none());
    }

    #[test]
    fn query_bounds_by_time_at_the_server() {
        let window = ScanWindow::last_days(7);
        let query = build_query("(Level=1 or Level=2)", &window);
        assert!(
            query.contains("timediff(@SystemTime) <="),
            "must filter server-side: {query}"
        );
        assert!(query.contains("Level=1"));
        // Seven days in milliseconds.
        assert!(query.contains(&604_800_000u64.to_string()), "got {query}");
        let unfiltered = build_query("", &window);
        assert!(!unfiltered.contains("Level"));
        assert!(unfiltered.contains("timediff"));
    }

    #[test]
    fn different_windows_produce_different_queries() {
        // The regression that made --days a no-op.
        let a = build_query("", &ScanWindow::last_days(1));
        let b = build_query("", &ScanWindow::last_days(30));
        assert_ne!(a, b);
    }

    /// Exercises the real API against this machine's own logs.
    #[test]
    fn live_query_respects_the_window() {
        let reader = WindowsEventLogReader::new();
        let window = ScanWindow::last_days(30);
        let collected = reader.collect_events(&window);
        if let CollectionStatus::Failed { reason } = &collected.status {
            eprintln!("event log unavailable ({reason}); skipping");
            return;
        }

        for event in &collected.value {
            assert!(
                window.contains(event.timestamp),
                "{} at {} escaped the scan window",
                event.source,
                event.timestamp
            );
        }

        // A narrower window must never return more than a wider one.
        let narrow = reader.collect_events(&ScanWindow::last_days(1));
        assert!(narrow.value.len() <= collected.value.len());
    }
}
