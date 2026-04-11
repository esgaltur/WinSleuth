use windows::Win32::System::EventLog::{
    OpenEventLogW, ReadEventLogW, EVENTLOG_SEQUENTIAL_READ,
    READ_EVENT_LOG_READ_FLAGS, EVENTLOGRECORD, CloseEventLog,
};
use windows::Win32::System::SystemServices::EVENTLOG_BACKWARDS_READ;
use windows::core::HSTRING;
use crate::modules::core::models::EventRecord;
use chrono::{Utc, TimeZone};
use crate::modules::core::traits::EventLogProvider;

pub struct WindowsEventLogReader;

impl EventLogProvider for WindowsEventLogReader {
    fn collect_events(&self) -> Vec<EventRecord> {
        let mut results = Vec::new();
        
        unsafe {
            let log_handle = OpenEventLogW(None, &HSTRING::from("System")).unwrap_or_default();
            if log_handle.is_invalid() {
                return results;
            }

            let mut buffer = vec![0u8; 1024 * 64];
            let mut bytes_read = 0u32;
            let mut bytes_needed = 0u32;

            let flags = READ_EVENT_LOG_READ_FLAGS(EVENTLOG_SEQUENTIAL_READ.0 | EVENTLOG_BACKWARDS_READ);

            while ReadEventLogW(
                log_handle,
                flags,
                0,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_read,
                &mut bytes_needed,
            ).is_ok() {
                let mut pos = 0;
                while pos < bytes_read as usize {
                    let record = &*(buffer.as_ptr().add(pos) as *const EVENTLOGRECORD);
                    
                    let source_ptr = buffer.as_ptr().add(pos + size_of::<EVENTLOGRECORD>()) as *const u16;
                    let mut len = 0;
                    while *source_ptr.add(len) != 0 && len < 256 {
                        len += 1;
                    }
                    let source_name = String::from_utf16_lossy(std::slice::from_raw_parts(source_ptr, len));

                    let timestamp = Utc.timestamp_opt(record.TimeGenerated as i64, 0).unwrap();
                    
                    let mut message = String::new();
                    if record.NumStrings > 0 {
                        let strings_ptr = buffer.as_ptr().add(pos + record.StringOffset as usize) as *const u16;
                        let mut strings_pos = 0;
                        for _ in 0..record.NumStrings {
                            let mut s_len = 0;
                            while *strings_ptr.add(strings_pos + s_len) != 0 {
                                s_len += 1;
                            }
                            let s = String::from_utf16_lossy(std::slice::from_raw_parts(strings_ptr.add(strings_pos), s_len));
                            if !message.is_empty() { message.push_str(" | "); }
                            message.push_str(&s);
                            strings_pos += s_len + 1;
                        }
                    }

                    // Production-grade filtering: more comprehensive event IDs
                    let is_pnp = source_name.contains("Kernel-PnP") && (record.EventID == 400 || record.EventID == 411);
                    let is_disk = source_name.contains("Disk") || source_name.contains("Ntfs") || source_name.contains("Volmgr");
                    let is_critical_disk = is_disk && (record.EventID == 7 || record.EventID == 11 || record.EventID == 51 || record.EventID == 55);
                    let is_crash = record.EventID == 1001 || record.EventID == 41 || record.EventID == 6008;
                    let is_whea = source_name.contains("WHEA-Logger");
                    let is_critical = is_crash || is_whea || (record.EventType.0 & 0x1 != 0); // EVENTLOG_ERROR_TYPE is 1

                    if is_critical || is_pnp || is_critical_disk {
                        results.push(EventRecord {
                            source: source_name,
                            event_id: record.EventID & 0xFFFF, // Low word is the actual ID
                            timestamp,
                            level: format!("{:?}", record.EventType),
                            message,
                        });
                    }

                    pos += record.Length as usize;
                    if pos >= bytes_read as usize { break; }
                }
            }
            
            let _ = CloseEventLog(log_handle);
        }

        results
    }
}
