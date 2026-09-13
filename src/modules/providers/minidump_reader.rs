//! Crash dump analysis.
//!
//! Replaces the previous provider, which opened each dump, read nothing, and
//! returned the literal string `"Analysis Pending (In Progress)"` as the
//! bugcheck code with the dump's own filename as the faulting module.
//!
//! Two dump formats matter and they are not the same thing:
//!
//! * **Kernel dumps** (`C:\Windows\Minidump\*.dmp`, `MEMORY.DMP`) begin with a
//!   `DUMP_HEADER` — *not* the `MDMP` container. The bugcheck code and its four
//!   parameters sit at documented offsets, which is where the stop code comes
//!   from.
//! * **User-mode dumps** (`%LOCALAPPDATA%\CrashDumps\*.dmp`) are real MDMP
//!   containers carrying a module list and an exception record, so the faulting
//!   address can be resolved against the modules *recorded in the dump itself*.
//!
//! x64 small kernel dumps carry a saved driver table. Attribution uses those
//! crash-time image ranges, so it works after reboot and driver removal. Other
//! kernel dump layouts still yield stop codes but remain unattributed. Current
//! driver addresses are never a fallback: file timestamps cannot prove that a
//! dump came from this boot (copying a dump can change its modification time).

mod triage;

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use minidump::{Minidump, MinidumpException, MinidumpModuleList, MinidumpSystemInfo, Module};

use crate::modules::analysis::bugcheck;
use crate::modules::core::models::*;
use crate::modules::core::traits::MinidumpProvider;

const KERNEL_DUMP_DIR: &str = "C:\\Windows\\Minidump";
const FULL_DUMP_PATH: &str = "C:\\Windows\\MEMORY.DMP";

/// `PAGE` — the first dword of every kernel crash dump.
const DUMP_SIGNATURE: u32 = 0x4547_4150;
/// `DU64` — 64-bit kernel dump.
const DUMP_VALID64: u32 = 0x3436_5544;
/// `DUMP` — 32-bit kernel dump.
const DUMP_VALID32: u32 = 0x504D_5544;

/// Offsets inside `DUMP_HEADER64`.
const BUGCHECK_CODE_OFFSET_64: usize = 0x38;
const BUGCHECK_PARAMS_OFFSET_64: usize = 0x40;
/// Offsets inside `DUMP_HEADER32`.
const BUGCHECK_CODE_OFFSET_32: usize = 0x28;
const BUGCHECK_PARAMS_OFFSET_32: usize = 0x2C;

/// Enough of the header to reach the bugcheck parameters.
const HEADER_PREFIX: usize = 0x100;

pub struct WindowsMinidumpReader;

impl WindowsMinidumpReader {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsMinidumpReader {
    fn default() -> Self {
        Self::new()
    }
}

impl MinidumpProvider for WindowsMinidumpReader {
    fn parse_minidumps(
        &self,
        window: &ScanWindow,
        modules: &[DriverInfo],
    ) -> Collected<Vec<CrashRecord>> {
        let mut records = Vec::new();
        let mut unreadable = 0usize;
        let mut attribution_errors = std::collections::BTreeMap::<&str, usize>::new();
        let mut candidates: Vec<PathBuf> = Vec::new();
        let mut dir_error = None;
        match fs::read_dir(KERNEL_DUMP_DIR) {
            Ok(entries) => {
                for entry in entries.filter_map(Result::ok) {
                    let path = entry.path();
                    if path
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("dmp"))
                    {
                        candidates.push(path);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                dir_error = Some("crash dump directory requires Administrator".to_string());
            }
            Err(_) => {
                // A missing directory simply means the machine has not crashed.
            }
        }

        if Path::new(FULL_DUMP_PATH).exists() {
            candidates.push(PathBuf::from(FULL_DUMP_PATH));
        }
        candidates.extend(user_dump_paths());
        for path in candidates {
            let timestamp = match file_time(&path) {
                Some(t) => t,
                None => continue,
            };
            if !window.contains(timestamp) {
                continue;
            }

            match self.analyse(&path, timestamp, modules) {
                Some((record, warning)) => {
                    records.push(record);
                    if let Some(reason) = warning {
                        *attribution_errors.entry(reason).or_default() += 1;
                    }
                }
                None => unreadable += 1,
            }
        }

        records.sort_by_key(|r| std::cmp::Reverse(r.timestamp));
        let mut warnings: Vec<String> = dir_error.into_iter().collect();
        if unreadable > 0 {
            warnings.push(format!("{unreadable} dump file(s) could not be parsed"));
        }
        for (reason, count) in attribution_errors {
            warnings.push(format!("{count} dump(s): {reason}"));
        }
        let status = if warnings.is_empty() {
            CollectionStatus::Complete
        } else {
            CollectionStatus::Partial {
                reason: warnings.join("; "),
            }
        };

        Collected {
            value: records,
            status,
        }
    }
}

impl WindowsMinidumpReader {
    fn analyse(
        &self,
        path: &Path,
        timestamp: DateTime<Utc>,
        _modules: &[DriverInfo],
    ) -> Option<(CrashRecord, Option<&'static str>)> {
        let display = path.to_string_lossy().to_string();
        let mut file = fs::File::open(path).ok()?;
        let prefix = read_prefix(&mut file, HEADER_PREFIX)?;
        if let Some((code, parameters)) = parse_kernel_header(&prefix) {
            let address = bugcheck::culprit_address(code, &parameters);
            let (attribution, warning) = if let Some(address) = address {
                match triage::read_modules(&mut file) {
                    Ok(modules) => (attribute_kernel(address, &modules), None),
                    Err(reason) => (CrashAttribution::Undetermined, Some(reason)),
                }
            } else {
                (CrashAttribution::Undetermined, None)
            };
            return Some((
                CrashRecord {
                    timestamp,
                    bugcheck_code: code,
                    bugcheck_name: bugcheck::name(code).to_string(),
                    parameters,
                    faulting_module: attribution.module().map(str::to_owned),
                    faulting_address: address,
                    attribution,
                    dump_path: display,
                    source: CrashSource::KernelDump,
                },
                warning,
            ));
        }

        // Not a kernel dump — try the user-mode container.
        analyse_user_dump(path, timestamp).map(|record| (record, None))
    }
}

fn attribute_kernel(address: u64, modules: &[triage::DumpModule]) -> CrashAttribution {
    let mut matches = modules.iter().filter(|m| m.contains(address));
    match (matches.next(), matches.next()) {
        (Some(module), None) => CrashAttribution::DumpModuleRange {
            module: module.name.clone(),
            base_address: module.base,
            size: module.size,
        },
        _ => CrashAttribution::Undetermined,
    }
}

/// Parse `DUMP_HEADER`. Returns the bugcheck code and its four parameters, or
/// `None` when this is not a kernel crash dump.
fn parse_kernel_header(bytes: &[u8]) -> Option<(u32, [u64; 4])> {
    if bytes.len() < HEADER_PREFIX {
        return None;
    }
    if read_u32(bytes, 0)? != DUMP_SIGNATURE {
        return None;
    }

    match read_u32(bytes, 4)? {
        DUMP_VALID64 => {
            let code = read_u32(bytes, BUGCHECK_CODE_OFFSET_64)?;
            let mut parameters = [0u64; 4];
            for (i, slot) in parameters.iter_mut().enumerate() {
                *slot = read_u64(bytes, BUGCHECK_PARAMS_OFFSET_64 + i * 8)?;
            }
            Some((code, parameters))
        }
        DUMP_VALID32 => {
            let code = read_u32(bytes, BUGCHECK_CODE_OFFSET_32)?;
            let mut parameters = [0u64; 4];
            for (i, slot) in parameters.iter_mut().enumerate() {
                *slot = read_u32(bytes, BUGCHECK_PARAMS_OFFSET_32 + i * 4)? as u64;
            }
            Some((code, parameters))
        }
        _ => None,
    }
}

/// Analyse a user-mode MDMP container. These carry their own module list, so
/// the faulting address resolves without any same-boot caveat.
fn analyse_user_dump(path: &Path, timestamp: DateTime<Utc>) -> Option<CrashRecord> {
    let dump = Minidump::read_path(path).ok()?;
    let exception: MinidumpException = dump.get_stream().ok()?;
    let system_info: MinidumpSystemInfo = dump.get_stream().ok()?;

    let address = exception.get_crash_address(system_info.os, system_info.cpu);
    let modules: Option<MinidumpModuleList> = dump.get_stream().ok();

    let (module_name, attribution) =
        match modules.as_ref().and_then(|m| m.module_at_address(address)) {
            Some(module) => {
                let name = Path::new(module.code_file().as_ref())
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| module.code_file().to_string());
                (
                    Some(name.clone()),
                    CrashAttribution::ModuleRange { module: name },
                )
            }
            None => (None, CrashAttribution::Undetermined),
        };

    let code = exception.raw.exception_record.exception_code;

    Some(CrashRecord {
        timestamp,
        bugcheck_code: code,
        bugcheck_name: exception_name(code).to_string(),
        parameters: [address, 0, 0, 0],
        faulting_module: module_name,
        faulting_address: Some(address),
        attribution,
        dump_path: path.to_string_lossy().to_string(),
        source: CrashSource::UserDump,
    })
}

/// Common user-mode exception codes. Distinct from bugcheck codes.
fn exception_name(code: u32) -> &'static str {
    match code {
        0xC000_0005 => "ACCESS_VIOLATION",
        0xC000_001D => "ILLEGAL_INSTRUCTION",
        0xC000_0025 => "NONCONTINUABLE_EXCEPTION",
        0xC000_0026 => "INVALID_DISPOSITION",
        0xC000_008C => "ARRAY_BOUNDS_EXCEEDED",
        0xC000_008E => "FLT_DIVIDE_BY_ZERO",
        0xC000_0090 => "FLT_INVALID_OPERATION",
        0xC000_0094 => "INT_DIVIDE_BY_ZERO",
        0xC000_0095 => "INT_OVERFLOW",
        0xC000_00FD => "STACK_OVERFLOW",
        0xC000_0374 => "HEAP_CORRUPTION",
        0xC000_0409 => "STACK_BUFFER_OVERRUN",
        0xC000_0417 => "INVALID_CRUNTIME_PARAMETER",
        0x8000_0003 => "BREAKPOINT",
        0xE064_3430 => "MANAGED_EXCEPTION",
        _ => "EXCEPTION",
    }
}

fn user_dump_paths() -> Vec<PathBuf> {
    let Ok(local) = std::env::var("LOCALAPPDATA") else {
        return Vec::new();
    };
    let dir = PathBuf::from(local).join("CrashDumps");
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("dmp")))
        .collect()
}

fn read_prefix(file: &mut fs::File, len: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut buffer = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    buffer.truncate(filled);
    Some(buffer)
}

fn file_time(path: &Path) -> Option<DateTime<Utc>> {
    let meta = fs::metadata(path).ok()?;
    let time = meta.modified().or_else(|_| meta.created()).ok()?;
    Some(DateTime::<Utc>::from(time))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic DUMP_HEADER64 so header parsing is verified without
    /// needing the machine to have crashed.
    fn synthetic_kernel_dump64(code: u32, params: [u64; 4]) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_PREFIX];
        bytes[0..4].copy_from_slice(&DUMP_SIGNATURE.to_le_bytes());
        bytes[4..8].copy_from_slice(&DUMP_VALID64.to_le_bytes());
        bytes[BUGCHECK_CODE_OFFSET_64..BUGCHECK_CODE_OFFSET_64 + 4]
            .copy_from_slice(&code.to_le_bytes());
        for (i, p) in params.iter().enumerate() {
            let at = BUGCHECK_PARAMS_OFFSET_64 + i * 8;
            bytes[at..at + 8].copy_from_slice(&p.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn parses_a_64_bit_kernel_dump_header() {
        let params = [0xFFFF_F000_0000_0000, 0x2, 0x0, 0xFFFF_F803_1234_5678];
        let bytes = synthetic_kernel_dump64(0xD1, params);
        let (code, parsed) = parse_kernel_header(&bytes).expect("header must parse");
        assert_eq!(code, 0xD1);
        assert_eq!(parsed, params);
        assert_eq!(bugcheck::name(code), "DRIVER_IRQL_NOT_LESS_OR_EQUAL");
        assert_eq!(
            bugcheck::culprit_address(code, &parsed),
            Some(0xFFFF_F803_1234_5678)
        );
    }

    #[test]
    fn parses_a_32_bit_kernel_dump_header() {
        let mut bytes = vec![0u8; HEADER_PREFIX];
        bytes[0..4].copy_from_slice(&DUMP_SIGNATURE.to_le_bytes());
        bytes[4..8].copy_from_slice(&DUMP_VALID32.to_le_bytes());
        // Literal wire offsets keep this regression independent of the parser constants.
        bytes[0x28..0x2C].copy_from_slice(&0x0000_007Eu32.to_le_bytes());
        bytes[0x2C..0x30].copy_from_slice(&0xC000_0005u32.to_le_bytes());
        bytes[0x30..0x34].copy_from_slice(&0x8123_4567u32.to_le_bytes());
        bytes[0x34..0x38].copy_from_slice(&3u32.to_le_bytes());
        bytes[0x38..0x3C].copy_from_slice(&4u32.to_le_bytes());
        let (code, params) = parse_kernel_header(&bytes).expect("32-bit header must parse");
        assert_eq!(code, 0x7E);
        assert_eq!(params, [0xC000_0005, 0x8123_4567, 3, 4]);
    }

    #[test]
    fn rejects_files_that_are_not_kernel_dumps() {
        assert!(parse_kernel_header(&vec![0u8; HEADER_PREFIX]).is_none());
        // An MDMP container must not be mistaken for a kernel dump.
        let mut mdmp = vec![0u8; HEADER_PREFIX];
        mdmp[0..4].copy_from_slice(b"MDMP");
        assert!(parse_kernel_header(&mdmp).is_none());
        assert!(parse_kernel_header(b"short").is_none());
    }

    const OLD_BASE: u64 = 0xFFFF_F803_1234_0000;

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Wire-format fixture with two saved modules, independent of the reader's
    /// entry/layout constants. The second entry catches incorrect entry strides.
    fn small_kernel_dump(code: u32, params: [u64; 4]) -> Vec<u8> {
        let mut bytes = synthetic_kernel_dump64(code, params);
        bytes.resize(0x3000, 0);
        put32(&mut bytes, 0x30, 0x8664);
        put32(&mut bytes, 0xF98, 4);
        put32(&mut bytes, 0x2004, 0x3000);
        put32(&mut bytes, 0x2008, 0x2FFC);
        put32(&mut bytes, 0x2030, 0x2200);
        put32(&mut bytes, 0x2034, 2);
        put32(&mut bytes, 0x2038, 0x2600);
        put32(&mut bytes, 0x203C, 0x400);
        for (entry, name_offset, path, base) in [
            (
                0x2200,
                0x2600,
                "\\SystemRoot\\system32\\ntoskrnl.exe",
                OLD_BASE - 0x100000,
            ),
            (
                0x2290,
                0x2700,
                "\\SystemRoot\\system32\\drivers\\flaky.sys",
                OLD_BASE,
            ),
        ] {
            put32(&mut bytes, entry, name_offset as u32);
            bytes[entry + 0x38..entry + 0x40].copy_from_slice(&base.to_le_bytes());
            put32(&mut bytes, entry + 0x48, 0x10000);
            let name: Vec<u16> = path.encode_utf16().collect();
            put32(&mut bytes, name_offset, name.len() as u32);
            for (i, unit) in name.iter().enumerate() {
                let start = name_offset + 4 + i * 2;
                bytes[start..start + 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        bytes[0x2FFC..].copy_from_slice(b"TRGD");
        bytes
    }

    struct TempDump(PathBuf);

    impl TempDump {
        fn new(bytes: &[u8]) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "winsleuth-dump-{}-{}-{}.dmp",
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::write(&path, bytes).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDump {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn saved_module_map_resolves_after_reboot_and_driver_removal() {
        let dump = TempDump::new(&small_kernel_dump(0xD1, [0, 2, 0, OLD_BASE + 0x5678]));
        let mut current = crate::modules::core::fixtures::healthy_machine().drivers;
        current[0].name = "innocent.sys".into();
        current[0].base_address = OLD_BASE;
        current[0].size = 0x10000;
        for timestamp in [Utc::now() - chrono::Duration::days(30), Utc::now()] {
            for live in [&current[..], &[][..]] {
                let (record, warning) = WindowsMinidumpReader::new()
                    .analyse(&dump.0, timestamp, live)
                    .unwrap();
                assert_eq!(warning, None);
                assert_eq!(record.faulting_module.as_deref(), Some("flaky.sys"));
                assert_eq!(
                    record.attribution,
                    CrashAttribution::DumpModuleRange {
                        module: "flaky.sys".into(),
                        base_address: OLD_BASE,
                        size: 0x10000
                    }
                );
            }
        }
    }

    #[test]
    fn saved_ranges_use_exclusive_ends_and_never_nearest_module() {
        let bytes = small_kernel_dump(0xD1, [0; 4]);
        let modules = triage::read_modules(&mut std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(modules.len(), 2);
        for address in [OLD_BASE, OLD_BASE + 0xFFFF] {
            assert_eq!(
                attribute_kernel(address, &modules).module(),
                Some("flaky.sys")
            );
        }
        for address in [OLD_BASE - 1, OLD_BASE + 0x10000, OLD_BASE + 0x20000] {
            assert_eq!(
                attribute_kernel(address, &modules),
                CrashAttribution::Undetermined
            );
        }
    }

    #[test]
    fn malformed_or_unsupported_dump_never_falls_back_to_live_addresses() {
        let good = small_kernel_dump(0xD1, [0, 2, 0, OLD_BASE + 0x5678]);
        let mut current = crate::modules::core::fixtures::healthy_machine().drivers;
        current[0].base_address = OLD_BASE;
        current[0].size = 0x10000;
        for (offset, value) in [
            (0xF98, 1),
            (0x2030, u32::MAX),
            (0x2034, u32::MAX),
            (0x2700, u32::MAX),
        ] {
            let mut bytes = good.clone();
            put32(&mut bytes, offset, value);
            let dump = TempDump::new(&bytes);
            let (record, warning) = WindowsMinidumpReader::new()
                .analyse(&dump.0, Utc::now(), &current)
                .unwrap();
            assert!(warning.is_some());
            assert_eq!(record.bugcheck_code, 0xD1);
            assert_eq!(record.faulting_address, Some(OLD_BASE + 0x5678));
            assert_eq!(record.attribution, CrashAttribution::Undetermined);
        }
    }

    #[test]
    fn corrupt_triage_tables_are_rejected_without_partial_attribution() {
        let good = small_kernel_dump(0xD1, [0; 4]);
        for (offset, value) in [
            (0x30, 0xAA64),
            (0x2004, 0x4000),
            (0x2008, 0),
            (0x2030, 0),
            (0x2034, 0),
            (0x2034, u32::MAX),
            (0x2038, 0x2200),
            (0x203C, u32::MAX),
            (0x203C, 4),
            (0x2290, 0x2500),
            (0x2290, 0x2FFC),
            (0x2700, 0),
            (0x2700, u32::MAX),
            (0x22D8, 0),
            (0x2FFC, 0),
        ] {
            let mut bytes = good.clone();
            put32(&mut bytes, offset, value);
            assert!(
                triage::read_modules(&mut std::io::Cursor::new(bytes)).is_err(),
                "offset {offset:X}"
            );
        }
        for base in [0, u64::MAX - 10, OLD_BASE - 0x100000] {
            let mut bytes = good.clone();
            bytes[0x22C8..0x22D0].copy_from_slice(&base.to_le_bytes());
            assert!(triage::read_modules(&mut std::io::Cursor::new(bytes)).is_err());
        }
        // Every truncation must fail, including after an otherwise valid first entry.
        for length in (0..good.len()).step_by(17).chain([good.len() - 1]) {
            assert!(triage::read_modules(&mut std::io::Cursor::new(&good[..length])).is_err());
        }
        let mut invalid_utf16 = good.clone();
        invalid_utf16[0x2704..0x2706].copy_from_slice(&0xD800u16.to_le_bytes());
        assert!(triage::read_modules(&mut std::io::Cursor::new(invalid_utf16)).is_err());
    }

    #[test]
    fn hardware_and_watchdog_parameters_never_name_a_driver() {
        for code in [0x124, 0x133] {
            let dump = TempDump::new(&small_kernel_dump(code, [OLD_BASE + 0x1234; 4]));
            let (record, warning) = WindowsMinidumpReader::new()
                .analyse(&dump.0, Utc::now(), &[])
                .unwrap();
            assert_eq!(warning, None);
            assert_eq!(record.faulting_address, None);
            assert_eq!(record.attribution, CrashAttribution::Undetermined);
        }
    }

    /// Optional independent fixture, not bundled or downloaded by the tests.
    /// https://github.com/rizinorg/rizin-testbins/blob/master/dmp/triage_x64.dmp
    /// Save it as target/triage-check/triage_x64.dmp, then run:
    /// cargo test public_x64_triage_dump_matches_debugger -- --ignored
    #[test]
    #[ignore = "requires the public Rizin triage_x64.dmp fixture; see test documentation"]
    fn public_x64_triage_dump_matches_debugger() {
        use sha2::{Digest, Sha256};
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/triage-check/triage_x64.dmp");
        let bytes = fs::read(&path).expect("download the documented fixture first");
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "6875e8ff013eddb9d562165067be24e2a231a8851690bb101f6597ca9534cd28"
        );
        let modules = triage::read_modules(&mut std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(modules.len(), 151);
        let (record, warning) = WindowsMinidumpReader::new()
            .analyse(&path, Utc::now(), &[])
            .unwrap();
        assert_eq!(warning, None);
        assert_eq!(record.bugcheck_code, 0x1000007E);
        assert_eq!(record.faulting_address, Some(0xFFFF_F804_8B58_334C));
        // Independently checked using Microsoft's debugger:
        // cdb -z triage_x64.dmp -c "lm a fffff8048b58334c; q"
        assert_eq!(
            record.attribution,
            CrashAttribution::DumpModuleRange {
                module: "amdppm.sys".into(),
                base_address: 0xFFFF_F804_8B58_0000,
                size: 0x3B000
            }
        );
    }

    /// Runs only if this machine happens to have user-mode crash dumps.
    #[test]
    fn real_user_dumps_yield_a_faulting_module() {
        let dumps = user_dump_paths();
        if dumps.is_empty() {
            eprintln!("no user-mode dumps present; skipping");
            return;
        }

        let mut analysed = 0;
        for path in dumps.iter().take(5) {
            let Some(time) = file_time(path) else {
                continue;
            };
            if let Some(record) = analyse_user_dump(path, time) {
                analysed += 1;
                assert!(
                    record.bugcheck_code != 0,
                    "{} produced no exception code",
                    record.dump_path
                );
                // The old provider set faulting_module to the dump's own file
                // name. Whatever we report must not be the .dmp itself.
                if let Some(module) = &record.faulting_module {
                    assert!(
                        !module.ends_with(".dmp"),
                        "faulting module must be a real module, got {module}"
                    );
                }
            }
        }
        assert!(analysed > 0, "no user-mode dump could be analysed");
    }
}
