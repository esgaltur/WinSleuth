//! Bounded reads of the x64 small kernel dump's saved module table.
//!
//! Format layout reference (field offsets only; no native struct casts):
//! https://github.com/rizinorg/rizin/blob/dev/librz/bin/format/dmp/dmp_specs.h
//! DUMP_HEADER64 is 0x2000 bytes; TRIAGE_DUMP64 follows it. Driver entries
//! are 0x90 bytes, containing an 8-byte prefix and a saved loader entry.
//! DriverNameOffset points to a DUMP_STRING (UTF-16 code-unit count + data),
//! not to the live UNICODE_STRING pointers inside the loader entry.

use std::io::{Read, Seek, SeekFrom};

use super::{DUMP_SIGNATURE, DUMP_VALID64, read_u32, read_u64};
use crate::modules::analysis::bugcheck;

const HEADER_SIZE: usize = 0x2000;
const TRIAGE_SIZE: usize = 0x80;
const ENTRY_SIZE: usize = 0x90;
const MAX_DRIVERS: usize = 4096;
const MAX_STRING_POOL: usize = 4 * 1024 * 1024;
const MAX_NAME_UNITS: usize = 1024;

#[derive(Debug, PartialEq)]
pub(super) struct DumpModule {
    pub name: String,
    pub base: u64,
    pub size: u32,
}

impl DumpModule {
    pub fn contains(&self, address: u64) -> bool {
        self.size != 0
            && self
                .base
                .checked_add(u64::from(self.size))
                .is_some_and(|end| self.base <= address && address < end)
    }
}

/// Never map a partial or ambiguous table. Returning an error still allows
/// the caller to report the bugcheck, with collection degradation disclosed.
pub(super) fn read_modules<R: Read + Seek>(
    reader: &mut R,
) -> Result<Vec<DumpModule>, &'static str> {
    const INVALID: &str = "invalid or truncated kernel triage module data";
    let file_size = reader.seek(SeekFrom::End(0)).map_err(|_| INVALID)?;
    let prefix = read_at(reader, 0, HEADER_SIZE + TRIAGE_SIZE).ok_or(INVALID)?;
    if read_u32(&prefix, 0) != Some(DUMP_SIGNATURE)
        || read_u32(&prefix, 4) != Some(DUMP_VALID64)
        || read_u32(&prefix, 0x30) != Some(0x8664)
        || read_u32(&prefix, 0xF98) != Some(4)
    {
        return Err("module attribution supports x64 small kernel dumps only");
    }

    let triage = &prefix[HEADER_SIZE..];
    let dump_size = read_u32(triage, 0x04).ok_or(INVALID)? as usize;
    let valid = read_u32(triage, 0x08).ok_or(INVALID)? as usize;
    let list = read_u32(triage, 0x30).ok_or(INVALID)? as usize;
    let count = read_u32(triage, 0x34).ok_or(INVALID)? as usize;
    let pool = read_u32(triage, 0x38).ok_or(INVALID)? as usize;
    let pool_size = read_u32(triage, 0x3C).ok_or(INVALID)? as usize;

    if dump_size as u64 > file_size
        || valid < HEADER_SIZE + TRIAGE_SIZE
        || valid.checked_add(4) != Some(dump_size)
        || count == 0
        || count > MAX_DRIVERS
        || pool_size == 0
        || pool_size > MAX_STRING_POOL
    {
        return Err(INVALID);
    }
    let marker = read_at(reader, valid as u64, 4).ok_or(INVALID)?;
    if marker != b"TRGD" {
        return Err(INVALID);
    }
    let list_size = count.checked_mul(ENTRY_SIZE).ok_or(INVALID)?;
    let list_end = list.checked_add(list_size).ok_or(INVALID)?;
    let pool_end = pool.checked_add(pool_size).ok_or(INVALID)?;
    if list < HEADER_SIZE + TRIAGE_SIZE
        || pool < HEADER_SIZE + TRIAGE_SIZE
        || list_end > valid
        || pool_end > valid
        || (list < pool_end && pool < list_end)
    {
        return Err(INVALID);
    }
    let entries = read_at(reader, list as u64, list_size).ok_or(INVALID)?;
    let strings = read_at(reader, pool as u64, pool_size).ok_or(INVALID)?;
    let mut modules = Vec::with_capacity(count);
    for entry in entries.chunks_exact(ENTRY_SIZE) {
        let name_offset = read_u32(entry, 0).ok_or(INVALID)? as usize;
        let relative = name_offset.checked_sub(pool).ok_or(INVALID)?;
        if relative % 2 != 0 {
            return Err(INVALID);
        }
        let units = read_u32(&strings, relative).ok_or(INVALID)? as usize;
        if units == 0 || units > MAX_NAME_UNITS {
            return Err(INVALID);
        }
        let start = relative.checked_add(4).ok_or(INVALID)?;
        let end = start
            .checked_add(units.checked_mul(2).ok_or(INVALID)?)
            .ok_or(INVALID)?;
        let raw = strings.get(start..end).ok_or(INVALID)?;
        let utf16: Vec<u16> = raw
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        let path = String::from_utf16(&utf16).map_err(|_| INVALID)?;
        let path = path.strip_suffix('\0').unwrap_or(&path);
        if path.chars().any(char::is_control) {
            return Err(INVALID);
        }
        let name = path.rsplit(['\\', '/']).next().ok_or(INVALID)?;
        if name.is_empty() || name == "." || name == ".." || name.contains(':') {
            return Err(INVALID);
        }
        let base = read_u64(entry, 0x38).ok_or(INVALID)?;
        let size = read_u32(entry, 0x48).ok_or(INVALID)?;
        if !bugcheck::is_kernel_address(base)
            || size == 0
            || base.checked_add(u64::from(size)).is_none()
        {
            return Err(INVALID);
        }
        modules.push(DumpModule {
            name: name.to_string(),
            base,
            size,
        });
    }
    modules.sort_by_key(|m| m.base);
    if modules
        .windows(2)
        .any(|pair| pair[0].base + u64::from(pair[0].size) > pair[1].base)
    {
        return Err("overlapping image ranges in kernel triage module data");
    }
    Ok(modules)
}

fn read_at<R: Read + Seek>(reader: &mut R, offset: u64, size: usize) -> Option<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset)).ok()?;
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).ok()?;
    Some(bytes)
}
