#![allow(non_camel_case_types)]
//! Kernel driver enumeration.
//!
//! Changes from the previous implementation:
//!
//! * `is_os_driver` is decided by the **signer** rather than by the file's
//!   folder. `System32\DriverStore\FileRepository` holds OEM drivers, so the
//!   old path test classified third-party drivers as operating system
//!   components.
//! * `size` is filled in from the PE `SizeOfImage`. It was declared but never
//!   populated, which is why crash attribution had no upper bound and fell back
//!   to a 100 MB guess.
//! * Signature verification understands catalog signatures (see
//!   [`super::signature`]).
//! * Hashing, signature checks and version reads run across a thread pool.
//!   Hashing every loaded driver serially was the single largest cost in a scan.

use std::path::Path;
use std::sync::Mutex;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW};
use windows::core::HSTRING;
use wmi::WMIConnection;

use crate::modules::analysis::loldrivers;
use crate::modules::core::models::*;
use crate::modules::core::traits::DriverInventoryProvider;
use crate::modules::providers::signature::SignatureVerifier;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Win32_SystemDriver {
    name: String,
    display_name: Option<String>,
    service_type: String,
    path_name: Option<String>,
}

/// Upper bound on hashing threads. Driver enumeration is I/O bound, so a few
/// more threads than cores still helps, but the cap keeps a scan from
/// saturating a small machine.
fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 8)
}

pub struct WindowsDriverInventory {
    /// Skip SHA-256 hashing. Hashes are only needed for the vulnerable-driver
    /// check, so callers that do not need them can opt out.
    pub compute_hashes: bool,
}

impl WindowsDriverInventory {
    pub fn new() -> Self {
        Self {
            compute_hashes: true,
        }
    }

    pub fn without_hashes() -> Self {
        Self {
            compute_hashes: false,
        }
    }
}

impl Default for WindowsDriverInventory {
    fn default() -> Self {
        Self::new()
    }
}

/// A driver discovered before enrichment.
struct Candidate {
    name: String,
    path: String,
    publisher: String,
    description: String,
    base_address: u64,
}

impl DriverInventoryProvider for WindowsDriverInventory {
    fn collect_drivers(&self) -> Collected<Vec<DriverInfo>> {
        let mut candidates: Vec<Candidate> = Vec::new();
        let mut wmi_failed = false;

        // 1. WMI gives the service names and display names for running drivers.
        match WMIConnection::new() {
            Ok(connection) => {
                let query = "SELECT Name, DisplayName, ServiceType, PathName \
                             FROM Win32_SystemDriver WHERE State = 'Running'";
                match connection.raw_query::<Win32_SystemDriver>(query) {
                    Ok(drivers) => {
                        for driver in drivers {
                            if !driver.service_type.contains("Kernel")
                                && !driver.service_type.contains("File System")
                            {
                                continue;
                            }
                            let path = normalise_path(&driver.path_name.unwrap_or_default());
                            if path.is_empty() {
                                continue;
                            }
                            candidates.push(Candidate {
                                name: file_name_of(&path),
                                path,
                                publisher: driver
                                    .display_name
                                    .clone()
                                    .unwrap_or_else(|| driver.name.clone()),
                                description: format!("Kernel service: {}", driver.name),
                                base_address: 0,
                            });
                        }
                    }
                    Err(_) => wmi_failed = true,
                }
            }
            Err(_) => wmi_failed = true,
        }

        // 2. PSAPI gives load addresses, and catches modules WMI does not list
        //    (ntoskrnl and the HAL among them).
        for (path, base) in enumerate_loaded_modules() {
            match candidates
                .iter_mut()
                .find(|c| c.path.eq_ignore_ascii_case(&path))
            {
                Some(existing) => existing.base_address = base,
                None => {
                    let name = file_name_of(&path);
                    candidates.push(Candidate {
                        publisher: name.clone(),
                        description: format!("Loaded kernel module: {name}"),
                        name,
                        path,
                        base_address: base,
                    });
                }
            }
        }

        let drivers = self.enrich(candidates);

        // Windows zeroes kernel module addresses for medium-integrity processes
        // as a KASLR disclosure mitigation. Without them a crash address cannot
        // be resolved to a module, so say so rather than silently reporting
        // every crash as unattributed.
        let addresses_hidden = !drivers.is_empty() && drivers.iter().all(|d| d.base_address == 0);
        let status = if wmi_failed {
            CollectionStatus::Partial {
                reason: "the WMI driver service query failed; driver names may be incomplete"
                    .into(),
            }
        } else if addresses_hidden {
            CollectionStatus::Partial {
                reason: "kernel module addresses are hidden from unelevated processes, so crashes cannot be attributed to a driver; re-run as Administrator"
                    .into(),
            }
        } else {
            CollectionStatus::Complete
        };

        Collected {
            value: drivers,
            status,
        }
    }
}

impl WindowsDriverInventory {
    /// Fan the expensive per-file work (hash, signature, version, PE size) out
    /// across worker threads.
    fn enrich(&self, candidates: Vec<Candidate>) -> Vec<DriverInfo> {
        let workers = worker_count().min(candidates.len().max(1));
        let queue = Mutex::new(candidates.into_iter());
        let results: Mutex<Vec<DriverInfo>> = Mutex::new(Vec::new());
        let compute_hashes = self.compute_hashes;
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    // The catalog context is thread-affine, so each worker
                    // builds its own and reuses it for its whole share.
                    let verifier = SignatureVerifier::new();
                    let mut local = Vec::new();
                    loop {
                        let Some(candidate) = queue.lock().ok().and_then(|mut q| q.next()) else {
                            break;
                        };
                        local.push(enrich_one(&verifier, candidate, compute_hashes));
                    }

                    if let Ok(mut all) = results.lock() {
                        all.append(&mut local);
                    }
                });
            }
        });
        let mut drivers = results.into_inner().unwrap_or_default();
        drivers.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        drivers
    }
}

fn enrich_one(
    verifier: &SignatureVerifier,
    candidate: Candidate,
    compute_hashes: bool,
) -> DriverInfo {
    let signature = verifier.verify(&candidate.path);
    let (version, company) = version_info(&candidate.path);
    let size = image_size(&candidate.path).unwrap_or(0);
    let hash = compute_hashes.then(|| file_hash(&candidate.path)).flatten();

    let category = categorise(
        &candidate.name,
        &candidate.publisher,
        &candidate.path,
        &company,
    );

    // The signer is the real test for "is this an operating system driver".
    let is_os_driver = signature.is_microsoft();

    let vulnerability = loldrivers::lookup(&candidate.name, hash.as_deref());

    DriverInfo {
        name: candidate.name,
        path: candidate.path,
        version,
        publisher: candidate.publisher,
        description: candidate.description,
        company,
        hash,
        base_address: candidate.base_address,
        size,
        signature,
        is_os_driver,
        category,
        vulnerability,
    }
}

// ---------------------------------------------------------------------------
// Path handling
// ---------------------------------------------------------------------------

fn normalise_path(raw: &str) -> String {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let cleaned = raw
        .trim()
        .trim_matches('"')
        .replace("\\SystemRoot", &system_root)
        .replace("\\??\\", "");

    if cleaned.is_empty() {
        return cleaned;
    }

    // A bare `system32\drivers\x.sys` is relative to the Windows directory.
    if cleaned.len() > 1 && cleaned.as_bytes()[1] == b':' {
        cleaned
    } else {
        format!(
            "{}\\{}",
            system_root.trim_end_matches('\\'),
            cleaned.trim_start_matches('\\')
        )
    }
}

fn file_name_of(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

fn enumerate_loaded_modules() -> Vec<(String, u64)> {
    let mut modules = Vec::new();
    let mut addresses = vec![std::ptr::null_mut(); 2048];
    let mut needed = 0u32;

    unsafe {
        let byte_size = (addresses.len() * size_of::<*mut std::ffi::c_void>()) as u32;
        if EnumDeviceDrivers(addresses.as_mut_ptr(), byte_size, &mut needed).is_err() {
            return modules;
        }

        let count = (needed as usize / size_of::<*mut std::ffi::c_void>()).min(addresses.len());
        let mut buffer = [0u16; 1024];
        for address in addresses.iter().take(count) {
            let len = GetDeviceDriverFileNameW(*address, &mut buffer);
            if len == 0 {
                continue;
            }
            let raw = String::from_utf16_lossy(&buffer[..len as usize]);
            let path = normalise_path(&raw);
            if !path.is_empty() {
                modules.push((path, *address as u64));
            }
        }
    }

    modules
}

// ---------------------------------------------------------------------------
// PE image size
// ---------------------------------------------------------------------------

/// `SizeOfImage` from the PE optional header — the loaded extent of the module.
///
/// Without this the crash correlator had no upper bound on a module's address
/// range and accepted a match up to 100 MB from the base.
pub(crate) fn image_size(path: &str) -> Option<u32> {
    let bytes = read_head(path, 0x400)?;
    parse_image_size(&bytes)
}

pub(crate) fn parse_image_size(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if &bytes.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }

    // NT signature (4) + IMAGE_FILE_HEADER (20) reaches the optional header.
    // `SizeOfImage` sits at offset 56 within it in both PE32 and PE32+.
    let optional = e_lfanew + 24;
    let magic = u16::from_le_bytes(bytes.get(optional..optional + 2)?.try_into().ok()?);
    if magic != 0x010B && magic != 0x020B {
        return None;
    }

    let at = optional + 56;
    let size = u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?);
    (size > 0).then_some(size)
}

fn read_head(path: &str, len: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
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

fn file_hash(path: &str) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(_) => return None,
        }
    }
    Some(hex::encode(hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Version resources
// ---------------------------------------------------------------------------

/// Read `FileVersion` and `CompanyName`.
///
/// The previous implementation hardcoded the language/codepage block
/// `040904b0` (US English, Unicode), so any driver localised differently
/// reported version "N/A" and company "Unknown". This reads the translation
/// table and tries each block the file actually declares.
fn version_info(path: &str) -> (String, String) {
    let mut version = "N/A".to_string();
    let mut company = "Unknown".to_string();

    let path_w = HSTRING::from(path);
    unsafe {
        let size = GetFileVersionInfoSizeW(&path_w, None);
        if size == 0 {
            return (version, company);
        }

        let mut buffer = vec![0u8; size as usize];
        if GetFileVersionInfoW(&path_w, Some(0), size, buffer.as_mut_ptr() as *mut _).is_err() {
            return (version, company);
        }

        let query = |sub_block: &str| -> Option<String> {
            let block = HSTRING::from(sub_block);
            let mut value: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut len = 0u32;
            let ok =
                VerQueryValueW(buffer.as_ptr() as *const _, &block, &mut value, &mut len).as_bool();
            if !ok || len == 0 || value.is_null() {
                return None;
            }
            let text = String::from_utf16_lossy(std::slice::from_raw_parts(
                value as *const u16,
                len as usize,
            ));
            let text = text.trim_end_matches('\0').trim().to_string();
            (!text.is_empty()).then_some(text)
        };
        for (language, codepage) in translations(&buffer).into_iter().chain(FALLBACK_BLOCKS) {
            let prefix = format!("\\StringFileInfo\\{language:04x}{codepage:04x}");
            if version == "N/A"
                && let Some(v) = query(&format!("{prefix}\\FileVersion"))
            {
                version = v;
            }
            if company == "Unknown"
                && let Some(c) = query(&format!("{prefix}\\CompanyName"))
            {
                company = c;
            }
            if version != "N/A" && company != "Unknown" {
                break;
            }
        }
    }

    (version, company)
}

/// Blocks worth trying when a file declares no translation table: US English
/// with the Unicode and multilingual codepages.
const FALLBACK_BLOCKS: [(u16, u16); 2] = [(0x0409, 0x04B0), (0x0409, 0x04E4)];

/// Read the `\VarFileInfo\Translation` table: pairs of (language, codepage).
unsafe fn translations(buffer: &[u8]) -> Vec<(u16, u16)> {
    unsafe {
        let block = HSTRING::from("\\VarFileInfo\\Translation");
        let mut value: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        let ok =
            VerQueryValueW(buffer.as_ptr() as *const _, &block, &mut value, &mut len).as_bool();
        if !ok || value.is_null() || len < 4 {
            return Vec::new();
        }

        let pairs = len as usize / 4;
        let raw = std::slice::from_raw_parts(value as *const u16, pairs * 2);
        (0..pairs).map(|i| (raw[i * 2], raw[i * 2 + 1])).collect()
    }
}

// ---------------------------------------------------------------------------
// Categorisation
// ---------------------------------------------------------------------------

pub(crate) fn categorise(name: &str, display: &str, path: &str, company: &str) -> DriverCategory {
    let text = format!("{name} {display} {path} {company}").to_lowercase();

    // Graphics first: GPU drivers match several other keyword sets and are their
    // own category of instability.
    if text.contains("nvlddmkm")
        || text.contains("amdkmdag")
        || text.contains("amdkmpfd")
        || text.contains("igdkmd")
        || text.contains("dxgkrnl")
        || text.contains("graphics kernel")
    {
        return DriverCategory::Graphics;
    }

    if text.contains("anticheat")
        || text.contains("anti-cheat")
        || text.contains("easyanticheat")
        || text.contains("battleye")
        || text.contains("vanguard")
        || text.contains("vgk.sys")
    {
        return DriverCategory::AntiCheat;
    }

    if text.contains("rgb")
        || text.contains("lighting")
        || text.contains("aura")
        || text.contains("icue")
        || text.contains("corsair")
        || text.contains("razer")
        || text.contains("steelseries")
        || text.contains("logitech")
        || text.contains("mystic light")
    {
        return DriverCategory::Rgb;
    }

    if text.contains("hwinfo")
        || text.contains("aida")
        || text.contains("rtcore")
        || text.contains("winring0")
        || text.contains("openhardwaremonitor")
        || text.contains("speedfan")
        || text.contains("cpuz")
        || text.contains("gpuz")
        || text.contains("fan control")
        || text.contains("sensor")
    {
        return DriverCategory::Monitoring;
    }

    if text.contains("overclock")
        || text.contains("afterburner")
        || text.contains("ryzenmaster")
        || text.contains("intel(r) extreme")
        || text.contains("xtu")
        || text.contains("throttlestop")
    {
        return DriverCategory::Overclocking;
    }

    if text.contains("antivirus")
        || text.contains("defender")
        || text.contains("kaspersky")
        || text.contains("bitdefender")
        || text.contains("sentinel")
        || text.contains("crowdstrike")
        || text.contains("sophos")
        || text.contains("eset")
        || text.contains("malwarebytes")
    {
        return DriverCategory::Antivirus;
    }

    if text.contains("vmware")
        || text.contains("virtualbox")
        || text.contains("vbox")
        || text.contains("hyper-v")
        || text.contains("vmnet")
        || text.contains("qemu")
    {
        return DriverCategory::Virtualisation;
    }

    if text.contains("ndis")
        || text.contains("vpn")
        || text.contains("wi-fi")
        || text.contains("wifi")
        || text.contains("ethernet")
        || text.contains("wireless")
        || text.contains("netadapter")
    {
        return DriverCategory::Network;
    }

    if text.contains("storport")
        || text.contains("storage")
        || text.contains("scsi")
        || text.contains("nvme")
        || text.contains("ahci")
        || text.contains("raid")
        || text.contains("disk")
        || text.contains("volume")
    {
        return DriverCategory::Storage;
    }

    if text.contains("usb") || text.contains("xhci") || text.contains("ehci") {
        return DriverCategory::Usb;
    }

    DriverCategory::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorises_by_purpose() {
        assert_eq!(
            categorise(
                "hwinfo64.sys",
                "HWiNFO64 Driver",
                "C:\\temp\\hwinfo64.sys",
                "REALiX"
            ),
            DriverCategory::Monitoring
        );
        assert_eq!(
            categorise(
                "AMDRyzenMasterDriver.sys",
                "AMD Ryzen Master",
                "C:\\bin\\x.sys",
                "AMD"
            ),
            DriverCategory::Overclocking
        );
        assert_eq!(
            categorise(
                "CorsairLLAccess64.sys",
                "Corsair Link",
                "C:\\d\\c.sys",
                "Corsair"
            ),
            DriverCategory::Rgb
        );
        // A GPU driver is graphics, not "other" and not overclocking.
        assert_eq!(
            categorise(
                "nvlddmkm.sys",
                "NVIDIA Kernel Mode Driver",
                "C:\\w\\nvlddmkm.sys",
                "NVIDIA"
            ),
            DriverCategory::Graphics
        );
        assert_eq!(
            categorise(
                "EasyAntiCheat.sys",
                "EasyAntiCheat",
                "C:\\p\\eac.sys",
                "Epic"
            ),
            DriverCategory::AntiCheat
        );
        assert_eq!(
            categorise("random.sys", "Something", "C:\\x.sys", "Acme"),
            DriverCategory::Other
        );
    }

    #[test]
    fn sensor_contention_covers_the_categories_that_actually_collide() {
        assert!(DriverCategory::Monitoring.contends_for_sensors());
        assert!(DriverCategory::Rgb.contends_for_sensors());
        assert!(DriverCategory::Overclocking.contends_for_sensors());
        assert!(!DriverCategory::Network.contends_for_sensors());
        assert!(!DriverCategory::Graphics.contends_for_sensors());
    }

    #[test]
    fn normalises_the_paths_windows_actually_reports() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        assert_eq!(
            normalise_path("\\SystemRoot\\System32\\drivers\\afd.sys"),
            format!("{root}\\System32\\drivers\\afd.sys")
        );
        assert_eq!(
            normalise_path("\\??\\C:\\Program Files\\Tool\\tool.sys"),
            "C:\\Program Files\\Tool\\tool.sys"
        );
        assert_eq!(
            normalise_path("\"C:\\Windows\\System32\\drivers\\x.sys\""),
            "C:\\Windows\\System32\\drivers\\x.sys"
        );
        // A relative path resolves against the Windows directory.
        assert_eq!(
            normalise_path("system32\\drivers\\rel.sys"),
            format!("{root}\\system32\\drivers\\rel.sys")
        );
        assert_eq!(normalise_path(""), "");
    }

    #[test]
    fn parses_size_of_image_from_a_real_binary() {
        // ntoskrnl is present on every Windows install and is large.
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let path = format!("{root}\\System32\\ntoskrnl.exe");
        if !Path::new(&path).exists() {
            eprintln!("ntoskrnl not present; skipping");
            return;
        }

        let size = image_size(&path).expect("ntoskrnl must yield a SizeOfImage");
        assert!(size > 1_000_000, "implausible SizeOfImage {size}");
        assert!(size < 100 * 1024 * 1024);
    }

    #[test]
    fn rejects_non_pe_input_rather_than_inventing_a_size() {
        assert_eq!(parse_image_size(b"not a pe file at all"), None);
        assert_eq!(parse_image_size(&vec![0u8; 1024]), None);

        // MZ header pointing nowhere useful.
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        assert_eq!(parse_image_size(&bytes), None);
    }

    #[test]
    fn parses_a_synthetic_pe32_plus_header() {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        let e_lfanew = 0x80usize;
        bytes[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        bytes[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
        let optional = e_lfanew + 24;
        bytes[optional..optional + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x0004_2000u32.to_le_bytes());
        assert_eq!(parse_image_size(&bytes), Some(0x42000));
    }

    /// The regression that produced the shipped example report.
    #[test]
    fn microsoft_drivers_are_classified_as_os_drivers() {
        let inventory = WindowsDriverInventory::without_hashes();
        let collected = inventory.collect_drivers();
        let drivers = collected.value;
        if drivers.is_empty() {
            eprintln!("no drivers enumerated; skipping");
            return;
        }

        let os_count = drivers.iter().filter(|d| d.is_os_driver).count();
        assert!(
            os_count > drivers.len() / 2,
            "only {os_count} of {} drivers recognised as Microsoft-signed; \
             catalog verification is broken",
            drivers.len()
        );

        // Named offenders from the previously committed example report.
        for name in ["afd.sys", "beep.sys", "bam.sys", "ntoskrnl.exe"] {
            if let Some(driver) = drivers.iter().find(|d| d.name.eq_ignore_ascii_case(name)) {
                assert!(
                    driver.signature.is_signed(),
                    "{name} reported as {:?}",
                    driver.signature
                );
                assert!(
                    driver.is_os_driver,
                    "{name} must be recognised as an OS driver"
                );
            }
        }
    }

    #[test]
    fn every_loaded_module_has_a_real_image_size() {
        let inventory = WindowsDriverInventory::without_hashes();
        let drivers = inventory.collect_drivers().value;
        if drivers.is_empty() {
            eprintln!("no drivers enumerated; skipping");
            return;
        }

        // `size` was declared but never populated before, which is why crash
        // attribution had no upper bound and fell back to a 100 MB guess. It
        // must now resolve for essentially every module, elevated or not.
        let sized = drivers.iter().filter(|d| d.size > 0).count();
        assert!(
            sized * 10 >= drivers.len() * 9,
            "only {sized} of {} drivers yielded a SizeOfImage",
            drivers.len()
        );
        for driver in drivers.iter().filter(|d| d.size > 0) {
            assert!(
                driver.size > 0x1000,
                "{} has implausible size {:#x}",
                driver.name,
                driver.size
            );
            assert!(
                driver.size < 200 * 1024 * 1024,
                "{} has implausible size",
                driver.name
            );
        }
    }

    /// Kernel addresses are hidden from medium-integrity processes as a KASLR
    /// disclosure mitigation, so this can only be checked when elevated.
    #[test]
    fn loaded_module_addresses_do_not_overlap() {
        if !crate::modules::core::privilege::is_elevated() {
            eprintln!("not elevated: kernel addresses are hidden by design; skipping");
            return;
        }

        let inventory = WindowsDriverInventory::without_hashes();
        let drivers = inventory.collect_drivers().value;
        let addressable: Vec<&DriverInfo> = drivers
            .iter()
            .filter(|d| d.base_address > 0 && d.size > 0)
            .collect();
        assert!(
            addressable.len() > 10,
            "only {} drivers carry both a base address and an image size",
            addressable.len()
        );
        for driver in &addressable {
            let overlapping = addressable
                .iter()
                .filter(|other| {
                    other.path != driver.path && other.contains_address(driver.base_address)
                })
                .count();
            assert_eq!(overlapping, 0, "{} overlaps another module", driver.name);
        }
    }

    /// An unelevated scan cannot attribute crashes. That must be reported, not
    /// silently turned into "no culprit found".
    #[test]
    fn hidden_addresses_are_reported_rather_than_passed_over() {
        let collected = WindowsDriverInventory::without_hashes().collect_drivers();
        if collected.value.is_empty() {
            eprintln!("no drivers enumerated; skipping");
            return;
        }

        if collected.value.iter().all(|d| d.base_address == 0) {
            let reason = collected
                .status
                .reason()
                .expect("hidden addresses must be reported as a partial collection");
            assert!(
                reason.contains("Administrator"),
                "the user needs to be told why attribution is unavailable: {reason}"
            );
        }
    }
}
