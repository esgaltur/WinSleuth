//! Authenticode verification that understands catalog signatures.
//!
//! The overwhelming majority of Windows drivers carry no embedded signature —
//! it lives in a `.cat` file under the driver store. Verifying only
//! `WTD_CHOICE_FILE` returns `TRUST_E_NOSIGNATURE` for all of them, which is
//! how the previous implementation came to report `AFD.sys`, `Beep.sys` and
//! several hundred other Microsoft kernel modules as unsigned third-party
//! drivers.
//!
//! This module hashes the file, looks the hash up in the system catalogs, and
//! verifies through `WTD_CHOICE_CATALOG`, falling back to embedded
//! verification. It also closes the trust state handle that
//! `WTD_STATEACTION_VERIFY` allocates, which the previous code leaked once per
//! driver.

use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, HWND};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
use windows::Win32::Security::WinTrust::{
    DRIVER_ACTION_VERIFY, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_0, WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_FILE_INFO, WTD_CHOICE_CATALOG,
    WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE, WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use crate::modules::core::models::SignatureStatus;

/// Skip the online revocation round trip. Verifying several hundred drivers
/// against a CRL endpoint would dominate the scan and fail entirely offline.
const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_1000;
const WTD_SAFER_FLAG: u32 = 0x0000_0100;
const TRUST_E_NOSIGNATURE: i32 = -2146762496; // 0x800B0100

/// Holds the catalog administrator context. Acquiring it is comparatively
/// expensive, so one verifier is reused for a whole batch of files.
///
/// Not shared between threads: the underlying context is thread-affine, so each
/// worker builds its own.
pub struct SignatureVerifier {
    cat_admin: isize,
}

impl SignatureVerifier {
    pub fn new() -> Self {
        let mut cat_admin: isize = 0;
        let algorithm = HSTRING::from("SHA256");
        unsafe {
            let _ = CryptCATAdminAcquireContext2(
                &mut cat_admin,
                Some(&DRIVER_ACTION_VERIFY),
                &algorithm,
                None,
                None,
            );
        }
        Self { cat_admin }
    }

    /// Verify one file. Never panics and never blocks on the network.
    pub fn verify(&self, path: &str) -> SignatureStatus {
        let path_w = HSTRING::from(path);
        let handle = unsafe {
            CreateFileW(
                &path_w,
                GENERIC_READ.0,
                // Loaded drivers are open by the kernel; without the full share
                // mask every running driver fails to open.
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        let handle = match handle {
            Ok(h) if !h.is_invalid() => h,
            _ => {
                return SignatureStatus::Unknown {
                    reason: "file could not be opened".to_string(),
                };
            }
        };
        let result = self.verify_handle(&path_w, handle);
        unsafe {
            let _ = CloseHandle(handle);
        }
        result
    }

    fn verify_handle(&self, path_w: &HSTRING, handle: HANDLE) -> SignatureStatus {
        // A catalog lookup needs the file's hash under the same algorithm the
        // catalogs were built with.
        let hash = match self.file_hash(handle) {
            Some(h) => h,
            None => return self.verify_embedded(path_w),
        };
        let cat_info =
            unsafe { CryptCATAdminEnumCatalogFromHash(self.cat_admin, &hash, None, None) };
        if cat_info == 0 {
            // No catalog vouches for this file; it must carry its own signature.
            return self.verify_embedded(path_w);
        }

        let status = self.verify_catalog(path_w, handle, &hash, cat_info);
        unsafe {
            let _ = CryptCATAdminReleaseCatalogContext(self.cat_admin, cat_info, 0);
        }

        match status {
            Some(s) => s,
            // Catalog membership without a valid catalog signature still leaves
            // the possibility of an embedded one.
            None => self.verify_embedded(path_w),
        }
    }

    fn file_hash(&self, handle: HANDLE) -> Option<Vec<u8>> {
        if self.cat_admin == 0 {
            return None;
        }
        unsafe {
            let mut size = 0u32;
            // First call reports the required buffer size.
            let _ =
                CryptCATAdminCalcHashFromFileHandle2(self.cat_admin, handle, &mut size, None, None);
            if size == 0 {
                return None;
            }
            let mut buffer = vec![0u8; size as usize];
            CryptCATAdminCalcHashFromFileHandle2(
                self.cat_admin,
                handle,
                &mut size,
                Some(buffer.as_mut_ptr()),
                None,
            )
            .ok()?;
            buffer.truncate(size as usize);
            Some(buffer)
        }
    }

    fn verify_catalog(
        &self,
        path_w: &HSTRING,
        handle: HANDLE,
        hash: &[u8],
        cat_info: isize,
    ) -> Option<SignatureStatus> {
        let mut info = CATALOG_INFO {
            cbStruct: size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        unsafe { CryptCATCatalogInfoFromContext(cat_info, &mut info, 0).ok()? };
        let catalog_path = String::from_utf16_lossy(&info.wszCatalogFile)
            .trim_end_matches('\0')
            .to_string();
        if catalog_path.is_empty() {
            return None;
        }
        let catalog_w = HSTRING::from(catalog_path.as_str());

        // The member tag is the file hash rendered as an uppercase hex string.
        let member_tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
        let member_tag_w = HSTRING::from(member_tag.as_str());
        let mut hash_buf = hash.to_vec();
        let mut catalog = WINTRUST_CATALOG_INFO {
            cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
            dwCatalogVersion: 0,
            pcwszCatalogFilePath: PCWSTR(catalog_w.as_ptr()),
            pcwszMemberTag: PCWSTR(member_tag_w.as_ptr()),
            pcwszMemberFilePath: PCWSTR(path_w.as_ptr()),
            hMemberFile: handle,
            pbCalculatedFileHash: hash_buf.as_mut_ptr(),
            cbCalculatedFileHash: hash_buf.len() as u32,
            pcCatalogContext: std::ptr::null_mut(),
            hCatAdmin: self.cat_admin,
        };
        let mut data = base_trust_data();
        data.dwUnionChoice = WTD_CHOICE_CATALOG;
        data.Anonymous = WINTRUST_DATA_0 {
            pCatalog: &mut catalog,
        };
        let (code, signer) = run_verify(&mut data);
        if code == 0 {
            Some(SignatureStatus::Catalog {
                signer: signer.unwrap_or_else(|| "unknown signer".to_string()),
            })
        } else {
            None
        }
    }

    fn verify_embedded(&self, path_w: &HSTRING) -> SignatureStatus {
        let file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(path_w.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data = base_trust_data();
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous = WINTRUST_DATA_0 {
            pFile: &file_info as *const _ as *mut _,
        };
        let (code, signer) = run_verify(&mut data);
        match code {
            0 => SignatureStatus::Embedded {
                signer: signer.unwrap_or_else(|| "unknown signer".to_string()),
            },
            TRUST_E_NOSIGNATURE => SignatureStatus::Unsigned,
            other => SignatureStatus::Unknown {
                reason: format!("WinVerifyTrust 0x{:08X}", other as u32),
            },
        }
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SignatureVerifier {
    fn drop(&mut self) {
        if self.cat_admin != 0 {
            unsafe {
                let _ = CryptCATAdminReleaseContext(self.cat_admin, 0);
            }
        }
    }
}

fn base_trust_data() -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WINTRUST_DATA_REVOCATION_CHECKS(WTD_REVOCATION_CHECK_NONE.0),
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: std::ptr::null_mut(),
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: HANDLE::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS(
            WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL,
        ),
        dwUIContext: Default::default(),
        pSignatureSettings: std::ptr::null_mut(),
    }
}

/// Runs the verification and *always* releases the trust state handle that
/// `WTD_STATEACTION_VERIFY` allocated. Returns the status code and, on success,
/// the signer's display name.
fn run_verify(data: &mut WINTRUST_DATA) -> (i32, Option<String>) {
    unsafe {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let code = WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            data as *mut _ as *mut _,
        );
        let signer = if code == 0 {
            signer_name(data.hWVTStateData)
        } else {
            None
        };

        // Release the provider state. Skipping this leaked a handle per file.
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            data as *mut _ as *mut _,
        );

        (code, signer)
    }
}

/// Pull the signing certificate's display name out of the trust provider state.
/// This is what makes "is it an operating system driver?" answerable from the
/// signer rather than from the file's folder.
unsafe fn signer_name(state: HANDLE) -> Option<String> {
    unsafe {
        if state.is_invalid() {
            return None;
        }
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if signer.is_null() {
            return None;
        }
        let cert = WTHelperGetProvCertFromChain(signer, 0);
        if cert.is_null() {
            return None;
        }
        let context = (*cert).pCert;
        if context.is_null() {
            return None;
        }

        let needed = CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
        if needed <= 1 {
            return None;
        }
        let mut buffer = vec![0u16; needed as usize];
        let written = CertGetNameStringW(
            context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut buffer),
        );
        if written <= 1 {
            return None;
        }
        let name = String::from_utf16_lossy(&buffer[..(written as usize).saturating_sub(1)]);
        let name = name.trim().to_string();
        if name.is_empty() { None } else { Some(name) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The WHQL attestation authority signs third-party drivers, so its name
    /// must not be mistaken for an operating system component.
    #[test]
    fn whql_attested_vendor_drivers_are_not_operating_system_drivers() {
        let verifier = SignatureVerifier::new();
        for name in ["nvlddmkm.sys", "AsIO2.sys", "AsIO3.sys", "MsIo64.sys"] {
            let path = format!(r"C:\Windows\System32\drivers\{}", name);
            if !std::path::Path::new(&path).exists() {
                continue;
            }

            let status = verifier.verify(&path);
            if let Some(signer) = status.signer()
                && signer.contains("Hardware Compatibility")
            {
                assert!(status.is_signed());
                assert!(
                    !status.is_microsoft(),
                    "{name} is signed by the WHQL authority ({signer}) but was classed as an operating system driver"
                );
            }
        }
    }

    #[test]
    fn core_os_drivers_verify_as_signed() {
        let verifier = SignatureVerifier::new();

        // These ship with every supported Windows install and are catalog
        // signed. Reporting any of them as unsigned is the exact regression
        // this module exists to prevent.
        for name in ["ntoskrnl.exe", "afd.sys", "beep.sys"] {
            let path = format!("C:\\Windows\\System32\\{}", name);
            let path = if std::path::Path::new(&path).exists() {
                path
            } else {
                format!("C:\\Windows\\System32\\drivers\\{}", name)
            };
            if !std::path::Path::new(&path).exists() {
                continue;
            }

            let status = verifier.verify(&path);
            assert!(
                status.is_signed(),
                "{path} reported as {status:?}; catalog verification is broken"
            );
            assert!(
                status.is_microsoft(),
                "{path} signer was not recognised as Microsoft: {status:?}"
            );
        }
    }

    #[test]
    fn a_non_binary_file_is_reported_unsigned_not_signed() {
        let verifier = SignatureVerifier::new();
        let temp = std::env::temp_dir().join("winsleuth_sig_probe.txt");
        std::fs::write(&temp, b"not a signed binary").unwrap();
        let status = verifier.verify(&temp.to_string_lossy());
        assert!(
            !status.is_signed(),
            "unsigned junk must not verify: {status:?}"
        );
        let _ = std::fs::remove_file(&temp);
    }

    #[test]
    fn a_missing_file_is_unknown_rather_than_unsigned() {
        let verifier = SignatureVerifier::new();
        let status =
            verifier.verify("C:\\Windows\\System32\\drivers\\winsleuth_does_not_exist.sys");
        assert!(
            matches!(status, SignatureStatus::Unknown { .. }),
            "missing files must not be claimed as unsigned: {status:?}"
        );
    }
}
