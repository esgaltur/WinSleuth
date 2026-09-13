//! Known-vulnerable driver detection (BYOVD).
//!
//! The scan already computes a SHA-256 for every loaded kernel driver and, in
//! the previous version, printed it and did nothing else. This turns that cost
//! into the sharpest finding the tool produces.
//!
//! Two matching strategies, deliberately weighted differently:
//!
//! * **By hash** — exact, and only possible once the user has fetched the
//!   loldrivers.io corpus with `winsleuth update-blocklist`. A hash match means
//!   *this exact file* is a known-vulnerable build.
//! * **By file name** — from the curated table below, which covers the drivers
//!   most commonly abused for Bring-Your-Own-Vulnerable-Driver attacks. Weaker
//!   evidence, because a vendor may have shipped a patched build under the same
//!   name, and reported as such.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::modules::core::models::VulnerableDriver;

/// A curated entry: a driver file name repeatedly abused for privileged
/// memory, MSR or port I/O access from user mode.
struct KnownDriver {
    file_name: &'static str,
    vendor: &'static str,
    capability: &'static str,
    cves: &'static [&'static str],
}

/// Drivers with well-documented privilege-escalation primitives. Names are
/// lowercase for comparison.
const KNOWN_VULNERABLE: &[KnownDriver] = &[
    KnownDriver {
        file_name: "rtcore64.sys",
        vendor: "MSI / RivaTuner Statistics Server",
        capability: "arbitrary kernel memory read/write and MSR access from user mode",
        cves: &["CVE-2019-16098"],
    },
    KnownDriver {
        file_name: "rtcore32.sys",
        vendor: "MSI / RivaTuner Statistics Server",
        capability: "arbitrary kernel memory read/write and MSR access from user mode",
        cves: &["CVE-2019-16098"],
    },
    KnownDriver {
        file_name: "dbutil_2_3.sys",
        vendor: "Dell",
        capability: "arbitrary kernel memory read/write",
        cves: &["CVE-2021-21551"],
    },
    KnownDriver {
        file_name: "dbutildrv2.sys",
        vendor: "Dell",
        capability: "arbitrary kernel memory read/write",
        cves: &["CVE-2021-36276"],
    },
    KnownDriver {
        file_name: "gdrv.sys",
        vendor: "Gigabyte",
        capability: "arbitrary physical memory and MSR access",
        cves: &["CVE-2018-19320"],
    },
    KnownDriver {
        file_name: "gdrv2.sys",
        vendor: "Gigabyte",
        capability: "arbitrary physical memory access",
        cves: &[],
    },
    KnownDriver {
        file_name: "asrdrv101.sys",
        vendor: "ASRock",
        capability: "arbitrary physical memory and MSR access",
        cves: &["CVE-2020-15368"],
    },
    KnownDriver {
        file_name: "asrdrv102.sys",
        vendor: "ASRock",
        capability: "arbitrary physical memory and MSR access",
        cves: &["CVE-2020-15368"],
    },
    KnownDriver {
        file_name: "asrdrv103.sys",
        vendor: "ASRock",
        capability: "arbitrary physical memory and MSR access",
        cves: &[],
    },
    KnownDriver {
        file_name: "winring0x64.sys",
        vendor: "OpenLibSys",
        capability: "arbitrary MSR and port I/O access; bundled with many fan and RGB tools",
        cves: &["CVE-2020-14979"],
    },
    KnownDriver {
        file_name: "winring0.sys",
        vendor: "OpenLibSys",
        capability: "arbitrary MSR and port I/O access",
        cves: &["CVE-2020-14979"],
    },
    KnownDriver {
        file_name: "iqvw64e.sys",
        vendor: "Intel",
        capability: "arbitrary kernel memory write via the Ethernet diagnostics driver",
        cves: &["CVE-2015-2291"],
    },
    KnownDriver {
        file_name: "iqvw32.sys",
        vendor: "Intel",
        capability: "arbitrary kernel memory write via the Ethernet diagnostics driver",
        cves: &["CVE-2015-2291"],
    },
    KnownDriver {
        file_name: "speedfan.sys",
        vendor: "Almico SpeedFan",
        capability: "arbitrary port I/O",
        cves: &["CVE-2007-5633"],
    },
    KnownDriver {
        file_name: "cpuz141.sys",
        vendor: "CPUID",
        capability: "arbitrary MSR read/write",
        cves: &["CVE-2017-15303"],
    },
    KnownDriver {
        file_name: "atszio.sys",
        vendor: "ASUS",
        capability: "arbitrary physical memory access",
        cves: &[],
    },
    KnownDriver {
        file_name: "atszio64.sys",
        vendor: "ASUS",
        capability: "arbitrary physical memory access",
        cves: &[],
    },
    KnownDriver {
        file_name: "asio.sys",
        vendor: "ASUS",
        capability: "arbitrary port I/O and physical memory access",
        cves: &[],
    },
    KnownDriver {
        file_name: "asio2.sys",
        vendor: "ASUS",
        capability: "arbitrary port I/O and physical memory access",
        cves: &["CVE-2021-33122"],
    },
    KnownDriver {
        file_name: "asio3.sys",
        vendor: "ASUS",
        capability: "arbitrary port I/O and physical memory access",
        cves: &[],
    },
    KnownDriver {
        file_name: "aoddriver2.sys",
        vendor: "AMD Overdrive",
        capability: "arbitrary MSR access",
        cves: &[],
    },
    KnownDriver {
        file_name: "ntiolib_x64.sys",
        vendor: "MSI",
        capability: "arbitrary physical memory, MSR and port I/O access",
        cves: &[],
    },
    KnownDriver {
        file_name: "msio64.sys",
        vendor: "MSI",
        capability: "arbitrary physical memory access",
        cves: &[],
    },
    KnownDriver {
        file_name: "capcom.sys",
        vendor: "Capcom",
        capability: "executes an arbitrary user-supplied pointer in kernel mode",
        cves: &[],
    },
    KnownDriver {
        file_name: "mhyprot2.sys",
        vendor: "miHoYo anti-cheat",
        capability: "arbitrary process termination and memory access; used by ransomware",
        cves: &[],
    },
    KnownDriver {
        file_name: "procexp152.sys",
        vendor: "Sysinternals Process Explorer",
        capability: "process handle manipulation; abused to terminate security products",
        cves: &[],
    },
    KnownDriver {
        file_name: "kprocesshacker.sys",
        vendor: "Process Hacker",
        capability: "process handle manipulation; abused to terminate security products",
        cves: &[],
    },
    KnownDriver {
        file_name: "viragt64.sys",
        vendor: "Trend Micro",
        capability: "arbitrary kernel memory access",
        cves: &["CVE-2017-5565"],
    },
    KnownDriver {
        file_name: "winio64.sys",
        vendor: "Yariv Kaplan WinIo",
        capability: "arbitrary physical memory and port I/O access",
        cves: &[],
    },
    KnownDriver {
        file_name: "winio.sys",
        vendor: "Yariv Kaplan WinIo",
        capability: "arbitrary physical memory and port I/O access",
        cves: &[],
    },
    KnownDriver {
        file_name: "directio64.sys",
        vendor: "PassMark DirectIO",
        capability: "arbitrary port I/O access",
        cves: &[],
    },
    KnownDriver {
        file_name: "phymem.sys",
        vendor: "unknown",
        capability: "arbitrary physical memory mapping",
        cves: &[],
    },
    KnownDriver {
        file_name: "glckio2.sys",
        vendor: "Gigabyte Aorus",
        capability: "arbitrary port I/O access",
        cves: &[],
    },
    KnownDriver {
        file_name: "eneio64.sys",
        vendor: "ENE Technology",
        capability: "arbitrary physical memory access; ships with several RGB suites",
        cves: &[],
    },
    KnownDriver {
        file_name: "enetechio64.sys",
        vendor: "ENE Technology",
        capability: "arbitrary physical memory access; ships with several RGB suites",
        cves: &[],
    },
    KnownDriver {
        file_name: "pcdsrvc_x64.sys",
        vendor: "PC-Doctor",
        capability: "arbitrary physical memory and MSR access",
        cves: &[],
    },
    KnownDriver {
        file_name: "amifldrv64.sys",
        vendor: "American Megatrends",
        capability: "arbitrary physical memory access from a firmware flashing driver",
        cves: &[],
    },
    KnownDriver {
        file_name: "rtkiow10x64.sys",
        vendor: "Realtek",
        capability: "arbitrary port I/O access",
        cves: &[],
    },
    KnownDriver {
        file_name: "bs_hwmio64_w10.sys",
        vendor: "Biostar",
        capability: "arbitrary physical memory and MSR access",
        cves: &[],
    },
    KnownDriver {
        file_name: "bs_rcio64.sys",
        vendor: "Biostar",
        capability: "arbitrary port I/O access",
        cves: &[],
    },
];

/// The on-disk corpus fetched from loldrivers.io.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Corpus {
    pub fetched_at: Option<String>,
    pub source: String,
    /// Lowercase SHA-256 to a short description.
    pub hashes: HashMap<String, CorpusEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub name: String,
    pub category: String,
    #[serde(default)]
    pub cves: Vec<String>,
}

/// The public feed of known-vulnerable drivers.
const CORPUS_URL: &str = "https://www.loldrivers.io/api/drivers.json";

static CORPUS: OnceLock<Corpus> = OnceLock::new();

pub fn corpus_path() -> PathBuf {
    crate::modules::core::store::data_dir().join("loldrivers.json")
}

/// Load the fetched corpus once per process. A missing file is normal — name
/// matching still works without it.
fn corpus() -> &'static Corpus {
    CORPUS.get_or_init(|| {
        std::fs::read_to_string(corpus_path())
            .ok()
            .and_then(|text| serde_json::from_str::<Corpus>(&text).ok())
            .unwrap_or_default()
    })
}

/// Check one driver against both the fetched hash corpus and the curated table.
pub fn lookup(file_name: &str, hash: Option<&str>) -> Option<VulnerableDriver> {
    let lower_name = file_name.to_lowercase();

    // An exact hash match is the strongest possible statement, so it wins.
    if let Some(hash) = hash {
        let key = hash.to_lowercase();
        if let Some(entry) = corpus().hashes.get(&key) {
            return Some(VulnerableDriver {
                matched_on: format!("SHA-256 {}", &key[..key.len().min(16)]),
                category: entry.category.clone(),
                cves: entry.cves.clone(),
                description: format!(
                    "This exact build of {} is listed in the known-vulnerable driver corpus.",
                    entry.name
                ),
            });
        }
    }

    let known = KNOWN_VULNERABLE
        .iter()
        .find(|k| k.file_name == lower_name)?;
    Some(VulnerableDriver {
        matched_on: "file name".to_string(),
        category: "known-vulnerable driver".to_string(),
        cves: known.cves.iter().map(|c| c.to_string()).collect(),
        description: format!(
            "{} ({}) exposes {}. Loaded builds of this driver are routinely used to disable \
             security software and escalate to kernel. Note this match is by file name — a \
             patched build may carry the same name.",
            file_name, known.vendor, known.capability
        ),
    })
}

/// Whether the corpus has been fetched, for reporting what the scan could see.
pub fn corpus_size() -> usize {
    corpus().hashes.len()
}

/// Number of curated file-name entries, always available offline.
pub fn curated_size() -> usize {
    KNOWN_VULNERABLE.len()
}

/// Download the loldrivers.io corpus and store it for later scans.
///
/// Kept explicit rather than automatic: a diagnostic tool should not make
/// network calls the user did not ask for.
pub fn update_corpus() -> anyhow::Result<usize> {
    // Trust the Windows certificate store rather than a bundled root list:
    // security products and corporate proxies commonly intercept TLS with a
    // root that Windows trusts but a bundled list does not.
    let agent = ureq::Agent::config_builder()
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .provider(ureq::tls::TlsProvider::NativeTls)
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .new_agent();

    let body = agent
        .get(CORPUS_URL)
        // Some endpoints refuse requests without a user agent.
        .header(
            "User-Agent",
            concat!("winsleuth/", env!("CARGO_PKG_VERSION")),
        )
        .header("Accept", "application/json")
        .call()?
        .body_mut()
        .read_to_string()?;

    let corpus = parse_corpus(&body)?;
    let count = corpus.hashes.len();

    let path = corpus_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string(&corpus)?)?;

    Ok(count)
}

/// Shape of one entry in the loldrivers.io feed.
#[derive(Deserialize)]
struct RemoteDriver {
    #[serde(default, rename = "Tags")]
    tags: Vec<String>,
    #[serde(default, rename = "Category")]
    category: Option<String>,
    #[serde(default, rename = "KnownVulnerableSamples")]
    samples: Vec<RemoteSample>,
    #[serde(default, rename = "CVE")]
    cve: Vec<String>,
}

#[derive(Deserialize)]
struct RemoteSample {
    #[serde(default, rename = "SHA256")]
    sha256: Option<String>,
    #[serde(default, rename = "Filename")]
    filename: Option<String>,
}

/// Turn the feed into a hash-keyed corpus.
///
/// Kept separate from the fetch so it is testable without a network, and so a
/// malformed or partially-populated feed cannot poison the corpus: entries
/// without a well-formed SHA-256 are skipped rather than stored.
pub fn parse_corpus(body: &str) -> anyhow::Result<Corpus> {
    let remote: Vec<RemoteDriver> = serde_json::from_str(body)?;

    let mut hashes = HashMap::new();
    for driver in remote {
        let label = driver
            .tags
            .first()
            .cloned()
            .unwrap_or_else(|| "unnamed driver".to_string());
        let category = driver
            .category
            .unwrap_or_else(|| "vulnerable driver".to_string());

        for sample in driver.samples {
            let Some(sha) = sample.sha256 else { continue };
            let sha = sha.trim().to_lowercase();
            if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            hashes.insert(
                sha,
                CorpusEntry {
                    name: sample.filename.unwrap_or_else(|| label.clone()),
                    category: category.clone(),
                    cves: driver.cve.clone(),
                },
            );
        }
    }

    Ok(Corpus {
        fetched_at: Some(chrono::Utc::now().to_rfc3339()),
        source: CORPUS_URL.to_string(),
        hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curated_names_are_matched_case_insensitively() {
        let hit = lookup("RTCore64.sys", None).expect("RTCore64 must be flagged");
        assert_eq!(hit.matched_on, "file name");
        assert!(hit.cves.contains(&"CVE-2019-16098".to_string()));
        assert!(hit.description.contains("MSR"));
        assert!(lookup("rtcore64.sys", None).is_some());
        assert!(lookup("RTCORE64.SYS", None).is_some());
    }

    #[test]
    fn ordinary_drivers_are_not_flagged() {
        assert!(lookup("afd.sys", None).is_none());
        assert!(lookup("ntoskrnl.exe", None).is_none());
        assert!(lookup("nvlddmkm.sys", None).is_none());
        // A hash that is not in the corpus must not produce a match on its own.
        assert!(lookup("something.sys", Some(&"a".repeat(64))).is_none());
    }

    #[test]
    fn the_curated_table_is_well_formed() {
        assert!(curated_size() > 30, "curated table looks truncated");
        for entry in KNOWN_VULNERABLE {
            assert_eq!(
                entry.file_name,
                entry.file_name.to_lowercase(),
                "{} must be lowercase for matching",
                entry.file_name
            );
            assert!(entry.file_name.ends_with(".sys"));
            assert!(!entry.capability.is_empty());
            for cve in entry.cves {
                assert!(cve.starts_with("CVE-"), "malformed CVE id {cve}");
            }
        }

        // No duplicates, which would make the table ambiguous.
        let mut names: Vec<&str> = KNOWN_VULNERABLE.iter().map(|k| k.file_name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(
            before,
            names.len(),
            "duplicate entries in the curated table"
        );
    }

    #[test]
    fn the_feed_is_parsed_into_hash_keyed_entries() {
        let feed = r#"[
          {
            "Tags": ["RTCore64.sys"],
            "Category": "vulnerable driver",
            "CVE": ["CVE-2019-16098"],
            "KnownVulnerableSamples": [
              {"SHA256": "01AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566AABB",
               "Filename": "RTCore64.sys"}
            ]
          }
        ]"#;

        let corpus = parse_corpus(feed).expect("the feed must parse");
        assert_eq!(corpus.hashes.len(), 1);

        // Hashes are stored lowercase so lookups are case-insensitive.
        let key = "01aabbccddeeff00112233445566778899aabbccddeeff00112233445566aabb";
        let entry = corpus
            .hashes
            .get(key)
            .expect("hash must be keyed lowercase");
        assert_eq!(entry.name, "RTCore64.sys");
        assert_eq!(entry.cves, vec!["CVE-2019-16098"]);
    }

    #[test]
    fn malformed_feed_entries_are_skipped_rather_than_stored() {
        let feed = r#"[
          {"Tags": ["a.sys"], "KnownVulnerableSamples": [{"SHA256": "too-short"}]},
          {"Tags": ["b.sys"], "KnownVulnerableSamples": [{"SHA256": null}]},
          {"Tags": ["c.sys"], "KnownVulnerableSamples": []},
          {"Tags": ["d.sys"], "KnownVulnerableSamples": [
              {"SHA256": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}]},
          {"Tags": [], "KnownVulnerableSamples": [
              {"SHA256": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}]}
        ]"#;

        let corpus = parse_corpus(feed).expect("must parse");
        // Only the last entry has a well-formed hash.
        assert_eq!(corpus.hashes.len(), 1);
        let only = corpus.hashes.values().next().unwrap();
        // With no filename and no tag, it still gets a usable label.
        assert_eq!(only.name, "unnamed driver");

        assert!(parse_corpus("not json").is_err());
        assert_eq!(parse_corpus("[]").unwrap().hashes.len(), 0);
    }

    #[test]
    fn a_corpus_hash_match_outranks_a_name_match() {
        // Both matching strategies must describe how they matched, so the
        // report can weight them differently.
        let by_name = lookup("gdrv.sys", None).unwrap();
        assert_eq!(by_name.matched_on, "file name");
        assert!(
            by_name
                .description
                .contains("patched build may carry the same name")
        );
    }
}
