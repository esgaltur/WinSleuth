//! Synthetic reports for testing rules without a Windows machine in the loop.
//!
//! The provider traits were built for exactly this seam and it was never used —
//! there was one test in the whole repository. These builders make every rule
//! testable, including the negative cases that matter most: a healthy machine
//! must produce no findings at all.

use chrono::{DateTime, Duration, Utc};

use crate::modules::core::models::*;

/// A machine with nothing wrong with it. The most important fixture: rules that
/// fire on this are the ones that made the tool untrustworthy.
pub fn healthy_machine() -> DiagnosticReport {
    let window = ScanWindow::last_days(7);
    let now = Utc::now();

    let mut report = DiagnosticReport::empty(window);
    report.elevated = true;
    report.system = SystemIdentity {
        hostname: "WORKBENCH".into(),
        os_caption: "Windows 11 Pro".into(),
        os_build: "10.0.26100".into(),
        motherboard_vendor: "ASUSTeK COMPUTER INC.".into(),
        motherboard_model: "TUF GAMING X570-PRO".into(),
        cpu_model: "AMD Ryzen 9 3900 12-Core Processor".into(),
        physical_memory_gb: 32.0,
        last_boot: Some(now - Duration::days(2)),
    };
    report.firmware = FirmwareInfo {
        vendor: "American Megatrends Inc.".into(),
        version: "4021".into(),
        date: "2025-11-02".into(),
        release_date: Some(now - Duration::days(300)),
    };
    report.security = SecurityPosture {
        hvci_enabled: Some(true),
        vbs_enabled: Some(true),
        driver_blocklist_enabled: Some(true),
        test_signing: Some(false),
        secure_boot: Some(true),
        kernel_dma_protection: Some(true),
    };

    // A realistic driver set: mostly Microsoft, one vendor GPU driver, and a
    // single monitoring utility — which on its own is not contention.
    report.drivers = vec![
        os_driver("ntoskrnl.exe", 0xFFFF_F800_0100_0000, 0x900000),
        os_driver("afd.sys", 0xFFFF_F800_0200_0000, 0x60000),
        os_driver("beep.sys", 0xFFFF_F800_0300_0000, 0x8000),
        os_driver("bam.sys", 0xFFFF_F800_0310_0000, 0x10000),
        vendor_driver(
            "nvlddmkm.sys",
            "NVIDIA Corporation",
            DriverCategory::Graphics,
            0xFFFF_F800_0400_0000,
            0x1_800000,
        ),
        vendor_driver(
            "HWiNFO64A.SYS",
            "REALiX",
            DriverCategory::Monitoring,
            0xFFFF_F800_0600_0000,
            0x9000,
        ),
    ];

    // Ordinary background noise: a handful of errors over a week.
    report.timeline = vec![
        event("DCOM", 10016, EventLevel::Error, now - Duration::days(4)),
        event(
            "Application Error",
            1000,
            EventLevel::Error,
            now - Duration::days(3),
        ),
        event("DCOM", 10016, EventLevel::Error, now - Duration::days(1)),
    ];

    report
}

/// A machine with genuine hardware errors: WHEA records plus matching stop
/// codes, on old firmware.
pub fn hardware_fault_machine() -> DiagnosticReport {
    let now = Utc::now();
    let mut report = healthy_machine();

    report.firmware.release_date = Some(now - Duration::days(1500));
    report.firmware.date = "2021-08-10".into();

    report.timeline.extend([
        event(
            "Microsoft-Windows-WHEA-Logger",
            18,
            EventLevel::Error,
            now - Duration::days(2),
        ),
        event(
            "Microsoft-Windows-WHEA-Logger",
            18,
            EventLevel::Error,
            now - Duration::days(1),
        ),
        event(
            "Microsoft-Windows-WHEA-Logger",
            17,
            EventLevel::Warning,
            now - Duration::hours(6),
        ),
    ]);

    report.crashes = vec![
        crash(
            0x124,
            now - Duration::days(2),
            CrashAttribution::Undetermined,
            None,
        ),
        crash(
            0x124,
            now - Duration::days(1),
            CrashAttribution::Undetermined,
            None,
        ),
    ];

    report
}

/// A machine where a specific third-party driver was executing at the moment of
/// each crash.
pub fn driver_fault_machine() -> DiagnosticReport {
    let now = Utc::now();
    let mut report = healthy_machine();

    report.drivers.push(vendor_driver(
        "flaky.sys",
        "Acme Peripherals",
        DriverCategory::Usb,
        0xFFFF_F800_0700_0000,
        0x20000,
    ));

    report.crashes = vec![
        crash(
            0xD1,
            now - Duration::days(2),
            CrashAttribution::ModuleRange {
                module: "flaky.sys".into(),
            },
            Some(0xFFFF_F800_0700_1234),
        ),
        crash(
            0xD1,
            now - Duration::hours(10),
            CrashAttribution::ModuleRange {
                module: "flaky.sys".into(),
            },
            Some(0xFFFF_F800_0700_4321),
        ),
    ];

    report
}

/// A machine with a failing disk.
pub fn failing_disk_machine() -> DiagnosticReport {
    let now = Utc::now();
    let mut report = healthy_machine();

    for hours in [2, 8, 20, 30, 44, 60] {
        report.timeline.push(EventRecord {
            source: "Disk".into(),
            channel: "System".into(),
            event_id: 7,
            timestamp: now - Duration::hours(hours),
            level: EventLevel::Error,
            message: "The device, \\Device\\Harddisk1\\DR1, has a bad block.".into(),
        });
    }

    report
}

/// A machine that was stable until a driver landed.
pub fn regression_machine() -> DiagnosticReport {
    let now = Utc::now();
    let mut report = healthy_machine();
    report.scan_window = ScanWindow::last_days(30);

    let broke_at = now - Duration::days(4);
    report.recent_changes = vec![
        SystemChange {
            name: "NVIDIA Display Driver 581.29".into(),
            date: broke_at - Duration::hours(5),
            change_type: ChangeType::Driver,
            version: Some("581.29".into()),
        },
        SystemChange {
            name: "Some App 2.1".into(),
            date: now - Duration::days(25),
            change_type: ChangeType::Software,
            version: Some("2.1".into()),
        },
    ];

    report.crashes = vec![
        crash(0x116, broke_at, CrashAttribution::Undetermined, None),
        crash(
            0x116,
            broke_at + Duration::days(1),
            CrashAttribution::Undetermined,
            None,
        ),
        crash(
            0x116,
            now - Duration::hours(8),
            CrashAttribution::Undetermined,
            None,
        ),
    ];

    report
}

/// A machine carrying a known-vulnerable driver with protections switched off.
pub fn vulnerable_driver_machine() -> DiagnosticReport {
    let mut report = healthy_machine();

    report.security.hvci_enabled = Some(false);
    report.security.driver_blocklist_enabled = Some(false);

    let mut driver = vendor_driver(
        "RTCore64.sys",
        "MSI",
        DriverCategory::Monitoring,
        0xFFFF_F800_0800_0000,
        0x8000,
    );
    driver.vulnerability = crate::modules::analysis::loldrivers::lookup("RTCore64.sys", None);
    report.drivers.push(driver);

    report
}

/// A machine with several tools fighting over the sensor bus.
pub fn sensor_contention_machine() -> DiagnosticReport {
    let mut report = healthy_machine();
    report.drivers.extend([
        vendor_driver(
            "RTCore64.sys",
            "MSI Afterburner",
            DriverCategory::Monitoring,
            0xFFFF_F800_0900_0000,
            0x8000,
        ),
        vendor_driver(
            "AsIO3.sys",
            "ASUSTeK",
            DriverCategory::Rgb,
            0xFFFF_F800_0910_0000,
            0x9000,
        ),
        vendor_driver(
            "AMDRyzenMasterDriver.sys",
            "AMD",
            DriverCategory::Overclocking,
            0xFFFF_F800_0920_0000,
            0xA000,
        ),
    ]);
    report
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

pub fn os_driver(name: &str, base: u64, size: u32) -> DriverInfo {
    DriverInfo {
        name: name.into(),
        path: format!("C:\\Windows\\System32\\drivers\\{name}"),
        version: "10.0.26100.1".into(),
        publisher: name.into(),
        description: format!("Loaded kernel module: {name}"),
        company: "Microsoft Corporation".into(),
        hash: None,
        base_address: base,
        size,
        signature: SignatureStatus::Catalog {
            signer: "Microsoft Windows Publisher".into(),
        },
        is_os_driver: true,
        category: DriverCategory::Other,
        vulnerability: None,
    }
}

pub fn vendor_driver(
    name: &str,
    company: &str,
    category: DriverCategory,
    base: u64,
    size: u32,
) -> DriverInfo {
    DriverInfo {
        name: name.into(),
        path: format!("C:\\Windows\\System32\\drivers\\{name}"),
        version: "1.2.3.4".into(),
        publisher: name.into(),
        description: format!("Loaded kernel module: {name}"),
        company: company.into(),
        hash: None,
        base_address: base,
        size,
        signature: SignatureStatus::Embedded {
            signer: company.into(),
        },
        is_os_driver: false,
        category,
        vulnerability: None,
    }
}

pub fn event(source: &str, id: u32, level: EventLevel, at: DateTime<Utc>) -> EventRecord {
    EventRecord {
        source: source.into(),
        channel: "System".into(),
        event_id: id,
        timestamp: at,
        level,
        message: format!("{source} reported event {id}."),
    }
}

pub fn crash(
    code: u32,
    at: DateTime<Utc>,
    attribution: CrashAttribution,
    address: Option<u64>,
) -> CrashRecord {
    CrashRecord {
        timestamp: at,
        bugcheck_code: code,
        bugcheck_name: crate::modules::analysis::bugcheck::name(code).to_string(),
        parameters: [0, 0, 0, address.unwrap_or(0)],
        faulting_module: attribution.module().map(|m| m.to_string()),
        faulting_address: address,
        attribution,
        dump_path: format!("C:\\Windows\\Minidump\\{}.dmp", at.format("%m%d%y-01")),
        source: CrashSource::KernelDump,
    }
}

pub fn service(name: &str, exit_code: u32, corroborated: bool) -> ServiceState {
    ServiceState {
        name: name.into(),
        display_name: name.into(),
        status: "Stopped".into(),
        exit_code,
        service_specific_exit_code: 0,
        corroborated_by_log: corroborated,
    }
}

pub fn device(name: &str, problem_code: u32) -> DeviceState {
    DeviceState {
        name: name.into(),
        device_id: format!("PCI\\VEN_TEST&DEV_{problem_code:04X}"),
        problem_code: Some(problem_code),
        problem_name: crate::modules::providers::device_inspector::problem_name(problem_code)
            .to_string(),
        status: format!("Code {problem_code}"),
    }
}
