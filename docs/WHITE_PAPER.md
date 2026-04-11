# WinSleuth White Paper
**Technical Architecture and Heuristic Methodology for Windows System Instability Diagnosis**

## Abstract

Windows system instability often arises from complex interactions between hardware, firmware, and kernel-level drivers. Traditional diagnostic methods often require manual correlation of disparate logs (Event Viewer, Minidumps, Reliability Monitor), which is time-consuming and error-prone. WinSleuth is a modular diagnostic tool built in Rust that automates the collection of system evidence and applies a rule-based heuristic engine to correlate events and identify likely causes of instability.

## 1. Introduction

Modern Windows systems are resilient, yet they remain susceptible to crashes (BSODs) and hangs. Common culprits include:
- Faulty hardware (CPU/Memory/Storage).
- Corrupt or buggy kernel-mode drivers.
- Conflicting system monitoring tools.
- Unstable firmware (BIOS/UEFI).

WinSleuth addresses these challenges by acting as an **evidence aggregator and correlation engine**. It transforms raw system data into actionable intelligence by applying expert-system rules to temporal and causal patterns.

## 2. Technical Architecture

WinSleuth is designed with a **Modular Provider Pattern** to ensure extensibility and testability. The architecture separates data acquisition (Providers) from data analysis (Heuristics).

### 2.1 Data Providers
Each system component is represented by a provider implementing a specific trait. This abstraction allows for easy mocking during testing and facilitates the addition of new data sources.

- **`SystemInventoryProvider`**: Retrieves CPU, Motherboard, and BIOS metadata using WMI (`ROOT\CIMV2`) and SMBIOS data. It identifies hardware versions and BIOS release dates to detect outdated firmware.
- **`DriverInventoryProvider`**: Enumerates all active kernel drivers using the `EnumDeviceDrivers` API. It verifies digital signatures (WHQL) and categorizes drivers based on known problematic patterns (e.g., RGB Control, low-level monitoring).
- **`EventLogProvider`**: Interfaces directly with the Windows Event Log (`EvtNext`) to retrieve critical Error/Warning events. It specifically targets sources like `WHEA-Logger`, `BugCheck`, and `Kernel-Power`.
- **`DeviceInspectorProvider`**: Queries the Plug-and-Play (PnP) subsystem via `SetupDi` APIs for devices reporting problem codes (e.g., Code 10, Code 43).
- **`MinidumpProvider`**: Scans the `%SystemRoot%\Minidump` directory to extract metadata (BugCheck codes, parameters, and timestamps) from recent crash dumps without requiring a full debugger attachment.
- **`ReliabilityReader`**: Accesses the Windows Reliability Monitor data to provide a high-level stability index and historical context of application and system failures.

### 2.2 The Heuristic Engine
The core of WinSleuth is the `WinSleuthEngine`. It coordinates the execution of providers and runs a suite of **Heuristic Rules** against the aggregated evidence. The engine follows a pipeline:
1.  **Collection**: Parallel execution of all registered Providers.
2.  **Normalization**: Converting disparate data formats into a unified `DiagnosticReport`.
3.  **Correlation**: Linking events based on temporal proximity and shared identifiers.
4.  **Evaluation**: Running the Heuristic Rule set to generate `SuspectedCause` objects.

## 3. Heuristic Methodology

WinSleuth does not rely on simple keyword matching. It uses structured rules to evaluate system state and calculate confidence scores.

### 3.1 Temporal Correlation Logic
The engine performs cross-provider correlation to find causal links.
- **Crash Proximity**: If a `BugCheck` (BSOD) is detected, the engine isolates all system events within a ±5 minute window. This window is critical for identifying "precursor" events like driver timeouts or service failures that lead to the crash.
- **Change Correlation**: By tracking system changes (updates, installations), the engine can correlate a sudden onset of instability with a specific software or driver modification.

### 3.2 Key Heuristic Rules
WinSleuth implements several specialized rules:
- **WHEA Analysis**: Identifies hardware-level errors reported by the Windows Hardware Error Architecture. It distinguishes between corrected errors (early warning) and uncorrected errors (immediate crash).
- **BugCheck Decoder**: Translates hexadecimal stop codes (e.g., `0x124`, `0xD1`) into human-readable descriptions and suggests common causes (e.g., `WHEA_UNCORRECTABLE_ERROR` vs. `DRIVER_IRQL_NOT_LESS_OR_EQUAL`).
- **Monitoring Conflict Detection**: Flags instances where multiple tools (e.g., HWInfo, MSI Afterburner, RGB Sync) are polling the same hardware sensors simultaneously, which is a known cause of SMBus/I2C collisions and system hangs.
- **Service & Driver Health**: Correlates service "Start" or "Failure" events with system instability, identifying background processes that may be crashing the kernel.

### 3.3 Scoring and Confidence Algorithm
Each `SuspectedCause` is assigned a confidence score (0.0 to 1.0) derived from:
- **Severity**: The critical nature of the signal (e.g., WHEA Error = 0.9, Unsigned Driver = 0.4).
- **Frequency**: Recurring errors indicate a systemic issue rather than a one-off glitch.
- **Correlation Strength**: Direct temporal links to a system crash provide the highest confidence.

## 4. Implementation Details (Rust)

Leveraging Rust provides memory safety and high performance, which are critical when interacting with kernel-level data and the Windows API.

- **Memory Safety**: Rust's ownership model prevents common bugs like null pointer dereferences or buffer overflows when parsing complex binary structures like Minidumps or Event Log records.
- **`windows-rs` Integration**: Direct binding to the official Windows metadata ensures high-fidelity access to native OS subsystems (WMI, PnP, EventLog) with minimal overhead.
- **Zero-Cost Abstractions**: The use of Traits for Providers and Heuristics allows for a clean, decoupled architecture without sacrificing runtime performance.

## 5. Conclusion and Future Work

WinSleuth provides a structured, automated approach to Windows troubleshooting, reducing the time required to diagnose complex system failures.

### Future Enhancements
- **Deep Minidump Parsing**: Integrating `dbghelp.dll` or a native Rust PE parser to perform automated stack trace analysis and identify the specific faulting module in a crash.
- **Live Kernel Telemetry**: Using Event Tracing for Windows (ETW) to capture real-time driver performance and latency metrics.
- **Machine Learning Integration**: Training a diagnostic model on a large corpus of known BSOD patterns to improve the accuracy of the heuristic scoring.
- **Remote Diagnostics**: Enabling centralized telemetry collection for enterprise IT environments to monitor fleet-wide stability.
