# WinSleuth User Guide

WinSleuth is a powerful diagnostic tool designed to help you identify the root causes of Windows system instability. Whether you're dealing with Blue Screens of Death (BSOD), random freezes, or hardware-related errors, WinSleuth can help you find the culprit.

## Table of Contents
1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Basic Usage](#3-basic-usage)
4. [Advanced Commands](#4-advanced-commands)
5. [Understanding the Report](#5-understanding-the-report)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Prerequisites

- **Operating System:** Windows 10 or Windows 11.
- **Privileges:** You must run WinSleuth as **Administrator** to access system event logs, driver information, and hardware diagnostics.
- **Internet (Optional):** Required for sending alerts via Webhooks (Discord/Slack).

## 2. Installation

WinSleuth is currently distributed as a command-line tool. You can download the latest version from the releases page or build it from source.

### Building from Source
If you have [Rust](https://rustup.rs/) installed:
```powershell
# Clone the repository
git clone https://github.com/your-repo/winsleuth.git
cd winsleuth

# Build for release
cargo build --release
```
The executable will be located at `target\release\winsleuth.exe`.

## 3. Basic Usage

WinSleuth's most common task is performing a full system scan.

### Full System Scan
```powershell
.\winsleuth.exe scan
```
This command collects hardware info, driver status, recent system changes, and event logs. It then runs a heuristic analysis to suggest possible causes of instability.

#### Look back further in time
By default, the scan looks at the last 7 days. You can change this:
```powershell
.\winsleuth.exe scan --days 30
```

#### Export to JSON
If you need to share the report with technical support:
```powershell
.\winsleuth.exe scan --format json > report.json
```

## 4. Advanced Commands

WinSleuth offers several specialized commands for deep-diving into specific system components.

### Inspect Drivers
List all third-party and potentially suspicious drivers (e.g., unsigned, monitoring tools):
```powershell
.\winsleuth.exe inspect-drivers
```

### Inspect Devices
View hardware devices that are reporting problem codes (Hardware errors):
```powershell
.\winsleuth.exe inspect-devices
```

### Event Timeline
Generate a chronological timeline of critical system events and crashes:
```powershell
.\winsleuth.exe timeline
```

### Live Monitor
Watch for new critical system events in real-time. This is useful for catching intermittent crashes as they happen:
```powershell
.\winsleuth.exe monitor --interval 5
```
You can also set up a **Discord or Slack Webhook** to get notified on another device:
```powershell
.\winsleuth.exe monitor --webhook "https://discord.com/api/webhooks/..."
```

## 5. Understanding the Report

When you run a `scan`, WinSleuth provides a "Suspected Causes" section. Each cause includes:

- **Source:** The component or log entry that triggered the finding.
- **Evidence:** The specific technical detail (e.g., "Event ID 6008", "Unsigned Driver: RGB_Sync.sys").
- **Confidence:** A score (0-10) indicating how likely this is the primary cause of your issues.
- **Description:** A human-readable explanation of why this is a concern.

## 6. Troubleshooting

- **"Access Denied" or "Missing Logs":** Ensure you are running your terminal (PowerShell or CMD) as **Administrator**.
- **No findings after a crash:** Try increasing the look-back period with `--days 14`.
- **WHEA errors detected:** This often indicates a hardware problem (CPU/Memory/PCIe). Check your motherboard's BIOS version and consider stress-testing your components.
