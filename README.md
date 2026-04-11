# WinSleuth

**WinSleuth** is a Windows-native diagnostic tool designed to identify low-level system instability, hardware/driver conflicts, and crash correlations.

## 🚀 Quick Links
- **[User Guide](docs/USER_GUIDE.md)**: How to install and use WinSleuth.
- **[White Paper](docs/WHITE_PAPER.md)**: Technical architecture and heuristic methodology.

## 🌟 Key Features
- **Hardware Inventory:** Collects Motherboard, BIOS, CPU, and device details.
- **Driver Audit:** Identifies suspicious third-party drivers (RGB, Monitoring, Overclocking).
- **Event Correlation:** Links BugCheck and Kernel-Power events with recent system changes.
- **Heuristic Engine:** Ranks causes by confidence and provides supporting evidence.
- **Live Monitoring:** Real-time system monitoring with optional Discord/Slack webhooks.

## 🔧 Architecture
The tool is built in Rust with a modular design:
- `system_inventory`: Hardware and firmware collection.
- `driver_inventory`: Kernel driver enumeration and categorization.
- `eventlog_reader`: Direct Windows Event Log processing.
- `heuristics_engine`: Rule-based suspicion scoring.
- `reporting`: Text and JSON output formatting.

## 💻 Usage
```powershell
# Run a full system scan
.\winsleuth.exe scan

# Start live monitoring
.\winsleuth.exe monitor
```

## 📜 License
Licensed under either of
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
at your option.

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
