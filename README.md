# WinSleuth

**WinSleuth** diagnoses Windows instability: blue screens, freezes, hardware
errors and driver conflicts. It gathers the evidence Windows already has,
correlates it, and tells you what it thinks is wrong — with the reasoning
attached, so you can disagree.

It is built to be trustworthy rather than exhaustive. A finding it cannot
support, it does not make.

## What it does

- **Names the driver that crashed you.** Parses crash dumps directly — no
  WinDbg, no symbol setup. For x64 small kernel dumps, the faulting instruction
  pointer is resolved against image ranges saved in the dump, even after a
  reboot or driver removal. Unsupported dumps remain unattributed.
- **Finds known-vulnerable drivers.** Every loaded kernel driver is hashed and
  checked against a curated list of drivers routinely abused to disable
  security software from the kernel, plus the full
  [loldrivers.io](https://www.loldrivers.io) corpus once fetched. It also
  reports whether Memory Integrity is actually switched on.
- **Says when it broke.** Finds the point your crash rate changed and lists the
  updates, installs and driver packages that landed around it.
- **Verifies signatures properly.** Catalog-signed drivers — which is nearly all
  of them — are recognised as signed, and WHQL-attested vendor drivers are not
  mistaken for operating system components.
- **Ranks by confidence.** Findings that describe the same underlying fault are
  merged, so WHEA errors plus a `0x124` stop code plus old firmware become one
  hardware verdict rather than three competing ones.
- **Tells you what it could not see.** An unelevated scan reports which evidence
  was unavailable instead of concluding that the machine is healthy.

## Install

Requires [Rust](https://rustup.rs/) and Windows 10 or 11.

```powershell
cargo build --release
.\target\release\winsleuth.exe --help
```

Most commands want Administrator rights. Without them Windows hides crash dumps,
service state and kernel module addresses, and the scan says so.

## Use

```powershell
# The main event. Add --elevate to raise a UAC prompt.
winsleuth scan --elevate

# Look further back
winsleuth scan --days 30

# A page you can share, written as UTF-8
winsleuth scan --format html --output report.html

# Everything a support desk asks for, redacted, in one zip
winsleuth collect --output evidence.zip

# Fetch the vulnerable-driver corpus (the only command that touches the network)
winsleuth update-blocklist

# Watch for crashes as they happen
winsleuth monitor --webhook "https://discord.com/api/webhooks/..."

# Compare against your last scan
winsleuth diff

# Prove a suspect driver guilty
winsleuth verify --suspects
```

`winsleuth ui` opens a desktop window over the same engine.

### A note on `verify`

`winsleuth verify --suspects` arms Driver Verifier against the drivers the scan
actually implicated. This is the definitive way to catch a misbehaving driver
and it can leave a machine unable to boot. It prints the recovery procedure and
asks for confirmation before changing anything; `winsleuth verify --off` reverts
it, and works from Safe Mode.

## How it is built

```
src/modules/
  providers/   Collect raw state: drivers, events, dumps, devices, changes
  core/        Normalise, correlate, score, persist
  analysis/    Heuristics, stop-code decoding, changepoint search
  ui_layer/    Console, HTML, JSON, desktop, evidence bundles
```

Providers sit behind traits and run concurrently. Rules emit *findings*; the
engine merges findings that share a root cause and ranks the result. The
[white paper](docs/WHITE_PAPER.md) describes the method; the
[user guide](docs/USER_GUIDE.md) covers day-to-day use.

## Tests

```powershell
cargo test
```

The suite runs against fixture machines (healthy, failing disk, hardware fault,
driver fault, regression, vulnerable driver) and against the real machine it is
running on. The most important test asserts that a healthy machine produces no
findings at all.

## License

Dual-licensed under [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your
option.

Unless you state otherwise, any contribution you intentionally submit for
inclusion in this work, as defined in Apache-2.0, shall be dual licensed as
above, without additional terms or conditions.
