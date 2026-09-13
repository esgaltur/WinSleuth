# WinSleuth

**Method and architecture for automated Windows instability diagnosis**

## Abstract

Windows keeps most of the evidence needed to explain an unstable machine, spread
across crash dumps, several event log channels, the driver store, the PnP
subsystem and the installer's own history. Correlating it by hand is slow and
error-prone. WinSleuth automates the collection and applies a rule-based engine
to rank the likely causes.

The design constraint that shapes everything below is that a diagnostic tool's
only asset is that its output can be trusted. A confident wrong answer is worse
than no answer, because the reader acts on it. Every mechanism here is built so
that when the evidence does not support a conclusion, the tool says so.

## 1. What goes wrong, and why it is hard

Instability on a modern Windows machine typically comes from one of:

- failing or out-of-spec hardware (CPU, memory, storage, power delivery);
- a defective kernel-mode driver;
- several low-level utilities contending for the same hardware interfaces;
- firmware that predates the hardware or workload it is running;
- a specific change — an update, a driver, an install — that broke a machine
  that was previously stable.

Each leaves traces, but in different places and different formats, and the
traces of an *effect* look much like the traces of a *cause*. A service crashing
after a disk error is a symptom. Naming it as the problem sends the reader in
the wrong direction.

## 2. Architecture

Four layers, with the data flowing one way.

```
providers  →  core  →  analysis  →  ui_layer
 collect     normalise   heuristics   present
             correlate   scoring
```

### 2.1 Providers

Each source of system state sits behind a trait, so it can be substituted for a
fixture in tests. Every provider takes the scan window and returns its result
paired with a **collection status**: complete, partial with a reason, or failed
with a reason. That status reaches the report. Silent degradation — returning an
empty list because access was denied — is the failure mode this design exists to
prevent.

| Provider | Source | Notes |
| --- | --- | --- |
| `SystemInventoryProvider` | WMI, sysinfo | Includes boot time for reporting |
| `FirmwareInventoryProvider` | `Win32_BIOS` | Release date parsed, not passed through raw |
| `DriverInventoryProvider` | `Win32_SystemDriver`, `EnumDeviceDrivers` | Signature, PE image size, hash, category |
| `EventLogProvider` | `EvtQuery` | Multiple channels, filtered server-side by time |
| `DeviceInspectorProvider` | SetupAPI, `CM_Get_DevNode_Status` | Problem codes with their documented meaning |
| `ServiceProvider` | Service Control Manager | Candidates only; corroborated later |
| `ChangeProvider` | Uninstall registry keys, QFE, `oem*.inf` | Never `Win32_Product` — see §5 |
| `MinidumpProvider` | `DUMP_HEADER`, MDMP | Both kernel and user-mode dumps |
| `SecurityPostureProvider` | `Win32_DeviceGuard`, registry | HVCI, blocklist, Secure Boot |

Providers run concurrently. Each opens its own WMI connection, so they are
independent.

### 2.2 Correlation

Correlation produces `CrashWindow` values *alongside* the timeline: the crash,
plus the events within five minutes either side, nearest first. The timeline
itself is never modified. This matters because every rule reads the timeline
after correlation runs; a correlation step that filtered it in place would make
rules under-report on exactly the machines that had crashed.

Crash markers in the log with no dump behind them — a Kernel-Power 41, a
BugCheck 1001 whose dump was deleted — get their own window, because a machine
that lost power is still a machine that went down.

### 2.3 Rules and findings

A rule returns zero or more **findings**, not a finished verdict. A finding
carries a base weight, its evidence, its recommendation, when it was last
observed, and — the important part — a **root cause key**.

Returning a collection rather than an option lets one rule report several
distinct instances: two failing disks are two findings, not one averaged
sentence.

### 2.4 Scoring

The engine groups findings by root cause key and combines each group.

**Combination is noisy-OR.** For findings with effective weights `wᵢ` in `[0,1]`:

```
combined = 1 − ∏(1 − wᵢ)
```

Independent evidence accumulates without ever reaching certainty. Two 60%
signals give 84%. Twelve 95% signals still give less than 100%.

**Effective weight applies recency.** Evidence is weighted by where it falls in
the scan window, from 1.0 at the end down to a floor of 0.4 at the start. The
floor matters: stale evidence is weaker, not worthless.

**Confidence needs agreement, not just magnitude.** `Certain` requires a
combined score of 90 or more *and* at least two independent rules contributing.
A single very strong rule reaches `High` and stops there.

The practical effect: WHEA events, a `0x124` stop code and out-of-date firmware
are three rules describing one hardware fault. They merge into a single
`Certain` hardware verdict instead of three unrelated entries competing for the
reader's attention.

## 3. Crash attribution

This is where a diagnostic tool is most tempted to overreach, and where a wrong
answer does the most damage.

**Kernel dumps** begin with a `DUMP_HEADER`, not the `MDMP` container. The
bugcheck code and its four parameters sit at documented offsets and are read
directly.

Turning that into a culprit requires two things to hold.

First, **the stop code must document one of its parameters as a code address.**
Only some do. `0x0A` and `0xD1` put the referencing address in parameter 4;
`0x1E`, `0x3B`, `0x7E` and `0x8E` put the instruction address in parameter 2;
`0x50` puts it in parameter 3. The `0x1000007E` and `0x1000008E` variants use
the same parameters as their base codes. Everything else returns
nothing. `0x124`'s parameters point at WHEA error records; `0x133`'s carry
timing counts. Reading an address out of those produces a confident lie.

Second, **the address must resolve inside a module's real image range.** The
range comes from the saved loader entry's `DllBase` and `SizeOfImage` in an x64
small kernel dump. A module with an unknown size never claims an address. The
alternative — nearest base address below, with a
tolerance — will regularly name a driver dozens of modules away from the real
one.

Kernel ASLR re-bases modules on each boot, so the current module list is never
used for kernel attribution. File modification time cannot prove boot identity:
copying an old dump can change that timestamp. The x64 triage reader instead
reads the driver table and UTF-16 string pool saved in the dump. It validates
the format, completion marker, file bounds, counts, names and non-overlapping
image ranges before accepting the table. Reads and allocations are bounded;
the entire memory dump is never loaded just to find a module.

`DumpModuleRange` records the module name, saved base and image size in the
report. This supports attribution after reboot and driver removal. Current
driver versions are explicitly labelled as current inventory. Unsupported
layouts and malformed tables remain unattributed, with collection degradation
reported when a code address could not be resolved because module data was
unavailable. No match in an otherwise valid table is also a legitimate result.

**User-mode dumps** are ordinary MDMP containers carrying their own module list
and exception record, so the faulting address resolves without any of the above
caveats. They are also not system crashes, and are reported separately: an
exception code such as `0xC0000409` is not a stop code, and presenting the two
together tells the reader the machine blue-screened when it did not.

## 4. Signature verification

Nearly every Windows driver carries no embedded Authenticode signature; the
signature lives in a `.cat` file in the driver store. Verifying only
`WTD_CHOICE_FILE` returns `TRUST_E_NOSIGNATURE` for all of them, which
misreports the entire operating system as unsigned.

Verification therefore hashes the file, looks the hash up with
`CryptCATAdminEnumCatalogFromHash`, and verifies through `WTD_CHOICE_CATALOG`,
falling back to embedded verification. The result is three-state —
catalog-signed, embedded-signed, or genuinely unsigned — plus a fourth state for
"could not be verified", which is deliberately not evidence of anything.

The signer's display name is extracted from the trust provider state, and this,
rather than the file's folder, decides whether a driver is an operating system
component. Two subtleties:

- `System32\DriverStore\FileRepository` holds *vendor* drivers, so a path test
  gets this backwards.
- Third-party drivers are WHQL-attested through the *Microsoft Windows Hardware
  Compatibility Publisher* authority. NVIDIA, ASUS and MSI drivers all carry
  "Microsoft" in the signer name while being emphatically not part of Windows.
  Matching the substring hides every vendor driver from the report, including
  the vulnerable ones.

## 5. Observing without disturbing

A tool that diagnoses instability must not itself perturb the system.

Enumerating the WMI class `Win32_Product` makes the Windows Installer run a
consistency check against every registered MSI and will reconfigure or repair
packages as a side effect. It takes minutes and fills the Application log with
its own events, which the tool would then read back as evidence. Installed
software is read from the uninstall registry keys instead.

The same principle governs monitoring. Live watching uses `EvtSubscribe`, so
Windows signals the process when records arrive; polling would mean re-reading
the log on every tick. Telemetry refreshes only CPU and memory rather than
enumerating every process. Network access happens only when explicitly
requested.

## 6. Known-vulnerable drivers

Every loaded driver is hashed. Those hashes are checked against a curated table
of drivers with documented privilege-escalation primitives — arbitrary physical
memory mapping, MSR access, unrestricted port I/O — and, when the user has
fetched it, the full loldrivers.io corpus.

The two match types are weighted differently and labelled differently. An exact
SHA-256 match proves that *this build* is the known-vulnerable one. A file-name
match is a strong hint that the report states as such, because a vendor may have
shipped a patched build under the same name.

This pairs with the security posture check. A vulnerable driver on a machine
with Memory Integrity enabled is a lesser concern than the same driver on a
machine where nothing is stopping it, and the engine merges those two findings
into one verdict.

## 7. Changepoint analysis

"What changed when it broke" is usually the most useful question, and it is
answerable from data already collected.

Each crash time is a candidate boundary. For each, the crash rate before is
compared with the rate after; the split with the greatest increase is the
changepoint. Changes landing within 72 hours of it become suspects.

Two guards keep this honest. At least two crashes must follow the changepoint —
one is an incident, not a trend. And a changepoint with no nearby change is
reported as a date, not as a lead, because a date on its own is not actionable.

Anchoring instead on the *first* crash in the window, as an earlier design did,
fires on the wrong change whenever the instability predates the window, which is
the common case.

## 8. Verification

Every heuristic is a pure function over a `DiagnosticReport`, so all of them are
tested against fixture machines: healthy, failing disk, hardware fault, driver
fault, regression, vulnerable driver, sensor contention.

The load-bearing test is the negative one. **A healthy machine must produce no
findings at all.** Rules that fire on a clean system are what make a diagnostic
tool untrustworthy, and they are invisible without a fixture that has nothing
wrong with it.

Provider tests run against the machine executing them and assert invariants that
hold regardless of its state: nothing outside the scan window is returned; core
operating system drivers verify as signed; loaded modules have plausible image
sizes; saved-range attribution includes a range containing the faulting address.
Synthetic dump tests cover reboot-independent attribution, removed drivers,
exclusive range ends, invalid offsets, excessive counts, malformed UTF-16,
overlapping ranges and truncation. An optional public dump fixture checks the
result against a module range independently verified with Microsoft's debugger.

## 9. Limits

Stated plainly, because a tool that hides its limits is back to being
untrustworthy.

- **Kernel module attribution supports x64 small dumps only.** Full, bitmap,
  32-bit and ARM64 kernel dump module maps are not yet supported. Their stop
  codes are still decoded. Even a supported dump needs a stop code with a
  documented instruction-address parameter; a module match identifies where
  execution faulted, not necessarily the origin of earlier memory corruption.
- **Unelevated scans are substantially blind.** Windows hides crash dumps,
  service state and kernel module addresses from medium-integrity processes.
  The report says so rather than working around it.
- **Name-based vulnerable-driver matching can be wrong** in the safe direction:
  it can flag a patched build. Fetching the hash corpus removes the ambiguity.
- **Heuristics rank leads; they do not prove causes.** Driver Verifier exists in
  the tool precisely because it is the only mechanism here that produces proof.

## 10. Possible directions

- Reading module maps from additional kernel dump layouts.
- ETW-based DPC and ISR latency measurement, for audio dropouts and
  `DPC_WATCHDOG_VIOLATION` — a common complaint with no good command-line tool.
- Symbolisation against the public symbol server, to resolve a faulting address
  to a function rather than only a module.
