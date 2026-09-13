# WinSleuth User Guide

WinSleuth works out why a Windows machine is unstable. It reads the evidence
Windows already keeps — crash dumps, event logs, driver signatures, install
history — and tells you what it thinks is wrong, with the reasoning shown.

## Contents

1. [Before you start](#1-before-you-start)
2. [Running a scan](#2-running-a-scan)
3. [Reading the report](#3-reading-the-report)
4. [Known-vulnerable drivers](#4-known-vulnerable-drivers)
5. [Watching for crashes](#5-watching-for-crashes)
6. [Getting help from someone else](#6-getting-help-from-someone-else)
7. [Proving a driver guilty](#7-proving-a-driver-guilty)
8. [Tracking a machine over time](#8-tracking-a-machine-over-time)
9. [When something does not work](#9-when-something-does-not-work)

---

## 1. Before you start

**Windows 10 or 11.**

**Administrator rights.** This matters more than it sounds. Without elevation
Windows will not let any process read the crash dump directory, enumerate
service state, or see kernel module addresses — and kernel addresses are what
crash attribution depends on. An unelevated scan is not merely less detailed; it
can miss the whole problem.

WinSleuth tells you when it is running degraded, both at the top of the report
and again in the "What could not be collected" section. It will never report a
clean bill of health without noting that it was running blind.

The easiest way to elevate:

```powershell
winsleuth scan --elevate
```

That raises a UAC prompt and re-runs itself. You can also just start your
terminal as Administrator.

**Network access** is only needed for `winsleuth update-blocklist` and for
webhook alerts. Nothing else contacts anything.

---

## 2. Running a scan

```powershell
winsleuth scan
```

The default window is seven days. Widen it when the problem is older, or when a
scan finds nothing:

```powershell
winsleuth scan --days 30
```

### Saving the report

```powershell
winsleuth scan --format html --output report.html
winsleuth scan --format json --output report.json
```

Use `--output` rather than shell redirection. PowerShell's `>` writes UTF-16
with a byte order mark, which most JSON parsers reject; `--output` writes UTF-8.

Every scan is also saved to `%LOCALAPPDATA%\WinSleuth\snapshots` so you can
compare later. `--no-save` skips that.

### Making it faster

`--no-hashes` skips SHA-256 hashing of every driver. It shaves a few seconds off
but disables exact matching against the vulnerable-driver corpus, so name
matching is all that remains.

---

## 3. Reading the report

The report leads with **Ranked causes**, because that is what you came for.
Everything below it is the supporting inventory.

Each cause carries:

- **A confidence level** — Low, Moderate, High or Certain. Certain requires a
  high score *and* at least two independent rules agreeing.
- **A score out of 100.** Independent evidence for the same cause accumulates
  without ever reaching absolute certainty: two 60% signals give 84%, not 120%.
  Recent evidence outweighs old evidence within the same window.
- **Evidence** — the specific records the finding rests on, with timestamps.
- **What to do** — and, where one exists, a command you can copy.
- **Corroborated by** — which rules contributed. More independent rules means a
  more trustworthy verdict.

### Crashes

System crashes and application crashes are listed separately, because they are
different problems. A stop code like `0x000000D1` means the kernel stopped. An
exception code like `0xC0000409` from a user-mode dump means one program
crashed, which is far less serious.

For each system crash the report states the culprit or says **"culprit: not
established"**. It will not guess. For x64 small kernel dumps, it uses the
driver names and image ranges recorded when the crash happened. This works
after a reboot, even if the driver has since been removed. The evidence labels
this as an image range recorded in the dump. Any current driver version shown
alongside it describes today's installation, not necessarily the crashed build.

Full, bitmap, 32-bit and ARM64 kernel dumps currently provide stop codes only;
their module maps are not yet supported. An unusable module table is reported
under collection coverage when it prevents instruction-address attribution.

### Third-party drivers

Only drivers *not* signed by Microsoft are listed. The count of operating system
drivers checked and excluded is shown at the end, so you know nothing was
quietly skipped.

Note that "signed by Microsoft" means the operating system signature. NVIDIA,
ASUS and MSI drivers are attested through the *Microsoft Windows Hardware
Compatibility Publisher* authority — they carry Microsoft in the signer name but
are third-party drivers and are listed as such.

---

## 4. Known-vulnerable drivers

Some signed, legitimate drivers expose privileged memory, MSR or port I/O access
to any user-mode process. They load normally because they are signed, and they
are routinely brought along by attackers specifically to switch off security
software from the kernel. They also cause instability in their own right.

WinSleuth checks every loaded driver against:

- a **curated list** of the most commonly abused ones, always available offline;
- the **full loldrivers.io corpus** by exact SHA-256, once you have fetched it.

```powershell
winsleuth update-blocklist
winsleuth inspect-drivers --vulnerable-only
```

A hash match means *this exact build* is known-vulnerable. A file-name match is
weaker — the vendor may have shipped a patched build under the same name — and
the report says which kind of match it made.

The report also shows whether **Memory Integrity (HVCI)** and the **Microsoft
vulnerable driver blocklist** are switched on. If a vulnerable driver is loaded
*and* those are off, nothing is stopping it being abused, and the two findings
are merged into one.

---

## 5. Watching for crashes

```powershell
winsleuth monitor
```

This subscribes to the event log rather than polling it, so it costs almost
nothing while idle. It watches for new crash dumps, critical events, and devices
appearing and disappearing.

```powershell
winsleuth monitor --webhook "https://discord.com/api/webhooks/..." --log-file crashes.log
```

Alerts are grouped: a burst of fifty related errors produces one notification,
not fifty. A crash dump always alerts immediately.

Stop it with Ctrl+C, or with **Quit** on the tray icon.

---

## 6. Getting help from someone else

```powershell
winsleuth collect --output evidence.zip
```

Produces the whole set — report, driver inventory, event timeline, machine
details — in one archive. Your user name, machine name and profile paths are
replaced throughout the text files.

Crash dumps are excluded by default. They can contain fragments of whatever was
in memory when the machine crashed, and they are not redactable. Add
`--include-dumps` when someone specifically asks for them.

Look inside before you send it. Only you know what is sensitive on your machine.

---

## 7. Proving a driver guilty

Driver Verifier makes Windows run chosen drivers under hostile conditions until
one breaks a rule, then stops with `0xC4 DRIVER_VERIFIER_DETECTED_VIOLATION`
naming the culprit. It is the definitive answer.

```powershell
winsleuth verify --suspects
```

This scans first and arms Verifier against only the drivers the scan actually
implicated — never every driver on the system, and never a Microsoft one.

**Read what it prints before agreeing.** A machine with Verifier armed against a
genuinely broken driver will often stop during startup and fail to reach the
desktop. To recover:

1. Interrupt startup twice so Windows offers recovery options.
2. Troubleshoot → Advanced options → Startup Settings → Safe Mode.
3. Run `winsleuth verify --off`, or `verifier /reset`.

Verifier also slows the machine noticeably while armed. That is expected.

```powershell
winsleuth verify --status   # what is currently armed
winsleuth verify --off      # turn it off (takes effect next boot)
```

---

## 8. Tracking a machine over time

```powershell
winsleuth history          # every saved scan
winsleuth diff             # this machine now against the last saved scan
```

The diff shows driver versions that changed, drivers added or removed, device
problems that appeared or cleared, and causes that came or went. It is the
fastest way to answer "what changed since it was working?"

---

## 9. When something does not work

**A scan finds nothing but the machine keeps crashing.**
Check the "What could not be collected" section first. If it says Administrator
rights are needed, re-run with `--elevate` — an unelevated scan cannot see crash
dumps at all. Otherwise widen the window with `--days 30`.

**"culprit: not established" on every crash.**
Check collection coverage for unsupported or damaged kernel dump module data.
Attribution currently supports x64 small kernel dumps; it does not depend on
the current boot's driver addresses. Alternatively, the stop code may not carry
a code address. `0x124` and `0x133`, for example, do not directly identify a
driver through their parameters — those are hardware and timing faults.

**A driver is reported as unsigned that should not be.**
Report it. Verification handles catalog signatures, embedded signatures and the
WHQL attestation authority; a false positive here is a bug worth fixing.

**WHEA errors.**
Hardware, not software. Return every clock and voltage to stock — XMP and EXPO
included — and retest before replacing anything.

**Monitor uses too much CPU.**
It should be near zero at idle. If it is not, that is a bug; please report it
with the `--interval` you used.
