# WinSleuth Implementation Plan

Status as of 13 September 2026, v0.3.0.

## 1. Product

An evidence-based diagnostic tool for Windows instability. It aggregates system
signals, correlates them, and ranks likely causes with the reasoning attached.

The governing constraint: **a confident wrong answer is worse than no answer.**
Where the evidence does not support a conclusion, the tool says so.

## 2. Architecture

```
src/modules/
  providers/   Trait-backed collection; each returns a CollectionStatus
  core/        Models, scoring, correlation, engine, history, privilege, watcher
  analysis/    Rules, stop codes, changepoint search, vulnerable-driver corpus
  ui_layer/    Console, HTML, JSON, desktop, evidence bundle
  verifier.rs  Supervised Driver Verifier runs
```

Providers run concurrently. Rules emit findings; the engine merges findings
sharing a root cause and ranks the result.

## 3. Completed

### Phase 1 — Correctness [DONE]
- [x] Catalog-aware signature verification; trust state handles released
- [x] Signer-based OS classification, including the WHQL attestation authority
- [x] Correlation writes to `correlations`, leaving `timeline` intact
- [x] `Win32_Product` replaced with uninstall registry keys
- [x] Causes ranked by confidence then score
- [x] Service findings require corroboration from Service Control Manager events
- [x] Elevation check with per-provider degradation reporting
- [x] Crash attribution bounded by real PE image ranges

### Phase 2 — Evidence [DONE]
- [x] Kernel `DUMP_HEADER` parsing: stop code and all four parameters
- [x] User-mode MDMP parsing, reported separately from system crashes
- [x] x64 small-dump attribution uses saved module ranges across reboots;
  unsupported maps remain unattributed, with no live-address fallback
- [x] `EvtQuery` event reader across six channels, filtered server-side
- [x] `ScanWindow` threaded through every provider; `--days` is live
- [x] Fixture machines, mock-friendly traits, a test per rule

### Phase 3 — Differentiation [DONE]
- [x] Known-vulnerable driver detection: curated table plus loldrivers.io corpus
- [x] Security posture: HVCI, blocklist, Secure Boot, test signing
- [x] Changepoint analysis replacing first-crash change correlation
- [x] Redacted evidence bundle
- [x] Noisy-OR scoring with recency weighting and corroboration-gated confidence

### Phase 4 — Monitoring [DONE]
- [x] `EvtSubscribe` push notifications; targeted telemetry refresh
- [x] Tray menu with Quit; Ctrl+C handling; alert coalescing
- [x] Webhook payloads built with a JSON serialiser
- [x] Snapshot history and `diff`

### Phase 5 — Closing the loop [DONE]
- [x] Supervised Driver Verifier with recovery guidance and confirmation
- [x] Self-contained HTML report
- [x] `--output` writing UTF-8; `--format` as a closed enum
- [x] Shared engine factory; monitor loop moved out of `main`
- [x] Release profile; `.gitignore` corrected

## 4. Verification

`cargo test` runs unit tests per module, a positive and negative case
per rule, and integration tests across the whole pipeline. Provider tests run
against the executing machine and assert invariants that hold whatever its
state.

The load-bearing test is `a_healthy_machine_produces_no_findings_at_all`.

The optional `public_x64_triage_dump_matches_debugger` test checks a public
Rizin dump against Microsoft's debugger. It is ignored by default; the test
documents the fixture URL, local path and command, and verifies its SHA-256.

## 5. Not done

- **Additional kernel dump layouts.** x64 small dumps now use their saved
  module tables across reboots. Full, bitmap, 32-bit and ARM64 kernel module
  maps still need support.
- **ETW DPC/ISR latency tracing.** Needs a kernel `PerfInfo` session. Valuable
  for audio dropouts and `DPC_WATCHDOG_VIOLATION`, and substantial work.
- **Symbolisation.** Resolving a faulting address to a function name via the
  public symbol server, rather than only to a module.

## 6. Repository

`build.ps1` remains tracked at the repository root but no longer exists on disk;
`dist/winsleuth.exe` and the generated example reports are tracked while being
build output. `Cargo.lock` should be committed — this is a binary crate, so a
reproducible build depends on it. `.gitignore` has been corrected to reflect all
of this; the index changes themselves are left for a deliberate commit.
