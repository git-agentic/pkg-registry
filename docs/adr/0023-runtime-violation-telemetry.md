# ADR-0023: Runtime violation telemetry (sandbox-as-sensor + fleet quarantine)

**Status:** Accepted (Phase 10)
**Date:** 2026-07-07

## Context

Phases 3–6 made the sandbox **contain** a denied capability — a blocked
credential read or exfil attempt fails the child process, but the failure is
silent. To an installer it looks indistinguishable from an ordinary build
hiccup (a flaky `postinstall`, a missing native toolchain): the sandbox did
its job, but nobody downstream learns that a specific package just tried to
read `~/.npmrc` or dial out to a non-approved host. Phase 10 turns the
already-enforcing sandbox into a **sensor**: it infers a violation from a
child's failure, reports it, and lets the fleet act on it without touching
the deterministic score.

## Decision

- **Inference from the known deny set, not a new detection mechanism.**
  `computeDenySet(approved, { homeDir, platform })`
  (`packages/sandbox/src/deny-set.ts`) derives the same `deniedPaths` /
  `networkDenied` the profile/`bwrap` generators already enforce — one
  function shared by `profile.ts`, `bwrap.ts`, and the sensor, so attribution
  can never drift from what is actually denied. `classifyViolation(result,
  denySet)` (`packages/sandbox/src/violation.ts`) is **pure and total**
  (never throws): it inspects a failed child's `exitCode`/`stderr` for a
  permission-error signature, then attributes it —
  - **`confirmed`**: an EPERM/EACCES filesystem line whose target is covered
    (`pathCovers`) by an entry in `deniedPaths`, or a `connect EPERM/EACCES
    host:port` under `networkDenied`.
  - **`suspected`**: a class-level network deny (`connect EPERM/EACCES`) with
    no parseable `host:port` to attribute.
  - **`null`**: exit `0` (nothing surfaced), no permission-error signature at
    all (an ordinary build failure), or a permission error on a path that is
    **not** in the deny set (ambient — not our sandbox). This last case is
    the false-positive filter: the deny set is ground truth, so an EPERM the
    sandbox didn't cause is never misreported as a violation.
- **Sensor in the runners, reporter in the shell, store + gate in the proxy.**
  Both `SeatbeltSandbox` and `BubblewrapSandbox` attach the classification to
  `SandboxResult.violation`. `sentinel-script-shell` — already the enforcement
  point for every dependency script (ADR-0019) — best-effort POSTs a detected
  violation to `POST /-/violations` (resolving the served integrity via the
  `/-/manifest` fetch it already makes for approval resolution); a reporting
  failure (unreachable proxy, non-2xx, malformed JSON) is swallowed and never
  changes the install's exit code (telemetry can't become a new failure mode).
  Root-install scripts are not reported — only dependency scripts, where
  `sentinel-script-shell` already resolves an integrity to key the report by.
  The proxy's `ViolationStore` (`packages/proxy/src/violations.ts`) records by
  `integrity`: **confirmed ⇒ quarantined** (and the standing approval, if any,
  is revoked); **suspected ⇒ record-only**, surfaced but not gated.
- **The quarantine is a serve-time overlay, never a score mutation.**
  `applyQuarantine` (`packages/proxy/src/server.ts`) runs at the tarball
  serve gate (`gateAndSend`) and in `audit-tree`'s per-row audit — the two
  places a gated verdict actually blocks something. `/-/audit` and
  `/-/manifest` return the un-overlaid static report; the tarball route's
  403 at install time is the actual enforcement point, so those read-only
  endpoints reporting the pre-overlay verdict doesn't open a gap. When the
  integrity is quarantined, `applyQuarantine` returns a **shallow copy**
  of the report (`{ ...report, verdict: "block", findings: [finding,
  ...report.findings] }`) with a `weight: 0` critical `runtime-violation`
  finding prepended. The cached `AuditReport` in `AuditStore` is never
  written to; the numeric score on that cached object is untouched. This
  preserves invariant #1 (scoring is deterministic given a policy) exactly:
  the *score* stays whatever the static rules produced, and the *verdict*
  override is a presentation-layer fact about the integrity's runtime
  history, applied fresh on every serve rather than baked into stored state.
  `x-sentinel-violations` surfaces the flag as a header alongside the
  existing `x-sentinel-score`/`x-sentinel-verdict`.
- **Integrity-scoped, fleet-wide.** Because `ViolationStore` keys on
  `(name, version, integrity)`'s immutable `integrity` (invariant #4), one
  confirmed violation anywhere in the fleet quarantines that exact tarball
  everywhere it's served from — the same bytes that leaked a violation once
  will keep serving `block` until an operator clears the record
  (`DELETE /-/violations/:integrity`).

## Best-effort limitation

The sensor only sees violations that **surface as process failure**. A
package whose exfil attempt is silently swallowed by its own error handling
(the process still exits `0`, or logs and continues past the denied call)
leaves no signal for `classifyViolation` to classify — `exitCode === 0`
short-circuits to `null` before any pattern match runs. This is a detection
gap, **not a containment gap**: the sandbox still denied the underlying
syscall (kernel-level Seatbelt/bwrap enforcement, unchanged since Phase 6);
the package's exfil attempt failed exactly as it would have without Phase
10. Telemetry is strictly additive visibility on top of unchanged
containment. The `violation-fs-probe`/`violation-net-probe` fixtures are
deliberately built to **propagate** the denial (crash instead of swallow),
demonstrating the detectable path; `enforce-probe` (Phase 6) is left
swallowing on purpose, to keep a fixture on record that shows containment
holding even when telemetry can't see it.

## Auth posture

`POST /-/violations` is unauthenticated this phase, the same posture as the
existing unauthenticated `/-/approvals` (ADR-0011/0013) — there is no
per-tenant identity model yet to authenticate against. The blast radius of a
spoofed report is bounded on two sides: the endpoint 400s unless
`store.get(integrity)` already has an audited report for that integrity
(`server.ts`'s `/-/violations` handler), so a spoofed violation can only
target an already-audited, real tarball — it can't invent quarantine for an
integrity the proxy has never seen; and `applyQuarantine` can only ever
force `verdict: "block"`, never relax a verdict. The worst a spoofed report
achieves is a **fail-closed denial-of-service** against one legitimate
package's integrity — never a bypass that lets a malicious tarball serve as
`allow`. Authenticating the endpoint (so only the reporting shell, not an
arbitrary caller, can quarantine) is deferred multi-tenant work.

## Consequences

- A single confirmed violation quarantines the noisy majority case for free —
  most real attacks that get this far (an exfil attempt that actually tries
  and fails, rather than swallowing) will crash loudly enough to be
  `confirmed`, and the fleet-wide integrity key means one detection protects
  every other install of the same bytes.
- The deny set used for attribution must never drift from what the profile
  generators actually enforce — if it did, `classifyViolation` could falsely
  attribute (or fail to attribute) a violation against a resource the
  sandbox doesn't actually deny. This is locked by
  `deny-set.test.ts`'s **non-drift test**, which asserts every
  `computeDenySet` path appears in the generated Seatbelt profile — a shared
  source of truth (`computeDenySet`) rather than a second hand-maintained
  list.
- The false-positive filter (target must be a member of the deny set,
  checked via `pathCovers`) means an ambient permission error unrelated to
  the sandbox (a genuinely broken build, a real filesystem permission issue
  on the host) is never misreported as a runtime violation — `null` is
  returned instead of a low-confidence guess.
- `runtime-violation` reuses the existing `install-script` category (no new
  `Category` added) — an `allow` waiver scoped to that category would also
  waive a runtime-violation quarantine finding; operators who want to keep
  runtime-violation gating even while waiving other `install-script` noise
  should waive by `ruleId`, mirroring the same caution ADR-0022 already
  raised for `provenance`/`integrity-mismatch`.
- `SENTINEL_VIOLATIONS` persists the store to a JSON file the same way
  `SENTINEL_STORE`/`SENTINEL_APPROVALS` persist their stores; unset, it's
  in-memory only and quarantine state doesn't survive a proxy restart.

## Deferred

- A tracer or LD_PRELOAD-style shim to detect swallowed denials (violations
  that never surface as process failure) — out of scope for a best-effort,
  stderr-pattern sensor.
- Authenticating `/-/violations` so only the reporting shell (not an
  arbitrary caller) can submit a report.
- Auto-quarantining on `suspected` confidence, once false-positive rates on
  class-level network denies are better understood.
- Cross-version propagation (quarantining every version of a package once
  one version is confirmed malicious, rather than the one exact integrity).
- A central telemetry service aggregating violations across proxies/fleets,
  rather than one proxy's local `ViolationStore`.

## Rejected

- **Scraping OS-level audit/security logs** (`log show` on macOS,
  `auditd`/`journald` on Linux) for denial events instead of parsing child
  stderr — probed and rejected: these logs are unavailable to an
  unprivileged process in the common case (no `sudo`, no special
  entitlement), and would make the sensor's operation depend on host
  configuration outside the sandbox's own control. Attribution from the
  child's own exit signal, using the exact deny set the runner already
  computed, needs no privilege and no host-specific log format.
- **Feeding violations into the static score** (adjusting `runAudit`/`score`
  so a quarantined integrity gets a lower cached score) — rejected outright:
  this breaks invariant #1 (scoring is deterministic given a policy; same
  input + same policy ⇒ same score, always). A runtime violation is
  learned *after* the tarball is already scored and cached; folding it into
  the score would make the same audit input produce a different score
  depending on what happened to run afterward. The serve-time overlay gets
  the same practical effect (an installer sees `block`) without that
  invariant break.

Extends ADR-0016 (macOS Seatbelt sandbox), ADR-0017 (env scrub + write
confinement — the deny set the sensor attributes against), ADR-0018
(cross-platform backends — both runners attach `SandboxResult.violation`
uniformly), ADR-0019 (enforced script-shell — the reporting point),
ADR-0013 (approval/reconcile overlay — the precedent for a mutable,
integrity-keyed proxy-side gate layered on top of an immutable cached
report), and ADR-0002 (deterministic scoring — the invariant the serve-time
overlay is built to preserve, not to violate). Supersedes nothing.
