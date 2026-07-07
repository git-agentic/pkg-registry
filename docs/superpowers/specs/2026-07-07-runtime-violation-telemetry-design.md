# Phase 10 — Runtime Violation Telemetry (sandbox as sensor + fleet quarantine)

**Date:** 2026-07-07
**Status:** Approved design, pre-implementation
**Extends:** ADR-0016/0017/0018 (sandbox runners + capability model), ADR-0019
(`sentinel install --enforce` script-shell interposition), ADR-0013 (approval
gate + reconcile overlay), ADR-0002 (deterministic scoring — invariant #1).

## Problem

Sentinel's sandbox (Phases 3–6) is fail-closed: when an install-time lifecycle
script attempts an undeclared or sensitive action, the kernel denies it. But that
denial is **silent** — the child gets an `EPERM`, npm sees a non-zero exit, and a
blocked credential-exfiltration attempt is indistinguishable from an ordinary build
hiccup. The sandbox is a shield; it is not yet a **sensor**.

Phase 10 closes the detect⇔contain loop: turn a sandbox denial into a structured,
attributed **violation event**, report it to the proxy, and **quarantine that exact
build across the fleet** — every subsequent install of the offending integrity, by
anyone, is blocked, backed by real runtime evidence that static analysis missed.
This is the strongest signal the product can emit: proof of attempted malice at
execution time.

## Probe evidence (2026-07-07, this repo's probe-before-spec discipline)

Ran real `sandbox-exec` denials on the darwin dev host:

- **macOS Seatbelt denials are NOT observable in the unified log unprivileged.** A
  `(deny file-read* …)` blocks the read, but `log show` with sender/`deny`
  predicates returns nothing without privilege; SBPL's `(with report)` modifier is
  **rejected on `deny` actions** (`report modifier does not apply to deny action`).
  ⟹ the sensor cannot read the OS log; it must work from what Sentinel already
  controls — the compiled deny set + the child's captured stderr/exit.
- **The child's own error carries the target.** Node surfaces
  `EPERM: operation not permitted, open 'secret/key.txt'` for a denied read and
  `connect EPERM 93.184.216.34:443` for a denied connect — the attempted path/host
  is in the message. Since npm lifecycle scripts are node, stderr gives real target
  attribution for free.
- **Allowed access stays clean** — an approved read under the same profile succeeds
  with no error, so the classifier does not false-trigger on normal execution.
- Phase 5 memory (Linux): bwrap denials surface as `EACCES`/`ENOENT` on the
  `--ro-bind`/tmpfs-denied path; classification must accept those shapes too.

## Decisions (brainstorm outcomes)

1. **Sensor by inference from the known deny set**, not OS-log scraping and not a
   syscall tracer / interposition shim. The sandbox already compiles the exact deny
   set (uncovered `SENSITIVE_PATHS` + network-when-unapproved) and captures the child's
   stderr; a pure classifier correlates a permission-error exit against that set.
   Cross-platform, zero new deps, no privilege. Rejected: strace/dtrace (dtrace is
   SIP-gated on macOS, adds per-script overhead, two output formats) and LD_PRELOAD/
   DYLD shim (a C artifact; dyld insertion is itself SIP-restricted; competes with
   the sandbox's env handling).
2. **A violation is a separate signal layer that never mutates the static score**
   (invariant #1). It layers beside the deterministic 0–100 score exactly like an
   approval or a `deny` — as a serve-time overlay.
3. **Consequence: quarantine** (confirmed violations only) — persist the record,
   auto-revoke the approval, and force `block` on every future serve of that
   integrity fleet-wide. Rejected: flag-only (a caught attack stays installable) and
   record-only telemetry (loop visible but not closed).
4. **Confidence gate** — only high-confidence (`confirmed`) violations auto-
   quarantine; `suspected` ones flag + alert but do not auto-403, bounding the blast
   radius of a best-effort inference sensor.

## Section 1 — Architecture & data flow

Sensor in `@sentinel/sandbox`; reporter in the CLI enforce path; store + gate in the
proxy.

1. **`SandboxResult` gains `violation?: SandboxViolation`.** The Seatbelt (`seatbelt.ts`)
   and bwrap (`bwrap.ts`) runners already know the compiled deny set and capture the
   child's stderr. A new pure `classifyViolation(result, denySet)` in
   `packages/sandbox/src/violation.ts` inspects a non-zero exit and returns a
   `SandboxViolation | null`. The runner attaches it to its `SandboxResult`.
2. **`sentinel-script-shell` reports it.** The enforce chokepoint (`script-shell.ts`)
   already holds `SENTINEL_PROXY`, `name`, `version`, `approved`, and the
   `SandboxResult`. When `result.violation` is present it `POST`s to
   `SENTINEL_PROXY/-/violations` **before** propagating the exit code. A reporting
   failure is swallowed (logged to stderr) and never changes the exit code — the
   install outcome is the sandbox's, not the reporter's.
3. **Proxy persists + quarantines.** A new `ViolationStore` (integrity-keyed, same
   pattern as `ApprovalStore`) records the event; a confirmed one revokes the
   integrity's approval and marks it quarantined; the serve path overlays a critical
   `runtime-violation` finding and forces `block`.

The deterministic static score is never touched — the quarantine is a serve-time
overlay, like today's `deny`/approval overlays (ADR-0013).

## Section 2 — The sensor: classification & false-positive model

`classifyViolation(result: SandboxResult, denySet: DenySet)` is pure and
conservative. The deny set is authoritative ground truth: the sandbox *allows*
everything the package was approved for and *denies* only (a) the `SENSITIVE_PATHS`
entries **not covered** by an approved filesystem capability (`profile.ts` computes
this `uncovered` set today) and (b) all network when no `network` capability was
approved. Any sandbox-*induced* permission error is, by construction, an attempt at
something sensitive or unapproved. The false-positive risk is an *ambient* EPERM
unrelated to our sandbox; **attribution is the filter**.

- **`confirmed`** — stderr matches a permission-error signature (`EPERM`, `EACCES`,
  `operation not permitted`, plus bwrap bind-denial shapes) **and** the extracted
  target falls inside the deny set. Extraction regexes the node shapes:
  `/(?:EPERM|EACCES)[^\n]*?['"]([^'"\n]+)['"]/` for filesystem (the quoted path) and
  `/connect (?:EPERM|EACCES) ([0-9.]+):(\d+)/` for network (host:port). A denied read
  of a path in `SENSITIVE_PATHS` → confirmed, target named. A permission error on a
  path we did **not** deny → ambient → **no event**.
- **`suspected`** — a permission-error signature under a profile that denies the whole
  class (any `connect EPERM` when network is deny-all) but with no attributable
  target string. Network denials are reliably sandbox-caused; targetless filesystem
  ones are lower-confidence.
- **none** — non-zero exit with no permission-error signature (ordinary build
  failure) → `null`.

**Best-effort scope (honest limitation).** The sensor only sees violations that
*surface as process failure* — an uncaught permission error yielding a non-zero exit
with a stderr signature. A script that deliberately catches the `EPERM` and continues
(exit 0, clean stderr — what sophisticated malware does) leaves **no trace** observable
to the parent (OS denial logs are unavailable unprivileged, as probed). This does not
weaken security: **containment is always enforced** (the sandbox blocked the access
regardless, unchanged from Phase 6); Phase 10 adds *telemetry* on top, and telemetry
captures the surfacing subset. Fleet quarantine therefore triggers on the noisy
majority of real payloads (which crash or log), not on a perfectly-silent swallow.
The effect-test and demo fixtures use a **propagating** probe (lets the `EPERM` throw,
or writes it to stderr and exits non-zero) to exercise the detectable path; the ADR
states the swallow-evasion limitation explicitly.

**Event shape (`SandboxViolation`):**

```ts
export interface SandboxViolation {
  kind: "filesystem" | "network" | "process";
  target: string | null;          // extracted path/host:port, or null
  confidence: "confirmed" | "suspected";
  deniedResource: string | null;  // the deny-set entry matched (sensitive path, or "network")
  evidence: { exitCode: number; stderrExcerpt: string }; // matched line, truncated ≤200 chars
}
```

`stderrExcerpt` is the single matched error line, truncated — never full stderr
(redaction-safe, mirrors `Evidence.snippet`). Only `confirmed` auto-quarantines.

`DenySet` is what the runner already computes to build the profile:
`{ deniedPaths: string[]; networkDenied: boolean }` — `deniedPaths` is the
canonicalized/expanded `uncovered` sensitive-path list from `profile.ts` (bwrap's
equivalent for Linux), and `networkDenied` is the `!hasNetwork` flag. The runners
expose it alongside the profile and pass it to `classifyViolation`, so this is a
capture, not a recomputation. For `confirmed`, the extracted `target` must match a
`deniedPaths` entry (via `pathCovers`) or, for network, `networkDenied` must be true.

## Section 3 — Reporting, storage, quarantine

- **`POST /-/violations`** — body is `SandboxViolation & { name, version, integrity }`.
  The proxy validates shape, requires an existing audited report for that integrity
  (the tarball was served, so it is in the `AuditStore`; a violation for an unknown
  integrity is a 400), and records a `ViolationRecord` keyed by integrity. Idempotent
  on `(integrity, kind, target)` — repeated installs of the same bad build don't
  duplicate.
- **Quarantine (confirmed only):** recording a confirmed violation (a)
  `approvals.remove(integrity)` — revokes any standing approval, and (b) sets a
  quarantine flag on the record. The serve path and `reconcile()` consult the store:
  a quarantined integrity gets a synthesized critical `runtime-violation` finding
  injected into the served report and its verdict forced to `block`, so the next
  fetch of that exact build — by anyone — 403s. Overlaid at serve time; the cached
  static `score` is unchanged (invariant #1 intact, same mechanism as `deny`).
- **`suspected`** violations are stored and surfaced but set no quarantine flag —
  they await a human/policy decision.
- **`DELETE /-/violations/:integrity`** — operator override that clears the
  quarantine (mirrors approval revocation).
- **Auth:** `POST /-/violations` is unauthenticated this phase, consistent with the
  trusted-deployment posture of `/-/approvals` (ADR-0013 stage B). A spoofed
  violation can only *quarantine* a package — a fail-closed DoS, not a security
  bypass. Authenticating it is deferred multi-tenant work (ADR-0013/0015 era),
  called out in ADR-0023.

## Section 4 — Surfacing, fixtures, testing

*Surfacing:*
- Header `x-sentinel-violations: <count>` on serve; a quarantined 403 body names the
  violation kind/target/evidence.
- **Dashboard**: a "Runtime violations" panel (sibling of Approvals) — package, kind,
  target, confidence, evidence line; quarantined rows flagged red.
- **`audit-tree`**: a quarantined integrity reports `block` with the violation as its
  top finding; the aggregate gains a `violations` count.
- **CLI**: `sentinel violations` lists recorded events; an enforce run that reports one
  prints a red one-line notice.

*Fixtures (safety-first, mirrors Phase 6's `enforce-probe`):* a new **benign** probe
package whose postinstall *attempts* one denied action and, unlike `enforce-probe`,
**lets the error propagate** (writes the `EPERM` to stderr and exits non-zero) so the
telemetry sensor has a surfacing signal to detect:
- a **filesystem** probe that constructs a `SENSITIVE_PATHS` target from string
  fragments (no `.ssh/id_rsa` literal even in comments), so static analysis emits only
  generic `filesystem:*` (which `pathCovers` treats as covering nothing → approving
  the package never lifts the deny — the honest value proposition: the sandbox
  backstops what static analysis missed);
- a **network** probe connecting to an RFC 5737 documentation IP (`198.51.100.0/24`).

Synthetic, inert, `SYNTHETIC FIXTURE` header; the scripts only try-and-fail then
report the failure — no live malware, ever. Packed via `make-fixtures` like every
fixture. (`enforce-probe` stays as-is — it demonstrates *containment* of a swallowed
denial; the new probes demonstrate *telemetry* of a propagating one.)

*Testing:*
- **Pure unit** (`packages/sandbox/test/violation.test.ts`): `classifyViolation`
  confirmed (target in deny set), suspected (class-denied, no target), none (ambient
  EPERM on a **non-denied** path → no event — the false-positive guard), each with
  real node EPERM stderr strings from the probe.
- **Sandbox effect tests per platform** (Seatbelt on darwin dev host, bwrap on Linux
  CI): drive the real benign probe through `createSandbox()` and assert a `confirmed`
  event, with a **positive control** that the script actually ran (Phase 5's
  vacuous-pass guard — a sandbox-setup abort must not read as a green detection).
- **Proxy e2e**: report → store → approval revoked → next serve of that integrity
  403s with the `runtime-violation` finding; a `suspected` report does **not** 403;
  `DELETE` clears the quarantine.
- **Invariant guard**: the `scoring is deterministic across runs` test stays green — a
  quarantined package's cached `score` is unchanged; only the overlaid verdict flips.

*Definition of done:* `npm run build` clean; `npm test` green (new count recorded in
CLAUDE.md with the darwin-skip caveats preserved); the malicious fixture still
blocked; ADR-0023 recorded; ARCHITECTURE.md extended (§3.11 + the enforce-flow
section); CLAUDE.md phase summary + count; README feature bullet + `sentinel
violations` and the `/-/violations` endpoint.

## Out of scope (deferred beyond Phase 10)

- Authenticating `/-/violations` (multi-tenant work; the spoof risk is fail-closed
  DoS only).
- Per-syscall precise attribution (tracer/shim) — inference from the deny set +
  stderr is the honest MVP; a tracer is a future precision upgrade.
- Auto-quarantine on `suspected` (kept human-gated by design).
- Propagating a quarantine to *other* versions of the same package (integrity-scoped
  only — a new build is a new artifact and must earn its own verdict).
- Cross-fleet violation aggregation / a central telemetry service (this phase is
  single-proxy; the record is local to the proxy's store).

## Invariants preserved

1. **Deterministic score** — violations never touch the 0–100 score; the block is a
   serve-time overlay (§3), like `deny`/approval.
2. **LLM never scores** — untouched.
3. **Sync gate cheap** — the sensor runs in the already-out-of-band install-time
   sandbox, not on the audit request path; reporting is a fire-and-forget POST from
   the CLI.
4. **Cache key = integrity** — violations are integrity-keyed, immutable-build-scoped.
5. **Proxy transparency** — packument passthrough untouched.
6. **Fail-open rules / never-crash** — `classifyViolation` is pure/total; a reporting
   failure never changes the install exit code.
7. **Private namespaces authoritative** — unchanged; a private package's own scripts
   run under the same sensor.
