# ADR-0042: Exec deny-by-default on macOS; Landlock plan for Linux; `native` formally advisory

**Status:** Accepted (Phase 28)
**Date:** 2026-07-10

Extends ADR-0038 (sandbox default-deny — this mirrors its write layering for exec) and ADR-0023 (violation telemetry — `classifyViolation` now attributes denied execs); supersedes nothing. This resolves the enforce-or-formally-downgrade decision tracked in issue #8 for the `process` kind on macOS; Linux enforcement is Phase 29.

## Context

The capability model exposes `process` and `native` as approvable kinds and
scores them (`capability-novelty`), but through Phase 27 neither sandbox
backend gated a spawn: Seatbelt had no `process-exec*` deny and bwrap adds
no exec restriction. An unapproved `child_process` spawn — including a
binary the script itself just downloaded — was permitted (issue #8,
documentation over-claim, P1).

Feasibility differs by platform. Seatbelt expresses path-based exec policy
natively (`process-exec*` + subpath/literal filters). Linux cannot do this
with bwrap alone: seccomp cannot inspect execve's path argument and bwrap
has no noexec mount option. Linux DOES have a path-based exec primitive —
Landlock (`LANDLOCK_ACCESS_FS_EXECUTE`, kernel ≥ 5.13) — but Node exposes
no Landlock syscalls, so it needs a small native piece (Phase 29,
probe-first). A runtime supervisor (seccomp-notify/pidfd) was considered
and rejected as Chrome-sandbox-class complexity for per-spawn decisions we
do not need; it remains the escalation path and layers on top of this
design without waste.

## Decision

macOS (Phase 28): exec is deny-by-default, mirroring the Phase 25 write
layering (SBPL last-match-wins):

1. `(deny process-exec*)` — blanket.
2. `(allow process-exec* …)` — a FIXED, non-configurable exec floor
   (`execAllowFloor`: /bin, /usr/bin, /usr/sbin, the node prefix, the
   project root, /Library/Developer, /Applications/Xcode.app,
   /opt/homebrew, /usr/local) plus approved `process:` PATH-Grants.
3. `(deny process-exec* (literal …))` — a curated `SENSITIVE_EXECUTABLES`
   carve-out (curl, wget, nc, ncat, socat, osascript, scp, sftp) expanded
   across the floor's bin dirs with no PATH resolution, re-denied unless a
   Grant lifts it.

`process` Grant target shapes: a bare word lifts that command's carve-out;
a target containing `/` (or starting `~`) is a path Grant appended to the
allow (guarded by `isSafeGrantTarget`); `*` lifts the whole carve-out but
opens no non-floor paths. `process-fork` stays allowed — only exec is
gated. `computeDenySet` mirrors the exec sets (non-drift-tested) and
`classifyViolation` attributes a denied exec, disambiguating the shell's
ambiguous "Operation not permitted" line via the write floor: denied in a
writable location ⇒ confirmed (a write there cannot fail); outside both
floors ⇒ suspected.

Linux: unchanged this phase — exec remains advisory pending Phase 29
(Landlock). `native` (dlopen/WASM): formally advisory-only on BOTH
platforms, permanently — no path-level primitive distinguishes loading an
artifact from reading it.

## Consequences

- Exec from any writable-but-not-project location (/tmp, ~/Downloads,
  caches) is kernel-denied on macOS — the dropped-binary pattern dies.
- Accepted residual: projectRoot is in the floor, so a package can write a
  binary into its own tree and exec it. Rejected alternative (a strict
  floor without projectRoot/Homebrew) breaks every node_modules/.bin shim
  and brew-installed build tool. Existing mitigations: `unscanned-content`
  surfaces bundled binaries (ADR-0041); `process` detection scores the
  spawn pattern.
- Platform asymmetry until Phase 29, documented in the threat model —
  same precedent as the ADR-0023/0038 telemetry and /dev asymmetries.
- A broad `process:` PATH Grant (e.g. `process:~` or `process:/Users`)
  widens the exec-allowed surface as much as the operator approves it to —
  human-approval-gated and consistent with the Phase 25 filesystem-Grant
  model, but a wide Grant is a wide Grant.
- Scoring, the approval model, bwrap, and the proxy are untouched
  (invariants #1–#7).

## Rejected alternatives

- Formalize advisory-only everywhere — leaves Seatbelt's native exec
  primitive unused while dropped binaries run.
- Strict floor (system + node only) — unacceptable default breakage.
- Operator-configurable floor — diverges from the Phase 25 precedent;
  widening the floor silently reopens the class.
- Runtime supervisor — complexity disproportionate to a pre-1.0 install
  sandbox; retained as the future escalation path.
