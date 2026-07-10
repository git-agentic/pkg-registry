# ADR-0044: Landlock Linux exec floor — enforced where available, advisory otherwise

**Status:** Accepted (Phase 2 / Landlock)
**Date:** 2026-07-10

Follows ADR-0042 (macOS exec floor) and ADR-0043 (Linux carve-out + advisory floor);
supersedes ADR-0043's advisory-floor default only where Landlock is available. Docs
sweep only — closing issue #8 is left to the controller after final review; this ADR
records that a cross-platform exec floor now exists (macOS Seatbelt + Linux Landlock)
so #8 is closable.

## Context

ADR-0043 shipped the Linux exfil-tool carve-out in pure TypeScript but left the exec
*floor* advisory because bwrap cannot `noexec`. A feasibility spike proved Landlock's
`LANDLOCK_ACCESS_FS_EXECUTE` enforces a path-based exec floor inside bwrap on
ubuntu-latest, unprivileged (`no_new_privs`, which bwrap sets), inherited across
`execve`. Node has no syscall API, so this requires a first-party compiled helper — a
deliberate, bounded exception to the repo's zero-native-dependency posture, chosen
because it is the only route to a real Linux floor.

## Decision

A self-contained C helper (`packages/sandbox/native/landlock-exec.c`, inline
Landlock uapi, no kernel headers) applies an exec-allow ruleset for the floor and execs
the script, invoked inside bwrap: `bwrap … landlock-exec --allow <floor> -- /bin/sh -c
<script>`. It is **compiled from source by a `npm run build` step** (`build-native.mjs`)
— NOT a `postinstall` hook (install-time script execution is the very thing Sentinel
guards against) and NOT a lazy runtime compile (writing-then-exec'ing a binary on the
containment path). The step is a no-op (exit 0) on non-Linux / no-`cc`.

The Linux floor is `execAllowFloor` **plus** `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`
(`linuxExecFloor`) — `FS_EXECUTE` gates the dynamic linker + library `mmap`, unlike the
macOS floor (the spike's first CI run failed precisely on this).

**Fail-open, pre-checked detection:** the helper is used iff it exists AND
`landlock-exec --check` (ABI probe) exits 0, cached for the process (`landlockActive`
in `packages/sandbox/src/bubblewrap.ts`); anything else falls back to the Phase 29
advisory floor with a one-time notice. `computeDenySet`/`classifyViolation` gain a
`linux-landlock` `execFloorMode` so a floor-outside exec denial attributes as a
`confirmed` `exec-floor-deny` violation. The Phase 29 `/dev/null` carve-out stays
(Landlock is allow-list-only and can't deny a literal under an allowed dir).
macOS/Seatbelt is untouched.

## Consequences

- A dropped binary anywhere outside the floor is kernel-denied on Linux where Landlock
  + the helper are available — closing the gap ADR-0043 documented as advisory.
- Hosts without Landlock (old kernel / LSM disabled) or without `cc` at build run under
  the Phase 29 advisory floor — no availability regression, one honest notice.
- A first-party compiled helper enters the tree (built from source, auditable, not a
  package dependency). Recorded as a bounded, deliberate posture exception.
- `native` stays advisory on both platforms (unchanged).

## Rejected alternatives

- `postinstall` hook / lazy runtime compile — posture violations (see Decision).
- Prebuilt per-arch binaries — opaque binary in a supply-chain tool.
- Failure-triggered detection — would fail every lifecycle script on a Landlock-less
  host before falling back.
- Fail-closed refusal — an availability regression vs. Phase 29.
