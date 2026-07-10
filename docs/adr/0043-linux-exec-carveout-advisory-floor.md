# ADR-0043: Linux exec — exfil-tool carve-out enforced, exec floor advisory

**Status:** Accepted (Phase 29)
**Date:** 2026-07-10

Follows ADR-0042 (macOS exec deny-by-default); supersedes nothing. Does not close
issue #8 — a cross-platform exec floor is not achieved (Linux floor stays advisory).

## Context

ADR-0042 enforces the `process` capability on macOS via Seatbelt `process-exec*`.
The intended Linux equivalent was a bwrap `noexec` mount of the writable-non-project
floor (pure TypeScript, no native code). A decisive check killed it: **bwrap has no
`noexec` mechanism** — confirmed against the `bwrap(1)` man page (no mount-flags option)
and the open, unimplemented feature request containers/bubblewrap#349. A CAP_SYS_ADMIN
inner-remount was rejected as a security regression (granting a powerful cap into an
untrusted script's context). The only route to a true Linux exec floor is Landlock,
which needs a native syscall piece — a first-party compiled dependency in a pure-TS
supply-chain-security tool — deferred as too large a commitment for pre-1.0.

## Decision

On Linux, ship in pure TypeScript:

1. **Exfil-tool carve-out (enforced).** Mask each `SENSITIVE_EXECUTABLES` literal
   (curl/wget/nc/ncat/socat/scp/sftp; `osascript` is macOS-only and inert on Linux)
   with `--ro-bind /dev/null <literal>` under bwrap (execve on `/dev/null` fails EACCES),
   unless an approved `process:` Grant covers it — reusing the sensitive-read mask
   pattern. Merged-usr symlink ancestors (e.g. Debian/Ubuntu's `/bin` → `/usr/bin`)
   are resolved before masking so the bind always targets an actual mountable node.
   A denied carve-out exec surfaces as a `confirmed` `process` violation.
2. **Exec floor advisory (documented, not enforced).** bwrap cannot deny exec of a
   binary dropped into a writable location; that gap stays open on Linux by decision.
   The dropped binary is still filesystem+network confined (can't read credentials or
   exfil without an approved `network` cap), so the residual is arbitrary local
   computation within existing confinement — the state ADR-0042 documents for the
   pre-enforcement posture.

`native` stays advisory on both platforms. The macOS floor + carve-out (ADR-0042) is
unchanged. `computeDenySet`'s Linux branch models no floor, so `classifyViolation` only
ever confirms a Linux `process` violation on a masked literal — never a floor guess.

## Consequences

- Linux gains real defense-in-depth against exfil-tool exec (valuable most when a
  `network` cap is approved; with none, `--unshare-net` already blocks exfil).
- The dropped-binary-exec gap remains on Linux — documented, fs+net confined.
- Platform asymmetry: macOS enforces the exec floor + carve-out; Linux enforces the
  carve-out only. Same "each platform enforces what it can" precedent as the
  ADR-0023/0038 telemetry and /dev asymmetries.
- #8 stays open. Landlock (a native Linux floor) is the only route to close it; deferred.

## Rejected / deferred alternatives

- bwrap `noexec` floor — impossible (no bwrap option; #349 open).
- CAP_SYS_ADMIN inner-remount — security regression, rejected.
- Native Landlock helper — deferred; compiled dependency + arch/kernel matrix +
  supply-chain-binary tension; its own design pass. Landlock is also allow-list-only and
  cannot express the carve-out, which would still rely on this phase's masking.
- seccomp execve filter — can't inspect execve's path argument.
