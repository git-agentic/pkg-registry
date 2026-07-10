# Phase 29 — Linux exec carve-out + advisory floor (pure-TS)

**Date:** 2026-07-10 (revised same day after a decisive feasibility check)
**Issue:** [#18](https://github.com/git-agentic/pkg-registry/issues/18) — Phase 29: Linux exec deny-by-default
**Follows:** ADR-0042 (Phase 28, macOS exec deny-by-default).
**Status:** Approved design, pre-implementation

## What changed from the first draft (and why)

The first draft's primary branch was **bwrap `noexec` mounts** — mount the writable
floor `noexec` to deny a dropped binary's exec in pure TypeScript. A decisive
documentation check killed it: **bwrap has no `noexec` mechanism.** Confirmed against
the official `bwrap(1)` man page (its complete mount-option set — `--bind`, `--tmpfs`,
`--ro-bind`, `--overlay`, `--perms`, `--size`, … — has no mount-flags/`noexec` option)
and the still-open, unimplemented feature request
[containers/bubblewrap#349](https://github.com/containers/bubblewrap/issues/349). The
only remaining mechanisms all fail: bwrap tmpfs is exec-by-default with no flag; an
inner remount needs `CAP_SYS_ADMIN`, and granting that into an untrusted lifecycle
script's context is a **security regression** (worse than a reviewed native helper), so
it is rejected outright.

That leaves two honest paths: a **native Landlock** piece (full enforcement, but a
first-party compiled dependency in a pure-TS supply-chain-security tool — its own large
design pass) or a **pure-TS partial**. Decision: **pure-TS partial** — for a pre-1.0
tool, the native dependency is a large, identity-cutting commitment whose gain sits on
top of filesystem+network confinement that already exists. Landlock is deferred (may
never be built); it keeps its own issue (#18 stays open).

## Decision summary

Phase 29 ships, on Linux, in pure TypeScript:

1. **Exfil-tool carve-out (enforced).** Mask each `SENSITIVE_EXECUTABLES` literal
   (`curl`/`wget`/`nc`/`ncat`/`socat`/`scp`/`sftp`; `osascript` is macOS-only and absent
   on Linux) by bind-mounting `/dev/null` over it (`--ro-bind /dev/null <literal>`) —
   reusing the exact pattern the repo already uses to mask sensitive *read* paths
   (`bwrap.ts:67`). `execve` on `/dev/null` fails, so the tool can't run. Skipped when an
   approved `process:` Grant covers the tool. This is real (if narrow) defense-in-depth,
   and it matters most in the network-cap-approved case (with no network cap,
   `--unshare-net` already blocks exfil).
2. **Advisory exec floor (documented, not enforced).** bwrap cannot deny exec of a binary
   a package drops into a writable location; that gap stays open on Linux **by decision**
   and is documented plainly. The dropped binary is still filesystem+network confined —
   it can't read credentials or exfil without an approved `network` cap — so the residual
   is "arbitrary local computation within existing confinement," the exact state ADR-0042
   already documents for the pre-enforcement posture.

**`#8` stays OPEN** — its claim is cross-platform exec-floor enforcement, which the
carve-out does not provide on Linux. This phase comments on #8 with the disposition;
it does not close it.

## Scope

**In scope:** extend the Linux backend (`packages/sandbox`) with the `/dev/null`
exfil-tool carve-out, denied-carve-out-exec violation classification, and honest
documentation of the advisory floor. Reuse Phase 28's shared pure helpers unchanged.

**Non-goals:** the exec **floor** (dropped-binary denial — not achievable in pure TS,
deferred to a possible Landlock phase); Landlock / any native dependency; `native`
capability enforcement (advisory both platforms, ADR-0042 unchanged); `process-fork`
gating; the macOS/Seatbelt path. Scoring, the approval model, and the proxy are
untouched (invariants #1–#7).

## Design

### Section 1 — Probe (small CI confirmation)

Since the dev host is macOS and the enforcement path is Linux-only, one small **CI
confirmation on ubuntu-latest**, captured before the classifier code, answers:

1. **Does `--ro-bind /dev/null <binary>` deny *exec*?** Overmount a real binary (e.g.
   `/usr/bin/curl` or a benign probe binary) with `/dev/null` under bwrap and confirm
   `execve` fails. Capture the **exact stderr shape** of the denial (expected: an
   `EACCES` / "Permission denied" line — execve on a non-regular file returns `EACCES` —
   which differs from Phase 28's macOS "Operation not permitted"/"bad interpreter"
   shapes). The Section 3 Linux classifier regexes are written against this captured
   shape, exactly as Phase 28's probe drove its regexes.

This is a confirmation, not an open architecture question (that was settled by the man
page). If `--ro-bind /dev/null` does *not* deny exec, stop and reconcile with the
maintainer before writing the classifier — but the existing SENSITIVE read-mask already
proves the bind works; only the exec-denial error shape is genuinely new.

### Section 2 — Carve-out mechanism

Extend `generateBwrapArgs` (`packages/sandbox/src/bwrap.ts`), reusing Phase 28's shared
pure helpers with **no duplication** (`SENSITIVE_EXECUTABLES`, `execCarveOutPaths`,
`classifyProcessTarget` from `sensitive-executables.ts`):

- For each `SENSITIVE_EXECUTABLES` command, for each candidate literal from
  `execCarveOutPaths(cmd)` that `pathExists` and is **not** covered by an approved
  `process:` Grant, emit `--ro-bind /dev/null <literal>`.
- **Grant handling** (mirrors macOS semantics): a `process:` **command** Grant
  (`classifyProcessTarget === "command"`) skips that command's masks; a **path** Grant
  covering a literal skips that literal's mask; **`*`** skips all masks. Path Grants are
  guarded by `isSafeGrantTarget`.
- Placement: emit the carve-out masks in the same region as the existing SENSITIVE masks
  (near `bwrap.ts:61-69`), after the floor/read binds, so a mask lands last and wins. The
  generator stays **pure** (same inputs ⇒ same argv).

The `execAllowFloor` is deliberately **not** used on Linux — there is no exec floor to
express (bwrap can't deny exec by path). Only the carve-out (deny specific literals via
masking) is expressible.

### Section 3 — Telemetry

- **Classification:** extend the **Linux** branch of `computeDenySet`
  (`packages/sandbox/src/deny-set.ts` — today it early-returns without exec fields) to
  carry the masked carve-out literals as a Linux exec-deny set, and give
  `classifyViolation` (`packages/sandbox/src/violation.ts`) the Linux denied-exec error
  shape captured by the Section 1 probe. A denied carve-out exec then surfaces as a
  `confirmed` `process` violation (`deniedResource` = the masked literal), feeding the
  existing violation → quarantine path. There is **no** `exec-default-deny` /
  writable-location branch on Linux (no floor to enforce), so Linux exec violations are
  only ever `confirmed` on a masked literal — never `suspected`. The darwin exec branch
  and the pre-existing network/filesystem branches stay byte-unchanged; the new deny-set
  opts remain optional so no existing caller breaks (invariant #6).
- **Wiring:** `BubblewrapSandbox` (`bubblewrap.ts`) passes the exec opts (`nodePrefix`,
  `projectRoot`, `cwd`, `tmpDir`) to both `generateBwrapArgs` and `computeDenySet` — the
  mirror of Phase 28's `SeatbeltSandbox` wiring. (`nodePrefix`/`projectRoot` are needed
  by `computeDenySet`'s signature for parity even though the Linux carve-out doesn't use
  a floor; pass them for a uniform call shape.)

**No per-run "advisory" spam.** The advisory-floor posture is a permanent by-design fact,
documented in the ADR/threat-model/README — not a runtime warning emitted on every Linux
lifecycle run (that would be noise). The carve-out itself always works (pure bind
mounts), so there is no per-host "can't enforce" degraded state to signal.

### Section 4 — Testing + scope

- **CI probe** (Section 1) — captured in a report like Phase 28's `task-2-report.md`.
- **Linux effect tests** (CI ubuntu-latest; describe-gated to skip on darwin, matching
  the existing bwrap suite): the `curl` carve-out is denied and lifted by
  `--approve process:curl`; a positive control (a `node_modules/.bin` shim and `node`
  still run — the carve-out doesn't over-block). Benign probes only; synthetic malware
  stays scored-as-text, never executed.
- **Hermetic generator unit tests** (platform-neutral): the `/dev/null` masks appear for
  uncovered `SENSITIVE_EXECUTABLES` literals and are lifted by command/path/`*` Grants;
  a deny-set↔argv non-drift check (mirroring Phase 28's profile↔deny-set one) confirming
  every Linux exec-deny-set literal is masked in the argv.
- **Definition of done:** `npm run build` clean, `npm test` green (count updated in
  CLAUDE.md), malicious fixtures still blocked, Linux CI (Node 22 + 24) green, ADR-0043 +
  doc sweep landed, #8 commented (stays open).

## ADR + docs

- **ADR-0043** — Linux exec: the exfil-tool carve-out via `/dev/null` masking (enforced);
  the exec **floor** advisory-by-decision (bwrap can't `noexec`, #349 open; native
  Landlock rejected for pre-1.0 as an identity-cutting compiled dependency whose gain
  sits atop existing fs+net confinement). Records the confirmed bwrap limitation and the
  Landlock deferral. Follows ADR-0042; supersedes nothing.
- **ARCHITECTURE §3.6, threat-model §3.9/§4, README sandbox section, CLAUDE.md** — update
  the enforcement-scope split to: `process` exec **floor** enforced on macOS
  (Seatbelt), **advisory on Linux** (bwrap can't path-gate exec); the exfil-tool
  **carve-out** enforced on **both** (Seatbelt literals / bwrap `/dev/null` masks);
  `native` advisory both. No overclaim of Linux floor enforcement anywhere.
- Comment on #8 with the disposition (macOS floor enforced; Linux carve-out enforced +
  floor advisory; Landlock the only route to a Linux floor, deferred) — **keep #8 open**.

## Rejected / deferred alternatives

- **bwrap `noexec` floor (the original primary branch)** — impossible: bwrap has no
  `noexec` option (man page + open request #349). Root cause of this revision.
- **CAP_SYS_ADMIN inner-remount to fake noexec** — rejected: grants a powerful cap into
  the untrusted-script context; a security regression in a containment tool, strictly
  worse than a reviewed native helper on the exact axis we care about.
- **Native Landlock helper** — deferred (may never be built). Full Linux floor
  enforcement, closes #8, but a first-party compiled dependency (addon or
  built-from-source helper), arch (x86_64/arm64) + kernel (≥5.13) matrix, and the
  supply-chain-binary shape Sentinel itself warns about. Needs its own brainstorm on the
  native mechanism; not a Phase-29 sub-detail. Also note Landlock is allow-list-only and
  **cannot** express the carve-out (deny a literal under an allowed parent), so a
  Landlock floor would still rely on this phase's masking for the carve-out.
- **seccomp execve filter** — rejected: seccomp cannot inspect execve's path argument.
- **Per-run loud-advisory runtime warning** — rejected as noise: the advisory-floor
  posture is permanent by design, documented once in the ADR/docs, not emitted per run.
