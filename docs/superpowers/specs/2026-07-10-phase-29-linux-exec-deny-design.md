# Phase 29 — Linux exec deny-by-default (bwrap noexec)

**Date:** 2026-07-10
**Issue:** [#18](https://github.com/git-agentic/pkg-registry/issues/18) — Phase 29: Linux exec deny-by-default via Landlock
**Follows:** ADR-0042 (Phase 28, macOS exec deny-by-default). Closes [#8](https://github.com/git-agentic/pkg-registry/issues/8) on success.
**Status:** Approved design, pre-implementation

## Decision summary

Phase 28 enforces the `process` capability on macOS via Seatbelt `process-exec*`.
Phase 29 brings exec deny-by-default to Linux. The issue's title names **Landlock**,
but Landlock needs syscalls Node cannot make (a native addon/helper), colliding with
this repo's deliberate **pure-TypeScript, zero-native-dependency** posture — doubly
awkward for a supply-chain-security tool shipping a compiled binary.

A better primary path avoids native code entirely: **bwrap `noexec` mounts.** A package
can only exec a binary it can *write*, so mounting every writable-non-project location
(`tmpDir`, `/tmp`, caches, writable Grants) `noexec` — while the project tree stays
exec'able for `node_modules/.bin` shims — denies the exact dropped-binary threat with
the same residual as macOS (a binary in the package's own tree can still exec), using
only bwrap argv. The exfil-tool carve-out (`curl`/`wget`/`nc`/…) is replicated by
masking each literal with `--ro-bind /dev/null` — the pattern the repo already uses for
sensitive-read paths.

Whether ubuntu's bwrap actually supports `noexec` mounts is unknown from a macOS dev
host, so this design is **probe-first** (a CI spike decides the architecture). Landlock
is the deferred fallback only if the probe kills noexec.

### Decisions locked in during brainstorming

1. **Probe noexec first; Landlock is a deferred fallback** (its own follow-up issue, not
   this phase).
2. **Fallback posture on a can't-enforce host: loud advisory, proceed.** When a host's
   bwrap can't apply the noexec mounts but filesystem+network confinement still works,
   emit an attributable "exec-gating unavailable" signal and run the script confined —
   never silent (silence would recreate the #8 over-claim), never fail-closed-refuse
   (that would regress today's Linux availability, where scripts run with no exec
   gating at all).
3. **Include the exfil-tool carve-out on Linux** (full macOS parity via `/dev/null`
   masking), skipped when a `process:` Grant covers the tool. Adds real value in the
   network-cap-approved case (with no network cap, `--unshare-net` already blocks
   exfil).

## Scope

**In scope:** extend the Linux backend (`packages/sandbox`) to enforce the `process`
capability via `noexec` writable-floor mounts + `/dev/null` carve-out masks, with
runtime loud-advisory fallback and denied-exec violation classification. Reuse Phase
28's shared pure helpers unchanged.

**Non-goals:** Landlock (deferred to its own issue; only pursued if the probe kills
noexec); `native` stays advisory-only on both platforms (ADR-0042, unchanged);
`process-fork` ungated; the macOS/Seatbelt path untouched. Scoring, the approval model,
and the proxy are untouched (invariants #1–#7).

## Design

### Section 1 — Probe gate (a CI spike; decides the architecture)

Because the dev host is macOS and the Linux enforcement path only runs in CI, the
feasibility question is a **throwaway CI spike on ubuntu-latest**, run and captured in
`RESULTS` before any product code (probe-before-spec, the repo's discipline — see the
Phase 28 probe precedent). It answers, in order:

1. **Can the installed bwrap mount the writable-non-project floor `noexec`?** Test the
   mechanisms the host's bwrap actually exposes, in preference order — (a) a native
   bwrap mount-flag / `noexec` option if one exists on this version; (b) a fresh
   `--tmpfs` over a scratch dir like `/tmp` (note: bwrap tmpfs is exec-by-default, so
   this only helps if a noexec variant exists); (c) confirm whether an inner remount
   is possible given bwrap's default caps (expected: no — the inner process lacks
   CAP_SYS_ADMIN). Capture the **exact stderr of a denied exec** (the EACCES/ENOEXEC
   shell shape) — the Section 3 classifier regexes are written against it, exactly like
   Phase 28's probe captured the Seatbelt shapes.
2. **Does `--ro-bind /dev/null <literal>` deny *exec* (not just read)?** Overmount a
   real binary with `/dev/null` and confirm `execve` fails. Validates the carve-out.
3. **Landlock reconnaissance (informational only, no code):** record whether
   `LANDLOCK_ACCESS_FS_EXECUTE` / the Landlock LSM is present in the CI kernel, so the
   deferred fallback issue starts with real data.

**Fork on probe (1):**
- **Green** → full implementation (Sections 2–4).
- **Red** → this phase ships only the carve-out masking (if probe 2 is green) as partial
  hardening, files the Landlock follow-up issue with the probe-3 recon, updates docs to
  state the true (partial) Linux posture, and leaves #8 open. No floor-based
  dropped-binary denial is faked.

The probe is a hard gate: if it contradicts this design's assumptions, stop and reconcile
with the maintainer before writing product code.

### Section 2 — Mechanism (primary/green branch)

Extend `generateBwrapArgs` (`packages/sandbox/src/bwrap.ts`), reusing Phase 28's shared
pure helpers with **no duplication**: `execAllowFloor`, `SENSITIVE_EXECUTABLES`,
`execCarveOutPaths`, `classifyProcessTarget` (`packages/sandbox/src/exec-floor.ts`,
`sensitive-executables.ts`).

- **Floor / dropped-binary denial:** mount every *writable-non-project* floor entry
  `noexec` — the `writeAllowFloor` set (`tmpDir`, `/tmp`, `/dev`, the node build caches)
  plus writable `filesystem:` Grants, **minus** `cwd`/`projectRoot` (which must stay
  exec'able for `node_modules/.bin`). This mirrors macOS's projectRoot-in-floor residual
  exactly. The precise bwrap incantation is fixed by probe (1)'s winning mechanism.
- **Carve-out:** for each `SENSITIVE_EXECUTABLES` literal (`execCarveOutPaths`) that
  `pathExists` and is **not** covered by an approved `process:` Grant, emit
  `--ro-bind /dev/null <literal>`. Reuses the existing SENSITIVE-mask branch's
  `/dev/null` pattern (`bwrap.ts:67`).
- **Grant shapes** (identical semantics to macOS): a `process:` **path** Grant under a
  writable dir is re-bound exec'able (a narrow exec-allowed bind that wins over the
  broad noexec, mount-order-managed like the existing Slice-2 cwd-over-projectRoot
  ordering); a **command** Grant skips that tool's `/dev/null` mask; **`*`** skips all
  masks but opens no writable dir to exec. `isSafeGrantTarget` guards path Grants
  fail-closed.

Mount ordering is load-bearing and follows the existing `generateBwrapArgs` discipline
(broad binds before narrow, tmpfs/mask carve-outs last). The generator stays **pure**
(same inputs ⇒ same argv).

### Section 3 — Telemetry + fallback

- **Classification:** extend the **Linux** branch of `computeDenySet`
  (`packages/sandbox/src/deny-set.ts` — today it early-returns without exec fields) to
  carry the Linux exec sets (the noexec'd writable-non-project paths and the masked
  carve-out literals), and give `classifyViolation`
  (`packages/sandbox/src/violation.ts`) the Linux denied-exec error shapes captured by
  probe (1). A denied exec then surfaces as a `confirmed` `process` violation, feeding
  the existing violation → quarantine path. This mirrors Phase 28; the darwin exec
  branch and the pre-existing network/filesystem branches stay byte-unchanged, and the
  new opts remain optional so no existing caller breaks (invariant #6).
- **Wiring:** `BubblewrapSandbox` (`bubblewrap.ts`) passes the exec opts (`nodePrefix`,
  `projectRoot`, `cwd`, `tmpDir`) to both `generateBwrapArgs` and `computeDenySet` —
  the exact mirror of Phase 28's `SeatbeltSandbox` Task-8 wiring.
- **Loud-advisory fallback:** a one-time runtime capability check of whether *this*
  bwrap supports the noexec mechanism (e.g. a version/feature probe, cached). If not
  supported, emit an attributable, non-silent signal ("exec-gating unavailable on this
  host; filesystem+network confinement active") and proceed. The existing `NS_FAILURE`
  fail-closed path (total sandbox failure — kernel refuses the namespace) is unchanged.

### Section 4 — Testing + scope

- **CI probe spike** (Section 1) — gates the implementation; captured in a report like
  Phase 28's `task-2-report.md`.
- **Linux effect tests** (CI, ubuntu-latest; describe-gated to skip on darwin, matching
  the existing bwrap enforcement suite): a dropped binary in a writable non-project dir
  is denied AND surfaces a `confirmed` process violation; the `curl` carve-out is denied
  and lifted by `--approve process:curl`; a positive control (a `node_modules/.bin` shim
  and `node` still run). Benign probes only — synthetic malware stays scored-as-text,
  never executed.
- **Hermetic generator unit tests** (platform-neutral): the noexec mounts appear for the
  writable-non-project floor and not for the project tree; carve-out `/dev/null` masks
  appear for uncovered literals and are lifted by Grants; the `*`/command/path Grant
  shapes; a deny-set↔argv non-drift check (mirroring the Phase 28 profile↔deny-set one).
- **Loud-advisory path test**: the fallback signal fires (and the script still runs)
  when the noexec capability is reported absent.
- **Definition of done:** `npm run build` clean, `npm test` green (count updated in
  CLAUDE.md), malicious fixtures still blocked, Linux CI (Node 22 + 24) green, ADR-0043
  + doc sweep landed. On a green probe, **#8 closes** (cross-platform enforcement
  achieved).

## ADR + docs

- **ADR-0043** — Linux exec deny-by-default via bwrap `noexec` + `/dev/null` carve-out
  masking; the probe-first decision; the loud-advisory fallback; the projectRoot-in-floor
  residual (shared with macOS); Landlock recorded as the rejected/deferred alternative
  with the probe-3 recon. Follows ADR-0042; supersedes nothing.
- **ARCHITECTURE §3.6, threat-model §3.9/§4, README sandbox section, CLAUDE.md** —
  update the enforcement-scope split to: `process` enforced on **both** platforms
  (macOS Seatbelt / Linux bwrap-noexec), `native` advisory-only both. On a red probe,
  these instead state the true partial posture.
- File the Landlock follow-up issue (carrying probe-3 recon) only if the probe kills
  noexec. Close #8 on a green probe.

## Testing strategy note (probe-first, CI-only enforcement)

The enforcement path is Linux-only and cannot be exercised on the macOS dev host — same
constraint as the existing bwrap suite. The probe is therefore a CI experiment, and the
implementation's real proof is the Linux CI effect tests. Generator/classifier logic is
unit-tested hermetically and platform-neutrally so the bulk of the work is verifiable off
CI; only the kernel-effect assertions need Linux.

## Rejected / deferred alternatives

- **Landlock + native helper (the issue's literal title)** — deferred. Adds a native
  build dependency (addon or built-from-source helper) to a deliberately pure-TS repo,
  an arch (x86_64/arm64) + kernel (≥5.13) matrix, and a compiled binary in a
  supply-chain-security tool. Pursued only if the noexec probe fails. Also note: Landlock
  is allow-list-only over path hierarchies and **cannot** express the exfil-tool
  carve-out (deny a literal under an allowed parent), so even the Landlock branch would
  document the carve-out as macOS-only — whereas the noexec branch gets it via masking.
- **seccomp execve filter** — rejected: seccomp cannot inspect execve's path argument,
  so it can't do path-based exec allow/deny.
- **Fail-closed refusal on can't-enforce hosts** — rejected as default: an availability
  regression vs. today's Linux (scripts run now with no exec gating).
- **Operator-selectable fail-closed env var** — not in this phase (YAGNI); loud-advisory
  is the single posture. Can be added later if an operator needs the hard guarantee.
