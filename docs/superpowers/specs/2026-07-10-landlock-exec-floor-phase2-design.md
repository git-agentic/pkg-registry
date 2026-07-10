# Landlock Linux exec floor — Phase 2 (shippable) design

**Date:** 2026-07-10
**Issue:** [#8](https://github.com/git-agentic/pkg-registry/issues/8) — closes it (cross-platform exec floor achieved, with a documented Landlock-availability caveat).
**Follows:** ADR-0042 (macOS exec floor), ADR-0043 (Linux carve-out + advisory floor). Built on the green feasibility spike (`docs/superpowers/specs/2026-07-10-landlock-spike-findings.md`).
**Status:** Approved design, pre-implementation

## What this ships

The **enforced** Linux exec floor: `sentinel run-scripts`/`install --enforce` on Linux runs each lifecycle script under a Landlock ruleset (via a small from-source helper inside bwrap) that denies exec of any binary outside the floor — closing the dropped-binary gap ADR-0043 left advisory. Where Landlock or the helper is unavailable, it falls back to Phase 29's carve-out + advisory floor with a one-time honest notice. macOS/Seatbelt is untouched.

The feasibility spike already proved this works inside bwrap on ubuntu-latest and surfaced two findings this design bakes in: the Linux floor must include the library/linker dirs (`FS_EXECUTE` gates library `mmap`), and the classifier needs a Landlock-floor mode (Phase 29's Linux exec branch is gated on an *empty* floor).

### Decisions locked in during brainstorming

1. **Compile via a build step in `npm run build`** — the literal place "compile all packages" already lives. NOT a `postinstall` hook (adding install-time script exec to an anti-install-script tool is a posture violation) and NOT lazy runtime compile (writing-then-exec'ing a binary on the containment path, plus cache/race management). Chosen because in this build-from-source model, build-env == run-env.
2. **Fail-open, pre-checked detection** (not failure-triggered): the helper is used only when it exists AND a cached `--check` ABI probe says Landlock is available; anything else ⇒ the Phase 29 advisory path. This is the load-bearing safety contract — a naive "always prepend the helper" would make every lifecycle script fail (exit 3) on a host without Landlock.
3. **One-time loud-advisory fallback** (not per-run spam): when the floor can't be enforced on a host, emit one attributable notice per process and run under the Phase 29 advisory floor.
4. **The Phase 29 `/dev/null` carve-out stays** — Landlock is allow-list-only and can't deny a literal under an allowed dir, so the carve-out masks remain the exfil-tool mechanism. Landlock adds the *floor*.

## Global constraints

- **The `build:native` step must no-op, never fail, on non-Linux or when `cc` is absent** — skip-with-log, exit 0. Otherwise it breaks `npm run build` on the macOS dev host and on any Linux box without a compiler.
- **macOS/Seatbelt path is byte-behavior-unchanged** — `generateProfile`, the darwin branches of `computeDenySet`/`classifyViolation`, and `execAllowFloor`'s macOS use are untouched.
- **The Phase 29 fallback path (carve-out + advisory floor + its classifier `linuxCarveMode`) stays working unchanged** when the Landlock helper is not active.
- Generators/classifier stay pure/deterministic (no fs in the pure functions; detection lives in `BubblewrapSandbox`).
- No new npm/native *dependency* — the helper is first-party source we compile, not a package.

## Design

### Section 1 — The helper + build step

- **Promote** `packages/sandbox/native/landlock-exec.c` (from the spike) to the shipped tree (it's already reviewed for syscall/ABI/struct correctness). Add a **`--check` mode**: when invoked as `landlock-exec --check`, run the ABI probe (`landlock_create_ruleset(NULL, 0, VERSION)`) and exit `0` (ABI ≥ 1, available) or `3` (unavailable), doing **no** ruleset setup and **no** `execve`. (Also address the spike's minor: a debug-only stderr line when an `--allow` path can't be opened, so a typo'd floor entry isn't silent.)
- **`packages/sandbox/scripts/build-native.mjs`**: if `process.platform !== "linux"` or no `cc` on PATH → print a skip notice and exit 0. Else `cc -O2 -o packages/sandbox/dist/landlock-exec packages/sandbox/native/landlock-exec.c`; on compile failure, log and exit 0 (fall back to advisory — don't break the build). Wire it into the sandbox package build so `npm run build` runs it after `tsc`. Gitignore `packages/sandbox/dist/landlock-exec`.

### Section 2 — Floor, deny-set, classifier

- **`linuxExecFloor`** (`packages/sandbox/src/exec-floor.ts` or a sibling): returns `execAllowFloor({nodePrefix, projectRoot})` entries **plus** `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64` (the spike finding — `FS_EXECUTE` gates the dynamic linker + shared-library `mmap`; these are Linux-only and NOT in the macOS floor). Pure. These become the helper's `--allow` args and the deny-set's floor.
- **`computeDenySet` Linux floor upgrade**: the Linux branch gains an optional signal ("Landlock floor active") — when set, populate `execAllowedPaths` from `linuxExecFloor` (so `classifyViolation` can attribute a floor-outside exec) and keep `execDeniedPaths` (the carve-out literals). When not set (fallback), the exact Phase 29 behavior (no floor, carve-out only) is unchanged. Paths are not firmlink-canonicalized on Linux (unchanged).
- **`classifyViolation` Landlock-floor mode** (the subtle piece): today the Linux dash-EACCES matcher (`firstLinuxExecLine`/`LINUX_EXEC_PATH`, "Permission denied") fires only in `linuxCarveMode` (`execAllowedPaths.length === 0`). Generalize so the Linux exec-denial shape is matched whenever a Linux exec-deny context exists — carve-out (empty floor, Phase 29) **or** Landlock floor (populated `execAllowedPaths`) — and attribute:
  - target ∈ `execDeniedPaths` (a masked carve-out literal) ⇒ `confirmed` process (both modes).
  - Landlock-floor mode, target NOT under any `execAllowedPaths` entry ⇒ `confirmed` process (`deniedResource: "exec-floor-deny"`) — the dropped-binary case.
  - Landlock-floor mode, target under the floor ⇒ ambient `null` (exec is allowed there; shouldn't surface, but safe).
  The macOS exec branch (which keys on "Operation not permitted" + the macOS floor) is untouched, and the Phase 29 carve-out-only path keeps its exact behavior. This directly resolves the spike-review finding that a populated floor would otherwise route the denial to the macOS branch and return `null`.

### Section 3 — Wiring + fail-open detection + fallback

- **Detection (`BubblewrapSandbox`, cached once):** `landlockActive` = (`dist/landlock-exec` exists) AND (`landlock-exec --check` exits 0). Computed lazily on first `run`, memoized. Any negative — no binary, `--check` exit 3, spawn error — ⇒ `landlockActive = false`.
- **Active path:** prepend `dist/landlock-exec --allow <linuxExecFloor entries> --` before `/bin/sh -c cmd` in the bwrap argv; pass the "Landlock floor active" signal to `computeDenySet` so the deny set carries the floor. The `/dev/null` carve-out masks (Phase 29) and all existing bwrap fs/read/write/network args are unchanged.
- **Fallback path:** exactly today's Phase 29 invocation (no helper, carve-out + advisory floor, `computeDenySet` with no floor), plus a **one-time** (per-process, memoized) attributable notice: "Landlock exec floor unavailable on this host (<reason: no helper built / kernel ABI < 1>); advisory floor active — a dropped binary can exec but stays fs+net confined."
- **`NS_FAILURE`** (kernel refuses the namespace ⇒ total sandbox failure) fail-closed behavior is untouched.

### Section 4 — Testing + docs + close #8

- **Hermetic unit tests** (platform-neutral, run on macOS): `linuxExecFloor` includes the lib dirs; `computeDenySet` populates `execAllowedPaths` in Landlock-floor mode and stays no-floor otherwise; `classifyViolation` confirms a floor-outside exec denial in Landlock-floor mode, still confirms a carve-out literal in both modes, and leaves the macOS branch + Phase 29 carve-out-only behavior unchanged; `build-native.mjs` no-ops (exit 0, skip log) on darwin.
- **Linux CI effect tests** (in the real suite, describe-gated to Linux; the spike assertions promoted): with the helper built and Landlock available, a `/tmp`-dropped `chmod +x` binary is **denied** and surfaces a `confirmed` process violation; a floor binary (a `.bin` shim, `node`) runs; the `--check` fail-open path (simulate helper absent) falls back to the Phase 29 advisory floor without breaking the script. Benign probes only.
- **Docs:** a new ADR (Landlock exec floor; from-source build step; the lib-dir floor finding; the fail-open detection contract; the classifier Landlock-floor mode; the one-time loud-advisory fallback). ARCHITECTURE §3.6, threat-model §3.9/§4, README sandbox section, CLAUDE.md updated: Linux exec floor **enforced where Landlock + the helper are available, advisory otherwise**; the exec floor+carve-out now enforced on both platforms where the primitives exist; `native` still advisory both.
- **Close #8** — the cross-platform exec floor exists (macOS Seatbelt + Linux Landlock), with the documented Landlock-availability caveat. The ADR records that a host lacking Landlock/`cc` runs under the advisory floor.

## Testing strategy note

The Landlock enforcement path is Linux-only and only runs in CI (as with the existing bwrap suite). The generator/deny-set/classifier logic — the bulk of the change — is unit-tested hermetically and platform-neutrally, so it's verifiable on the macOS dev host; only the kernel-effect assertions and the actual `cc` compile need Linux CI. `build-native.mjs`'s macOS no-op is directly testable on the dev host.

## Rejected / deferred alternatives

- **`postinstall` compile hook** — adds install-time script execution to a tool built to guard against exactly that; posture violation.
- **Lazy runtime compile** — writes-then-execs a binary on the untrusted-script containment path, plus cache-hash invalidation and a compile race; its only benefit (build-env ≠ run-env) doesn't hold in build-from-source.
- **Prebuilt per-arch binaries** — opaque binary in a supply-chain tool; rejected in the spike.
- **Failure-triggered detection** (prepend the helper, handle exit 3 after) — would fail every lifecycle script on a Landlock-less host before falling back; the pre-checked `--check` contract avoids it.
- **Fail-closed refusal when Landlock unavailable** — an availability regression vs. Phase 29 (which runs scripts under the advisory floor); loud-advisory fallback instead.
- **A per-run advisory warning** — noise; the notice is one-time per process.
