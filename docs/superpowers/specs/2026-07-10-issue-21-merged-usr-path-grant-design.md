# Design: fix #21 — a path-form `process:` grant is defeated for its merged-usr sibling candidate

**Date:** 2026-07-10
**Issue:** [#21](https://github.com/git-agentic/pkg-registry/issues/21) (found in the Phase 29 / ADR-0043 whole-branch review)
**Scope:** `packages/sandbox` only — `bwrap.ts`, `deny-set.ts`, `bubblewrap.ts`, and their tests. No scoring, policy, or approval-model changes (invariants #1–#7 untouched).

## The bug

On Debian/Ubuntu merged-usr systems (`/bin` → `/usr/bin`), the Phase 29 exfil-tool
carve-out defeats a **path-form** grant:

1. **Generator** (`packages/sandbox/src/bwrap.ts`, carve-out loop): the grant
   coverage check runs against the **literal** candidate
   (`pathCovers(grant, lit)`), but the `/dev/null` mask is applied to the
   **resolved real path** (`resolve(lit)`). With `--approve process:/usr/bin/curl`,
   the `/usr/bin/curl` literal is lifted, but the sibling literal `/bin/curl` is
   not covered, resolves to `/usr/bin/curl`, and re-masks the same inode — the
   approved tool stays exec-denied.
2. **Classification mirror** (`packages/sandbox/src/deny-set.ts`, Linux branch):
   `execDeniedPaths` is computed from unresolved literals with no `realpath` at
   all, so with that grant it lists `/bin/curl` while the actual mask lands on
   `/usr/bin/curl`. A printed `/usr/bin/curl` denial matches nothing and
   `classifyViolation` returns `null` instead of `confirmed`.

Direction is **fail-closed** (over-blocks; no exec escape) and the documented
command form `process:curl` is unaffected — this is a fidelity/UX fix, not a
security hole. The grant target `/usr/bin/curl` is inside the Landlock floor, so
the `/dev/null` mask is the only deny mechanism in play: fixing the mask loop
fixes the bug under both the advisory (Phase 29) and Landlock (Phase 2 /
ADR-0044) modes.

## The fix rule

> A carve-out candidate literal is lifted when a path grant covers the
> **literal**, or when the grant's **resolved** form covers the candidate's
> **resolved** form.

Grants and candidates are compared in the same path space the mask actually
lands in. Resolution is used **only for the coverage decision** — the deny set
keeps emitting invocation-form literals (see below).

## Changes

### 1. Generator — `packages/sandbox/src/bwrap.ts`

In the exec carve-out loop, precompute `resolvedGrants = execPathGrants.map(resolve)`.
Lift a candidate `lit` when either:

- `execPathGrants.some((g) => pathCovers(g, lit))` (existing check), or
- `resolvedGrants.some((rg) => pathCovers(rg, resolve(lit)))` (new).

Effects on merged-usr:

- Grant `process:/usr/bin/curl`: `/bin/curl` resolves to `/usr/bin/curl`,
  is covered by the resolved grant, and is never masked — curl execs.
- The symmetric form `process:/bin/curl`: the grant resolves to
  `/usr/bin/curl` and lifts both siblings.

The existing `exists`/`maskedReal` dedupe logic is unchanged.

### 2. Deny-set mirror — `packages/sandbox/src/deny-set.ts` + `bubblewrap.ts`

- Add an optional `realpath?: (p: string) => string` to `computeDenySet`'s
  opts, defaulting to identity — the same injectable pattern
  `generateBwrapArgs` already has, so the function stays pure for hermetic
  tests.
- The Linux branch's path-grant filter applies the same lifted-if rule
  (literal-covered OR resolved-covered).
- `execDeniedPaths` continues to emit **literals** (both `/bin/` and
  `/usr/bin/` candidate forms): the shell prints the *invocation* form in a
  denial line, so classification must match either form. Only the coverage
  decision resolves.
- `lDenied` feeds both the Landlock (`execFloorMode: "linux-landlock"`) and
  advisory branches, so one change covers both modes.
- `BubblewrapSandbox.run` passes `realpath: safeRealpath` at its
  `computeDenySet` call site (`bubblewrap.ts`).
- **No change to `classifyViolation`**: once the mask is correctly lifted
  there is no denial to classify, and the deny set stays consistent for the
  candidates that remain masked.
- **No change to the darwin branch**: macOS has no merged-usr; its
  `canonicalizeMacPath` firmlink handling is a different concern.

### 3. Tests

Hermetic, platform-neutral (all use an injected merged-usr resolver
`/bin/<x> → /usr/bin/<x>`, the same shape as the existing Phase 29 live
non-drift test's resolver):

- `packages/sandbox/test/bwrap.test.ts` — merged-usr variants of
  "a path Grant covering a literal lifts that literal's mask":
  - grant `/usr/bin/curl` ⇒ **no** curl mask in the argv at all; wget stays
    masked;
  - inverse grant form `/bin/curl` ⇒ likewise lifts both siblings.
- `packages/sandbox/test/deny-set.test.ts` —
  - with injected realpath + path grant `/usr/bin/curl`,
    `execDeniedPaths` excludes both curl literals and keeps wget's;
  - add a **path-grant variant** of "non-drift under live merged-usr path
    resolution (Phase 29)" (keep the existing command-grant test as-is —
    today it only exercises command grants, which is why it passes).

CI-only Linux effect test (inside `bubblewrap.test.ts`'s existing
describe-skip-on-darwin `BubblewrapSandbox enforcement` block; ubuntu-latest
*is* merged-usr):

- `--approve process:/usr/bin/curl` (path form) ⇒ curl actually execs —
  the real regression test for this bug.

### 4. Docs

No ADR change: ADR-0043's documented grant semantics ("a path grant lifts
covered literals") are what this fix makes true on merged-usr; nothing is
reversed or superseded. Close #21 on merge.

## Out of scope / follow-ups

- **Untracked adjacent gap** (found while reading, not part of #21): the
  Landlock exec floor (`bubblewrap.ts`) is built from
  `linuxExecFloor({nodePrefix, projectRoot})` only — approved `process:`
  **path grants outside the floor** (e.g. `/opt/vendor/bin/tool`) are never
  added to the helper's `--allow` set, so they are exec-denied on
  Landlock-active hosts. macOS lifts path grants into the Seatbelt allow;
  Linux Landlock does not. Same fail-closed direction. File as a separate
  issue. (Issue #24 is a different Landlock item — spawnSync-shape denial
  classification.)

## Definition of done

`npm run build` clean, `npm test` green (hermetic tests pass on darwin; the
effect test verifies on Linux CI), the new merged-usr grant tests prove the
fix, and the existing carve-out behavior without grants is byte-identical.
