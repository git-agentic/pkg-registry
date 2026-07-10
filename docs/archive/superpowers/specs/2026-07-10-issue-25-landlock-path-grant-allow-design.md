# Design: fix #25 — approved `process:` path grants outside the floor are never `--allow`ed to landlock-exec

**Date:** 2026-07-10
**Issue:** [#25](https://github.com/git-agentic/pkg-registry/issues/25) (found while fixing #21; predicted by that spec's "Out of scope" note)
**Scope:** `packages/sandbox` only — `deny-set.ts`, `bubblewrap.ts`, and their
tests. Fail-closed direction today (over-blocks; no exec escape). No scoring,
policy, or approval-model changes (invariants #1–#7 untouched).

## The bug

On a Landlock-active host, the exec floor passed to the `landlock-exec`
helper (`packages/sandbox/src/bubblewrap.ts`, the `inner` argv) is built from
`linuxExecFloor({ nodePrefix, projectRoot })` **only** — approved `process:`
**path grants** are never appended as `--allow` entries. `computeDenySet`'s
Landlock branch mirrors the omission (`execAllowedPaths` = floor only). So a
grant like `process:/opt/vendor/bin/tool` outside the floor is exec-denied
anyway: the operator approved it, and it silently doesn't work.

macOS already lifts path grants into the Seatbelt exec allow
(`deny-set.ts`'s darwin branch builds `execAllowedPaths` from
`execAllowFloor(...)` **plus** `execPathGrants`); Linux Landlock must mirror
that pattern. Grants **inside** floor dirs (e.g. `/usr/bin/...`) are
unaffected — the carve-out mask, fixed by #21, is the only deny mechanism
for those.

## The fix

One new shared pure function — drift-proof by construction, the same pattern
that already keeps `linuxExecFloor` in sync between the generator and the
classifier:

```ts
// packages/sandbox/src/deny-set.ts (it owns expandHome/isSafeGrantTarget and
// already imports exec-floor + sensitive-executables; defining it in
// exec-floor.ts would create an import cycle)
export function landlockAllowPaths(
  approved: Capability[],
  opts: { homeDir: string; nodePrefix: string; projectRoot: string },
): string[]
```

Returns `linuxExecFloor({ nodePrefix, projectRoot })` plus every `process:`
capability that classifies as `path` (`classifyProcessTarget`), passes
`isSafeGrantTarget`, expanded via `expandHome(target, homeDir)`.

Two call sites:

1. **Helper invocation** — `BubblewrapSandbox.run` (`bubblewrap.ts`): the
   `inner` argv's `--allow` entries come from
   `landlockAllowPaths(opts.approved, { homeDir, nodePrefix, projectRoot })`
   instead of bare `linuxExecFloor(...)`.
2. **Classification mirror** — `computeDenySet`'s Landlock branch
   (`deny-set.ts`): `execAllowedPaths: landlockAllowPaths(approved, ...)`.
   Same function, same inputs ⇒ the classifier's model cannot drift from
   what the helper enforces. `classifyViolation` needs **no change** —
   grants land in `execAllowedPaths`, which its attribution ladder already
   consults (a denial on a granted path can no longer occur; a floor-inside
   result stays ambient).

Details:

- **No realpath resolution needed here**, unlike #21's masks: the helper
  `open()`s each `--allow` entry and the Landlock rule attaches to the
  resolved inode hierarchy, so a symlinked grant target already works. #21
  resolved because a *bind destination* must be a real mountable node —
  that constraint doesn't exist for `O_PATH` opens.
- A grant to a **nonexistent** path is already tolerated: the helper skips
  unopenable `--allow` entries (merged-usr tolerance in `landlock-exec.c`).
- Unsafe targets (`*`, `/`, empty, any `..` segment) are dropped by
  `isSafeGrantTarget`, exactly as on macOS — the grant simply doesn't widen
  the floor.
- The helper caps `--allow` at 256 entries; the floor is ~13 and grants are
  operator-approved singletons, so the cap is not a practical concern.
- The Phase 29 `/dev/null` carve-out masking and its #21 grant-lift logic
  are untouched (they run in `generateBwrapArgs`, a different layer).

## Tests

Hermetic, platform-neutral:

- `deny-set.test.ts` —
  - Landlock branch: a safe path grant (`/opt/vendor/bin/tool`) appears in
    `execAllowedPaths` alongside the floor; unsafe targets (`*`, `/`,
    `..`-containing) do not; a `~`-form grant expands against `homeDir`.
  - Non-drift: `computeDenySet(...).execAllowedPaths` (Landlock branch)
    deep-equals `landlockAllowPaths(...)` for the same inputs.
- `exec-floor.test.ts` or `deny-set.test.ts` — direct `landlockAllowPaths`
  unit tests (floor-only when no grants; floor + expanded grants otherwise).

CI-only Linux effect tests (inside `bubblewrap.test.ts`'s existing
describe-skip-on-darwin `BubblewrapSandbox enforcement` block, same
built-helper gating as the two existing Phase 2 Landlock effect tests):

- Copy a real binary (e.g. `/usr/bin/env`) to a temp dir **outside** the
  floor; with `--approve process:<that path>` it execs (exit 0, no
  violation) — the real regression test for this bug.
- The same exec **without** the grant stays denied and surfaces a
  `confirmed` process violation (`exec-floor-deny`) — proves the grant is
  the thing that flipped it, and pins the deny direction.

## Docs

No ADR change: ADR-0044 documents the floor and the grant model; lifting
approved path grants into the enforced floor is what makes its documented
semantics true (macOS parity), not a reversal. Update CLAUDE.md's test-notes
line. Close #25 on merge.

## Out of scope / follow-ups

- **Known residual — path grants under `$HOME`** (file as a new issue when
  landing this): a `process:` path grant under `$HOME` still can't exec on
  Linux even after this fix — bwrap's `--tmpfs $HOME` (Phase 25 Slice 2)
  hides the file entirely, so the exec fails ENOENT before Landlock is
  consulted. That's a filesystem-visibility gap (the grant would also need a
  `--ro-bind` re-expose in `generateBwrapArgs`), not an exec-floor gap.
  The motivating case (`/opt/vendor/bin/tool`, outside `$HOME`) is covered.
- Issue #24 (spawnSync-shape denial classification) — separate branch,
  separate spec
  (`2026-07-10-issue-24-landlock-spawnsync-classification-design.md`).

## Definition of done

`npm run build` clean, `npm test` green (hermetic tests on darwin; the
effect tests verify on Linux CI), the new grant tests prove the fix, and
behavior with no path grants is byte-identical (floor-only `--allow` set).
