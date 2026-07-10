# Design: fix #24 — Landlock mode misclassifies a node spawnSync-shape exec denial

**Date:** 2026-07-10
**Issue:** [#24](https://github.com/git-agentic/pkg-registry/issues/24) (found in the Phase 2 / ADR-0044 whole-branch review)
**Scope:** `packages/sandbox/src/violation.ts` and its tests only. Telemetry
precision — never containment (the kernel denies the exec either way). No
scoring, policy, or approval-model changes (invariants #1–#7 untouched).

## The bug

`classifyViolation`'s Landlock branch (`execFloorMode === "linux-landlock"`)
only matches the **dash shell** denial shape via `firstLinuxExecLine`
(`/bin/sh: 1: <path>: Permission denied`). A denial that surfaces as node's
**`spawnSync <path> EACCES`** line instead falls through to the macOS exec
branch, where — because `writeAllowedPaths` is intentionally absent in
Landlock mode while `execAllowedPaths` is populated — it returns
`confidence: "suspected"` rather than `confirmed` with
`deniedResource: "exec-floor-deny"`.

Two mislabels, both fixed by the same change:

- **Floor-outside** spawnSync denial (the dropped-binary case, the issue):
  reported `suspected` — should be `confirmed` / `exec-floor-deny`.
- **Floor-inside** spawnSync EACCES (a genuinely ambient error the floor
  allows): the fall-through also reports `suspected` — should be `null`,
  exactly as the dash shape already is.

Phase 29 carve-out mode (no floor) is **not** affected: a spawnSync denial on
a masked literal already attributes `confirmed` via the macOS-branch
fall-through's `execDeniedPaths` match, and the `noFloorModeled` guard keeps
everything else `null`.

## The fix

In the Landlock branch of `classifyViolation`
(`packages/sandbox/src/violation.ts`): when `firstLinuxExecLine` finds no
dash-shape line, fall back to `firstSpawnExecLine(stderr)` with the target
extracted by `SPAWN_EXEC_PATH`. Feed whichever `(line, target)` pair was
found through the **existing attribution ladder unchanged**:

1. target covered by an `execDeniedPaths` carve-out literal → `confirmed`,
   `deniedResource` = the literal;
2. target outside every `execAllowedPaths` entry → `confirmed`,
   `deniedResource: "exec-floor-deny"`;
3. target under the floor → `null` (ambient).

Details:

- **No `canonicalizeMacPath`** — Linux paths are never firmlink-canonicalized
  (consistent with both existing Linux branches).
- If a spawn line exists but no path extracts, keep today's fall-through to
  the macOS branch (`suspected`, null target) — no behavior change for the
  unattributable case.
- No new regexes: `firstSpawnExecLine` / `SPAWN_EXEC_PATH` already exist
  (Phase 28) and are ReDoS-safe by the same split-test construction.
- This is the Landlock-mode analog of how the Phase 28/29 branches already
  pair the shell shape with the spawn shape (`violation.ts`'s macOS branch
  consults both).

## Tests

Hermetic, platform-neutral, in `violation.test.ts`'s existing
"Linux Landlock floor mode (Phase 2)" describe:

- `spawnSync /tmp/dropped EACCES` (floor-outside) → `confirmed`,
  `kind: "process"`, `deniedResource: "exec-floor-deny"` — the issue's case;
- `spawnSync /usr/bin/curl EACCES` (masked carve-out literal) → `confirmed`
  on the literal;
- `spawnSync /usr/bin/make EACCES` (floor-inside) → `null` (ambient);
- existing dash-shape cases stay untouched and green.

No Linux effect test: the Phase 2 effect test already proves the common
shell-exec path end-to-end, and this fix is a pure-function classification
change fully pinned by unit tests.

## Docs

No ADR change: ADR-0044's classification design ("a floor-outside exec
denial is confirmed as `exec-floor-deny`") is what this fix makes true for
the spawn shape; nothing is reversed or superseded. Update CLAUDE.md's
test-notes line for the Landlock classifyViolation cases. Close #24 on
merge.

## Out of scope

- Issue #25 (path grants never appended to the helper's `--allow` set) —
  separate branch, separate spec
  (`2026-07-10-issue-25-landlock-path-grant-allow-design.md`).

## Definition of done

`npm run build` clean, `npm test` green on darwin, the three new
spawnSync-shape Landlock unit tests prove the fix, and every existing
violation-classification test is byte-identical in behavior.
