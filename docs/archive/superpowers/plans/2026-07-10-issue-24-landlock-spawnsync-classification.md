# Fix #24 — Landlock spawnSync-Shape Classification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In Landlock-floor mode, classify a node `spawnSync <path> EACCES` exec denial through the same attribution ladder as the dash-shell shape, so a floor-outside denial is `confirmed`/`exec-floor-deny` instead of `suspected`.

**Architecture:** One pure-function change in `classifyViolation`'s `execFloorMode === "linux-landlock"` branch (`packages/sandbox/src/violation.ts`): fall back to the existing `firstSpawnExecLine`/`SPAWN_EXEC_PATH` extractors when no dash-shape line matches. No new regexes, no other branches touched. Spec: `docs/superpowers/specs/2026-07-10-issue-24-landlock-spawnsync-classification-design.md`.

**Tech Stack:** TypeScript (ESM, NodeNext — internal imports use `.js` specifiers), `node:test` + `tsx`.

## Global Constraints

- Telemetry precision only — containment is unaffected either way (spec).
- No `canonicalizeMacPath` on Linux paths (spec: Linux paths are never firmlink-canonicalized).
- A spawn line with no extractable path keeps today's fall-through to the macOS branch (`suspected`, null target).
- Phase 29 carve-out mode and the darwin branch are untouched; every existing violation test stays green unchanged.
- Definition of done: `npm run build` clean, `npm test` green on darwin (763 pass expected: 760 + 3 new).

---

### Task 1: Create the branch

**Files:** none (git only)

- [ ] **Step 1: Branch off main**

```bash
git checkout main && git pull && git checkout -b fix-24-landlock-spawnsync-classification
```

### Task 2: spawnSync-shape attribution in the Landlock branch

**Files:**
- Modify: `packages/sandbox/src/violation.ts:145-156` (the `execFloorMode === "linux-landlock"` branch)
- Test: `packages/sandbox/test/violation.test.ts` (the existing `classifyViolation — Linux Landlock floor mode (Phase 2)` describe, which ends at the `does not fire without execFloorMode` test)

**Interfaces:**
- Consumes: existing module-level helpers in `violation.ts` — `firstLinuxExecLine`, `LINUX_EXEC_PATH`, `firstSpawnExecLine`, `SPAWN_EXEC_PATH`, `pathCovers`, `excerpt`; the test file's existing `LL_DS` deny-set fixture and `failLL(stderr)` helper.
- Produces: no signature changes — `classifyViolation(result, denySet)` behavior only.

- [ ] **Step 1: Write the failing test (plus two pins)**

Add inside the `describe("classifyViolation — Linux Landlock floor mode (Phase 2)", ...)` block in `packages/sandbox/test/violation.test.ts`, after the `does not fire without execFloorMode` test:

```ts
  // Issue #24: a denial surfacing through node instead of the shell reports
  // "spawnSync <path> EACCES" — same attribution ladder as the dash shape.
  test("a floor-OUTSIDE spawnSync-shape denial is confirmed exec-floor-deny (issue #24)", () => {
    const v = classifyViolation(failLL("spawnSync /tmp/spikestash/payload EACCES"), LL_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "exec-floor-deny");
    assert.equal(v?.target, "/tmp/spikestash/payload");
  });
  test("a spawnSync-shape denial on a masked carve-out literal is confirmed on the literal", () => {
    const v = classifyViolation(failLL("spawnSync /usr/bin/curl EACCES"), LL_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "/usr/bin/curl");
  });
  test("a spawnSync-shape EACCES UNDER the floor stays ambient null", () => {
    assert.equal(classifyViolation(failLL("spawnSync /usr/bin/make EACCES"), LL_DS), null);
  });
```

Note for the reviewer: only the FIRST test fails today (it currently returns `suspected` via the macOS fall-through). The second and third already pass through that fall-through (`execDeniedPaths` match / `execAllowedPaths` ambient check) — they are pins proving the new in-branch handling preserves those outcomes.

- [ ] **Step 2: Run the tests to verify the first fails**

Run: `node --import tsx --test packages/sandbox/test/violation.test.ts`
Expected: FAIL — `a floor-OUTSIDE spawnSync-shape denial is confirmed exec-floor-deny (issue #24)` with `confidence: 'suspected'` (actual) vs `'confirmed'` (expected); the two pin tests PASS; all pre-existing tests PASS.

- [ ] **Step 3: Implement the fallback in the Landlock branch**

In `packages/sandbox/src/violation.ts`, replace the Landlock branch's line/target extraction (currently two `const` lines at the top of the `if (denySet.execFloorMode === "linux-landlock")` block):

```ts
  if (denySet.execFloorMode === "linux-landlock") {
    // Dash shape first; a denial surfacing through node instead reports
    // "spawnSync <path> EACCES" (issue #24) — same ladder for both shapes.
    // No canonicalizeMacPath: Linux paths are never firmlink-canonicalized.
    let line = firstLinuxExecLine(stderr);
    let target = line ? LINUX_EXEC_PATH.exec(line)?.[1] ?? null : null;
    if (!line) {
      line = firstSpawnExecLine(stderr);
      target = line ? SPAWN_EXEC_PATH.exec(line)?.[1] ?? null : null;
    }
    if (line && target) {
      const evidence = { exitCode: result.exitCode, stderrExcerpt: excerpt(line) };
      const carved = (denySet.execDeniedPaths ?? []).find((p) => p === target || pathCovers(p, target));
      if (carved) return { kind: "process", target, confidence: "confirmed", deniedResource: carved, evidence };
      const allowed = (denySet.execAllowedPaths ?? []).some((p) => pathCovers(p, target));
      if (!allowed) return { kind: "process", target, confidence: "confirmed", deniedResource: "exec-floor-deny", evidence };
      return null; // under the floor → exec allowed → ambient
    }
  }
```

The attribution body (`carved` → floor-outside → ambient) is byte-identical to what's there today; only the extraction above it changes (`const` → `let` + the spawn fallback). A spawn line with no extractable path leaves `target` null, so the `if (line && target)` guard falls through to the macOS branch exactly as before.

- [ ] **Step 4: Run the violation tests, then the full suite**

Run: `node --import tsx --test packages/sandbox/test/violation.test.ts`
Expected: PASS — all tests including the three new ones.

Run: `npm run build && npm test`
Expected: build clean; 763 pass, 2 skipped on darwin (was 760 — the 3 new tests are hermetic and platform-neutral).

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/violation.ts packages/sandbox/test/violation.test.ts
git commit -m "fix(sandbox): classify a spawnSync-shape exec denial in Landlock floor mode (#24)"
```

### Task 3: CLAUDE.md test notes + PR

**Files:**
- Modify: `CLAUDE.md` (the `npm test` annotation block — the sentence describing Phase 2 (Landlock)'s classifyViolation unit tests, and the `760 tests on this host (758 pass, 2 skipped...)` count)

**Interfaces:**
- Consumes: Task 2 merged into the branch.
- Produces: the PR closing #24.

- [ ] **Step 1: Update CLAUDE.md**

In the `npm test` comment block: change `760 tests on this host (758 pass, 2 skipped on darwin)` to `763 tests on this host (761 pass, 2 skipped on darwin)`, and in the sentence listing Phase 2 (Landlock)'s classifyViolation Landlock-floor-mode unit tests (`"Linux Landlock floor mode (Phase 2)": floor-outside denial confirmed exec-floor-deny, masked carve-out literal still confirmed, under-floor denial null, inert without execFloorMode — violation.test.ts`), extend the parenthetical with `, plus the same three outcomes for the node spawnSync denial shape (#24)`. Also update the later self-reference `the 760 count` occurrences ONLY if they describe the total (they enumerate which suites are IN the count — leave the phrasing, the number is defined once at the top; check with `grep -n "760" CLAUDE.md` and update each hit to 763).

- [ ] **Step 2: Verify the stated count matches reality**

Run: `npm test 2>&1 | tail -5`
Expected: the pass/skip totals printed match the numbers just written into CLAUDE.md. If they differ, fix CLAUDE.md to the actual numbers, not the other way around.

- [ ] **Step 3: Commit, push, open the PR**

```bash
git add CLAUDE.md
git commit -m "docs: CLAUDE.md test notes for the #24 spawnSync-shape Landlock classification fix"
git push -u origin fix-24-landlock-spawnsync-classification
gh pr create --repo git-agentic/pkg-registry \
  --title "fix(sandbox): classify a spawnSync-shape exec denial in Landlock floor mode" \
  --body "Closes #24. In \`execFloorMode === \"linux-landlock\"\`, \`classifyViolation\` now falls back to the existing \`firstSpawnExecLine\`/\`SPAWN_EXEC_PATH\` extractors when no dash-shape line matches, and runs the target through the unchanged attribution ladder — a floor-outside \`spawnSync <path> EACCES\` denial is now \`confirmed\`/\`exec-floor-deny\` instead of \`suspected\`. Telemetry precision only; containment unchanged. Spec: docs/superpowers/specs/2026-07-10-issue-24-landlock-spawnsync-classification-design.md

https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf"
```

Expected: PR opens; CI (ubuntu, Node 22 + 24) runs the Linux enforcement suites and stays green — this change adds no Linux-only tests, but the Landlock effect tests exercise the dash shape end-to-end and must not regress.
