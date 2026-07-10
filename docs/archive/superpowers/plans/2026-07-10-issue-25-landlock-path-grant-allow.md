# Fix #25 — Landlock Path-Grant `--allow` Lift Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On Landlock-active hosts, an approved `process:` **path grant** outside the exec floor (e.g. `process:/opt/vendor/bin/tool`) is appended to the `landlock-exec` helper's `--allow` set and mirrored into `computeDenySet`'s `execAllowedPaths`, so the granted tool actually execs (macOS parity).

**Architecture:** One new shared pure function, `landlockAllowPaths(approved, {homeDir, nodePrefix, projectRoot})` in `packages/sandbox/src/deny-set.ts` (it owns `expandHome`/`isSafeGrantTarget` and already imports `exec-floor` + `sensitive-executables`; defining it in `exec-floor.ts` would create an import cycle). Both call sites — `BubblewrapSandbox.run`'s `--allow` argv and `computeDenySet`'s Landlock branch — call the same function, so generator and classifier cannot drift. `classifyViolation` needs no change. Spec: `docs/superpowers/specs/2026-07-10-issue-25-landlock-path-grant-allow-design.md`.

**Tech Stack:** TypeScript (ESM, NodeNext — internal imports use `.js` specifiers), `node:test` + `tsx`, bubblewrap + the from-source `landlock-exec` helper on Linux CI.

## Global Constraints

- Land AFTER the #24 branch (`fix-24-landlock-spawnsync-classification`) merges; branch off updated `main`.
- No realpath resolution in `landlockAllowPaths` — the helper `open()`s each `--allow` entry, so a symlinked grant target already attaches to the resolved node (spec; unlike #21's bind-destination masks).
- Unsafe targets (`*` never classifies as `path`; `/`, empty, any `..` segment fail `isSafeGrantTarget`) must not widen the floor.
- Behavior with no path grants must be byte-identical (floor-only `--allow` set).
- The Phase 29 `/dev/null` carve-out masking in `generateBwrapArgs` (and its #21 grant lift) is untouched.
- Effect tests are CI-only: inside `bubblewrap.test.ts`'s describe-skip-on-darwin `BubblewrapSandbox enforcement` block, gated `{ skip: skipNoHelper }` like the two existing Landlock effect tests.
- Definition of done: `npm run build` clean, `npm test` green on darwin (+6 hermetic tests over main's count; effect tests verify on Linux CI).

---

### Task 1: Create the branch

**Files:** none (git only)

- [ ] **Step 1: Branch off main (with #24 already merged)**

```bash
git checkout main && git pull && git checkout -b fix-25-landlock-path-grant-allow
```

### Task 2: `landlockAllowPaths` + deny-set mirror

**Files:**
- Modify: `packages/sandbox/src/deny-set.ts` (new export after `isSafeGrantTarget`; one line in the Landlock branch at `deny-set.ts:117-125`)
- Test: `packages/sandbox/test/deny-set.test.ts` (the existing `computeDenySet — Linux Landlock floor mode (Phase 2)` describe and its `L`/`procCap` fixtures)

**Interfaces:**
- Consumes: `linuxExecFloor` (`exec-floor.js`), `classifyProcessTarget` (`sensitive-executables.js`), `expandHome`/`isSafeGrantTarget` (local), `Capability` (`@sentinel/core`) — all already imported by `deny-set.ts`.
- Produces: `export function landlockAllowPaths(approved: Capability[], opts: { homeDir: string; nodePrefix: string; projectRoot: string }): string[]` — Task 3 imports this from `./deny-set.js`.

- [ ] **Step 1: Write the failing tests**

In `packages/sandbox/test/deny-set.test.ts`, add `landlockAllowPaths` to the existing `../src/deny-set.js` import, and add `import { linuxExecFloor } from "../src/exec-floor.js";` if not present. Then add inside `describe("computeDenySet — Linux Landlock floor mode (Phase 2)", ...)`, after the merged-usr test:

```ts
  // Issue #25: approved process: PATH grants join the floor in execAllowedPaths —
  // the Linux mirror of the darwin floor+grants pattern.
  test("a safe process: path grant outside the floor lands in execAllowedPaths (issue #25)", () => {
    const ds = computeDenySet([procCap("/opt/vendor/bin/tool")], { ...L, landlockFloor: true });
    assert.ok(ds.execAllowedPaths!.includes("/opt/vendor/bin/tool"));
    assert.ok(ds.execAllowedPaths!.includes("/bin"), "floor entries still present");
  });
  test("a ~-form path grant expands against homeDir", () => {
    const ds = computeDenySet([procCap("~/tools/bin/x")], { ...L, landlockFloor: true });
    assert.ok(ds.execAllowedPaths!.includes("/home/test/tools/bin/x"));
  });
  test("unsafe path-grant targets never widen the floor", () => {
    const floorOnly = computeDenySet([], { ...L, landlockFloor: true }).execAllowedPaths;
    const ds = computeDenySet([procCap("/"), procCap("/opt/a/../b")], { ...L, landlockFloor: true });
    assert.deepEqual(ds.execAllowedPaths, floorOnly);
  });
  test("command and wildcard grants open no paths (carve-out lift only)", () => {
    const floorOnly = computeDenySet([], { ...L, landlockFloor: true }).execAllowedPaths;
    const ds = computeDenySet([procCap("curl"), procCap("*")], { ...L, landlockFloor: true });
    assert.deepEqual(ds.execAllowedPaths, floorOnly);
  });
  test("non-drift: Landlock execAllowedPaths equals landlockAllowPaths for the same inputs", () => {
    const caps = [procCap("/opt/vendor/bin/tool"), procCap("curl"), procCap("~/tools/bin/x")];
    const ds = computeDenySet(caps, { ...L, landlockFloor: true });
    assert.deepEqual(
      ds.execAllowedPaths,
      landlockAllowPaths(caps, { homeDir: L.homeDir, nodePrefix: L.nodePrefix, projectRoot: L.projectRoot }),
    );
  });
  test("landlockAllowPaths: floor-only with no grants", () => {
    assert.deepEqual(
      landlockAllowPaths([], { homeDir: "/home/test", nodePrefix: "/usr", projectRoot: "/work/pkg" }),
      linuxExecFloor({ nodePrefix: "/usr", projectRoot: "/work/pkg" }),
    );
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --import tsx --test packages/sandbox/test/deny-set.test.ts`
Expected: FAIL — the import of `landlockAllowPaths` doesn't resolve (or, once stubbed, the grant tests fail with `/opt/vendor/bin/tool` missing from `execAllowedPaths`). All pre-existing tests PASS.

- [ ] **Step 3: Implement**

In `packages/sandbox/src/deny-set.ts`, add after `isSafeGrantTarget`:

```ts
/**
 * The Landlock helper's full exec-allow set (Phase 2 + issue #25): the Linux
 * exec floor PLUS every safe, expanded `process:` PATH grant — the Linux
 * mirror of the darwin branch's floor+grants `execAllowedPaths`. Shared by
 * `BubblewrapSandbox.run` (the helper's `--allow` argv) and `computeDenySet`'s
 * Landlock branch, so the generator and the classifier cannot drift. Pure —
 * no realpath: the helper open()s each entry, so a symlinked grant target
 * already attaches to the resolved node (unlike #21's bind-destination masks).
 */
export function landlockAllowPaths(
  approved: Capability[],
  opts: { homeDir: string; nodePrefix: string; projectRoot: string },
): string[] {
  const grants = approved
    .filter((c) => c.kind === "process")
    .map((c) => c.target)
    .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
    .map((t) => expandHome(t, opts.homeDir));
  return [...linuxExecFloor({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot }), ...grants];
}
```

In `computeDenySet`'s Landlock branch (the `if (opts.landlockFloor && opts.nodePrefix && opts.projectRoot)` return), replace the `execAllowedPaths` line:

```ts
        execAllowedPaths: landlockAllowPaths(approved, {
          homeDir: opts.homeDir, nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot,
        }),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --import tsx --test packages/sandbox/test/deny-set.test.ts`
Expected: PASS — all tests including the six new ones.

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/deny-set.ts packages/sandbox/test/deny-set.test.ts
git commit -m "fix(sandbox): landlockAllowPaths — process: path grants join the Landlock execAllowedPaths mirror (#25)"
```

### Task 3: Helper invocation wiring + effect tests

**Files:**
- Modify: `packages/sandbox/src/bubblewrap.ts` (imports + the `inner` argv in `run()`)
- Test: `packages/sandbox/test/bubblewrap.test.ts` (inside the describe-skip-on-darwin `BubblewrapSandbox enforcement` block, after the existing `Landlock floor: a floor binary (node) and a node_modules/.bin shim still run` test; uses the file's existing `skipNoHelper`, `mkdtempSync`/`realpathSync`/`tmpdir`/`join`/`writeFileSync`/`mkdirSync` imports)

**Interfaces:**
- Consumes: `landlockAllowPaths` from `./deny-set.js` (Task 2's export, exact signature above).
- Produces: no API change — `BubblewrapSandbox.run`'s `inner` argv now carries `--allow` entries for path grants.

- [ ] **Step 1: Write the effect tests (CI-verified, not runnable on darwin)**

Add to `packages/sandbox/test/bubblewrap.test.ts` inside the enforcement describe:

```ts
  test("Landlock floor: a process: path grant outside the floor is --allow'ed and execs (issue #25)", { skip: skipNoHelper }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-grant-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const stash = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-vendor-")));
    const tool = join(stash, "tool");
    writeFileSync(tool, "#!/bin/sh\necho TOOL-OK\n", { mode: 0o755 });
    const res = new BubblewrapSandbox().run(`"${tool}"`, {
      cwd: proj, approved: [{ kind: "process", target: tool, evidence: [] }], homeDir: home, projectRoot: proj,
    });
    assert.equal(res.exitCode, 0, res.stderr);
    assert.match(res.stdout, /TOOL-OK/);
    assert.equal(res.violation, undefined);
  });

  test("Landlock floor: the same outside-floor exec WITHOUT the grant stays denied (confirmed exec-floor-deny)", { skip: skipNoHelper }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-nogrant-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const stash = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-vendor2-")));
    const tool = join(stash, "tool");
    writeFileSync(tool, "#!/bin/sh\necho TOOL-OK\n", { mode: 0o755 });
    const res = new BubblewrapSandbox().run(`"${tool}"`, { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    assert.notEqual(res.exitCode, 0);
    assert.doesNotMatch(res.stdout, /TOOL-OK/);
    assert.equal(res.violation?.kind, "process");
    assert.equal(res.violation?.confidence, "confirmed");
    assert.equal(res.violation?.deniedResource, "exec-floor-deny");
  });
```


- [ ] **Step 2: Wire the helper invocation**

In `packages/sandbox/src/bubblewrap.ts`:

Replace the import pair:

```ts
import { computeDenySet } from "./deny-set.js";
...
import { linuxExecFloor } from "./exec-floor.js";
```

with:

```ts
import { computeDenySet, landlockAllowPaths } from "./deny-set.js";
```

(delete the now-unused `linuxExecFloor` import line entirely), and replace the `inner` construction in `run()`:

```ts
    const inner = useLandlock
      ? [
          landlockHelperPath(),
          ...landlockAllowPaths(opts.approved, { homeDir: opts.homeDir, nodePrefix, projectRoot })
            .flatMap((p) => ["--allow", p]),
          "--", "/bin/sh", "-c", cmd,
        ]
      : ["/bin/sh", "-c", cmd];
```

- [ ] **Step 3: Build + full suite on darwin (effect tests skip here)**

Run: `npm run build && npm test`
Expected: build clean; all hermetic tests pass; the two new effect tests are inside the describe-level `requires Linux` skip on darwin. Confirm no TypeScript unused-import error from the removed `linuxExecFloor` line.

- [ ] **Step 4: Commit**

```bash
git add packages/sandbox/src/bubblewrap.ts packages/sandbox/test/bubblewrap.test.ts
git commit -m "fix(sandbox): append process: path grants to the landlock-exec --allow set (#25)"
```

### Task 4: CLAUDE.md notes, follow-up issue, PR (CI is the real verifier)

**Files:**
- Modify: `CLAUDE.md` (the `npm test` annotation block: total count line + the Phase 2 (Landlock) sentences)

**Interfaces:**
- Consumes: Tasks 2–3 committed on the branch.
- Produces: the PR closing #25; a new filed issue for the `$HOME`-grant residual.

- [ ] **Step 1: Update CLAUDE.md**

Run `npm test 2>&1 | tail -5` and copy the ACTUAL totals into the `npm test` comment's count line (main's count + 6 hermetic tests). In the Phase 2 (Landlock) sentence listing `computeDenySet`'s Landlock unit tests, extend with `, plus the issue #25 path-grant execAllowedPaths lift + landlockAllowPaths non-drift tests (deny-set.test.ts)`. In the sentence describing the two Landlock bwrap effect tests inside the describe-level-skip block, change "The two Landlock bwrap effect tests" to "The four Landlock bwrap effect tests" and append the two new test names (`"Landlock floor: a process: path grant outside the floor is --allow'ed and execs (issue #25)"` and `"Landlock floor: the same outside-floor exec WITHOUT the grant stays denied (confirmed exec-floor-deny)"`).

- [ ] **Step 2: File the $HOME-grant residual follow-up issue**

```bash
gh issue create --repo git-agentic/pkg-registry --label bug \
  --title "Linux: a process: path grant under \$HOME can never exec — --tmpfs \$HOME hides it before Landlock is consulted" \
  --body "Found while fixing #25 (see docs/superpowers/specs/2026-07-10-issue-25-landlock-path-grant-allow-design.md, Out of scope). A \`process:\` path grant under \$HOME (e.g. \`process:~/tools/bin/x\`) is now correctly appended to the Landlock \`--allow\` set (#25), but bwrap's \`--tmpfs \$HOME\` (Phase 25 Slice 2, ADR-0038) empties \$HOME before the helper runs, so the exec fails ENOENT — a filesystem-visibility gap, not an exec-floor gap. Fix sketch: \`generateBwrapArgs\` should \`--ro-bind-try\` a safe, expanded \`process:\` path-grant target (or its parent dir) alongside the Slice 2 read-allow re-binds, mirroring how \`filesystem:\` grants re-bind. Fail-closed today (over-blocks; no escape). Refs: packages/sandbox/src/bwrap.ts, ADR-0038, ADR-0044.

https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf"
```

- [ ] **Step 3: Commit, push, open the PR**

```bash
git add CLAUDE.md
git commit -m "docs: CLAUDE.md test notes for the #25 Landlock path-grant --allow lift"
git push -u origin fix-25-landlock-path-grant-allow
gh pr create --repo git-agentic/pkg-registry \
  --title "fix(sandbox): approved process: path grants join the Landlock exec floor (--allow)" \
  --body "Closes #25. New shared pure \`landlockAllowPaths\` in deny-set.ts (floor + safe expanded \`process:\` path grants) feeds BOTH the landlock-exec \`--allow\` argv (bubblewrap.ts) and \`computeDenySet\`'s Landlock \`execAllowedPaths\` — drift-proof by construction, macOS floor+grants parity. Two new CI-only Landlock effect tests prove the grant flips an outside-floor exec from confirmed-denied to running. Known residual (\$HOME-grant visibility) filed as a follow-up issue. Spec: docs/superpowers/specs/2026-07-10-issue-25-landlock-path-grant-allow-design.md

https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf"
```

Expected: PR opens; ubuntu CI (Node 22 + 24) builds the helper from source and runs all four Landlock effect tests — the two new ones are the real regression proof for this fix. Do not merge on darwin-green alone; wait for Linux CI.
