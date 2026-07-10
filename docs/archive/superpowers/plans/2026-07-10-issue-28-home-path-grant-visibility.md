# Issue #28: Under-$HOME `process:` Path-Grant Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a `process:` path grant under `$HOME` actually executable inside the Linux bwrap sandbox (today `--tmpfs $HOME` hides it → ENOENT before Landlock is consulted), and harden `isSafeGrantTarget` against bare-`~` grants that expand to all of `$HOME`.

**Architecture:** Two pure-function changes in `packages/sandbox`: (1) `generateBwrapArgs` (`bwrap.ts`) re-exposes safe, expanded `process:` path grants *strictly under* `$HOME` as `--ro-bind-try` mounts after the Slice 2 tmpfs; (2) `isSafeGrantTarget` (`deny-set.ts`) gets a one-line syntactic reject of `~` and `~/`, which flows into every existing call site (darwin Seatbelt profile, `landlockAllowPaths`, both `computeDenySet` branches, bwrap rw grants) with no signature change. No classifier changes — visibility isn't classified. Spec: `docs/superpowers/specs/2026-07-10-issue-28-home-path-grant-visibility-design.md`.

**Tech Stack:** TypeScript (ESM, NodeNext — internal imports use `.js` specifiers), `node:test` + `tsx`, npm workspaces.

## Global Constraints

- No scoring, policy, or approval-model changes (invariants #1–#7 untouched). This plan touches only `packages/sandbox` src/tests, plus CLAUDE.md.
- ESM only; internal imports use `.js` specifiers even from `.ts` sources.
- Never delete `dist/` (the mount can EPERM on `rm`); use `npx tsc --build --force packages/sandbox` if a rebuild is needed.
- Hermetic tests only in `npm test` — never hit live npm.
- The two Linux effect tests (Task 3) CANNOT run on darwin: they live inside `bubblewrap.test.ts`'s describe-level-skip-on-darwin `BubblewrapSandbox enforcement` block and verify on Linux CI (ubuntu, Node 22 + 24). On this darwin host, only confirm the suite still parses and skips.
- Do NOT do arithmetic on CLAUDE.md's documented test count — run `npm test` and use the actual printed count (see Task 4).
- Behavior guarantee: the generated bwrap argv must be byte-identical for every configuration with no under-`$HOME` path grant and no bare-`~` grant.

---

### Task 0: Branch

**Files:** none (git only)

- [ ] **Step 1: Create the work branch**

```bash
git checkout -b fix-28-home-path-grant-visibility
```

(If executing via a worktree skill, the worktree replaces this step — just ensure the branch name is `fix-28-home-path-grant-visibility`.)

---

### Task 1: `isSafeGrantTarget` rejects bare `~` and `~/`

**Files:**
- Modify: `packages/sandbox/src/deny-set.ts:46-49` (the `isSafeGrantTarget` function)
- Test: `packages/sandbox/test/deny-set.test.ts` (the existing `describe("isSafeGrantTarget", ...)` block at ~line 274, and the `describe("computeDenySet — Linux Landlock floor mode (Phase 2)", ...)` block at ~line 203)
- Test: `packages/sandbox/test/profile.test.ts`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `isSafeGrantTarget(target: string): boolean` — same signature, now returns `false` for `"~"` and `"~/"`. Task 2's re-bind logic and every existing call site (`profile.ts:50,91`, `deny-set.ts:67,126,160`, `bwrap.ts:47,92`) rely on this rejection happening inside the shared predicate.

- [ ] **Step 1: Write the failing tests**

In `packages/sandbox/test/deny-set.test.ts`, add to the existing `describe("isSafeGrantTarget", ...)` block (after the `"any '..' path-traversal segment is rejected"` test):

```ts
  test("bare '~' and '~/' are rejected — they expand to all of $HOME (#28)", () => {
    assert.ok(!isSafeGrantTarget("~"));
    assert.ok(!isSafeGrantTarget("~/"));
    assert.ok(isSafeGrantTarget("~/tools/bin/x"), "a ~-prefixed real path stays allowed");
  });
```

In the same file, add to the `describe("computeDenySet — Linux Landlock floor mode (Phase 2)", ...)` block (after the `"landlockAllowPaths: floor-only with no grants"` test — `procCap`, `landlockAllowPaths`, and `linuxExecFloor` are already imported/defined there):

```ts
  test("landlockAllowPaths: a bare '~' grant is dropped (floor-only result, #28)", () => {
    assert.deepEqual(
      landlockAllowPaths([procCap("~")], { homeDir: "/home/test", nodePrefix: "/usr", projectRoot: "/work/pkg" }),
      linuxExecFloor({ nodePrefix: "/usr", projectRoot: "/work/pkg" }),
    );
  });
```

In `packages/sandbox/test/profile.test.ts`, add inside the top-level `describe("generateProfile", ...)` block (the `fs` helper and `withOpts` are defined at the top of the file; `HOME` is `"/Users/test"`):

```ts
  test("a bare '~' grant does not open $HOME for write, read, or exec (#28 guard)", () => {
    const p = generateProfile(
      [fs("~"), { kind: "process", target: "~", evidence: [] }],
      withOpts({ homeDir: HOME }),
    );
    // The exact closing quote makes this precise: read-allow entries like
    // "/Users/test/.node-gyp" do not match '(subpath "/Users/test")'.
    assert.ok(!p.includes('(subpath "/Users/test")'), "no allow form may target $HOME itself");
    assert.match(p, /\(deny file-read\* \(subpath "\/Users\/test"\)\)/); // Slice 2 deny still present
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npx tsx --test packages/sandbox/test/deny-set.test.ts packages/sandbox/test/profile.test.ts
```

Expected: the three new tests FAIL (`isSafeGrantTarget("~")` currently returns `true`; the profile currently emits `(subpath "/Users/test")` in its allow lines; `landlockAllowPaths` currently includes `/home/test`). All pre-existing tests PASS.

- [ ] **Step 3: Implement the guard**

In `packages/sandbox/src/deny-set.ts`, replace the `isSafeGrantTarget` body (currently lines 46–49):

```ts
export function isSafeGrantTarget(target: string): boolean {
  if (!target || target === "*" || target === "/") return false;
  if (target === "~" || target === "~/") return false; // expands to all of $HOME (#28)
  return !target.split("/").includes("..");
}
```

Also extend the function's doc comment (the paragraph above it) with one sentence:

```
 * Bare `~` (and `~/`) is rejected too (#28): it expands to all of `$HOME` —
 * including the writable write-floor entries under home — re-opening nearly
 * as much as the rejected `/`.
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npx tsx --test packages/sandbox/test/deny-set.test.ts packages/sandbox/test/profile.test.ts packages/sandbox/test/bwrap.test.ts packages/sandbox/test/seatbelt.test.ts
```

Expected: ALL PASS (the extra two files check no existing generator behavior regressed).

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/deny-set.ts packages/sandbox/test/deny-set.test.ts packages/sandbox/test/profile.test.ts
git commit -m "fix(sandbox): isSafeGrantTarget rejects bare ~ grants — they expand to all of \$HOME (#28)"
```

---

### Task 2: `generateBwrapArgs` re-exposes under-`$HOME` `process:` path grants

**Files:**
- Modify: `packages/sandbox/src/bwrap.ts:50-69` (the `ro` list + mount steps) and `packages/sandbox/src/bwrap.ts:88-93` (the `process:`-target computation, which hoists up)
- Test: `packages/sandbox/test/bwrap.test.ts`

**Interfaces:**
- Consumes: `isSafeGrantTarget` from Task 1 (bare `~` already dropped before this task's filter runs).
- Produces: no new exports. `generateBwrapArgs(approved, opts)` signature unchanged; new behavior: for each approved `process:` capability whose target classifies as `path`, passes `isSafeGrantTarget`, and — after `expandHome` — starts with `homeDir + "/"`, the argv gains `--ro-bind-try <expanded> <expanded>` positioned after `--tmpfs <homeDir>` and before the step 4 rw binds.

- [ ] **Step 1: Write the failing tests**

In `packages/sandbox/test/bwrap.test.ts`, add after the `describe("generateBwrapArgs — exfil-tool carve-out (Phase 29)", ...)` block. Reuse the existing module-scope helpers — do NOT redefine them: `binds` (line 56), `OPTS2` (line 62, `homeDir: "/home/x"`), `fs` (line 7), and `proc` (line 172, already `(target) => ({ kind: "process", target, evidence: [] })`):

```ts
/** Index of the (flag, value) pair in the flat argv, or -1. */
function pairIdx(args: string[], flag: string, value: string): number {
  for (let i = 0; i < args.length; i++) if (args[i] === flag && args[i + 1] === value) return i;
  return -1;
}

describe("generateBwrapArgs — under-$HOME process: path-grant visibility (issue #28)", () => {
  test("a process: path grant under $HOME is --ro-bind-try'd back inside the tmpfs, AFTER it", () => {
    const args = generateBwrapArgs([proc("~/tools/bin/x")], OPTS2);
    const grantIdx = pairIdx(args, "--ro-bind-try", "/home/x/tools/bin/x");
    const tmpfsIdx = pairIdx(args, "--tmpfs", "/home/x");
    assert.ok(grantIdx >= 0, "the grant target must be re-exposed read-only");
    assert.ok(tmpfsIdx >= 0, "the $HOME tmpfs mask must remain");
    assert.ok(grantIdx > tmpfsIdx, "the re-expose must come AFTER the tmpfs (mount order: later wins)");
  });

  test("a process: path grant outside $HOME gets no re-bind (already visible via the ro root)", () => {
    const args = generateBwrapArgs([proc("/opt/vendor/bin/tool")], OPTS2);
    assert.ok(!binds(args, "--ro-bind-try").includes("/opt/vendor/bin/tool"));
    assert.ok(!binds(args, "--bind-try").includes("/opt/vendor/bin/tool"), "and it is not rw-bound either");
  });

  test("a bare '~' grant (process or filesystem) re-binds nothing; the tmpfs stays (#28 guard)", () => {
    const args = generateBwrapArgs([proc("~"), fs("~")], OPTS2);
    for (const flag of ["--ro-bind-try", "--bind-try", "--bind"]) {
      assert.ok(!binds(args, flag).includes("/home/x"), `${flag} must not re-expose $HOME itself`);
    }
    assert.ok(binds(args, "--tmpfs").includes("/home/x"), "the $HOME tmpfs mask stays");
  });

  test("an absolute process: grant equal to homeDir does not re-bind $HOME (strictly-under filter)", () => {
    // The syntactic ~-guard cannot see this form; the strictly-under filter must catch it.
    const args = generateBwrapArgs([proc("/home/x")], OPTS2);
    assert.ok(!binds(args, "--ro-bind-try").includes("/home/x"));
    assert.ok(binds(args, "--tmpfs").includes("/home/x"), "the $HOME tmpfs mask stays");
  });

  test("command and wildcard process grants produce no re-binds (paths only)", () => {
    const withCmd = generateBwrapArgs([proc("curl"), proc("*")], OPTS2);
    const baseline = generateBwrapArgs([], OPTS2);
    assert.deepEqual(binds(withCmd, "--ro-bind-try"), binds(baseline, "--ro-bind-try"));
  });

  test("a path grant re-binds even when a wildcard grant is co-present (wildcard lifts masks, opens no paths)", () => {
    const args = generateBwrapArgs([proc("*"), proc("~/tools/bin/x")], OPTS2);
    assert.ok(binds(args, "--ro-bind-try").includes("/home/x/tools/bin/x"));
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npx tsx --test packages/sandbox/test/bwrap.test.ts
```

Expected: the first and last new tests FAIL (`--ro-bind-try /home/x/tools/bin/x` is not emitted today). The other four new tests PASS already (they pin current no-op behavior — that's intentional: they lock the byte-identical guarantee). All pre-existing tests PASS.

- [ ] **Step 3: Implement the re-expose**

In `packages/sandbox/src/bwrap.ts`:

**(a)** Move the `process:`-target computation (currently lines 88–93, the five statements from `const procTargets = ...` through `.map((p) => expandHome(p, home));`) up to just after the `const rw = ...` declaration (after current line 49), keeping it verbatim:

```ts
  // process: targets — computed BEFORE the mounts because path grants under $HOME
  // feed the ro re-binds below (issue #28), not just the Phase 29 mask loop.
  const procTargets = approved.filter((c) => c.kind === "process").map((c) => c.target);
  const grantedCmds = new Set(procTargets.filter((t) => classifyProcessTarget(t) === "command"));
  const execWildcard = procTargets.some((t) => classifyProcessTarget(t) === "wildcard");
  const execPathGrants = procTargets
    .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
    .map((p) => expandHome(p, home));
```

(The mask loop lower down keeps using these same consts — delete the now-duplicate block that preceded it.)

**(b)** After the existing `const ro = ...` declaration (currently lines 52–54), add:

```ts
  // issue #28: a process: path grant STRICTLY UNDER $HOME must be re-exposed inside
  // the tmpfs (read-only — exec permission is Landlock's job, and bwrap has no noexec)
  // or its exec fails ENOENT before Landlock is consulted. Outside-home grants are
  // already visible via the ro root bind; $HOME itself or an ancestor is excluded by
  // the strictly-under filter (re-binding it would nullify the tmpfs).
  const roGrants = execPathGrants.filter((p) => p.startsWith(home + "/"));
```

**(c)** Change the step 3 mount loop (currently line 65) from:

```ts
  for (const p of ro) args.push("--ro-bind-try", p, p);
```

to:

```ts
  for (const p of [...ro, ...roGrants]) args.push("--ro-bind-try", p, p);
```

**(d)** Update the function's doc comment (lines 8–17): after the sentence ending `SENSITIVE masks carve out last.`, insert: `Approved process: path grants strictly under $HOME re-bind read-only beside the read-allow (issue #28).`

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npx tsx --test packages/sandbox/test/bwrap.test.ts packages/sandbox/test/deny-set.test.ts packages/sandbox/test/bubblewrap.test.ts
```

Expected: ALL PASS (bubblewrap.test.ts's enforcement suite reports its describe-level skip on darwin — that's normal).

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/bwrap.ts packages/sandbox/test/bwrap.test.ts
git commit -m "fix(sandbox): re-expose under-\$HOME process: path grants inside the bwrap tmpfs (#28)"
```

---

### Task 3: Linux effect tests + deny-set test-comment flip

**Files:**
- Modify: `packages/sandbox/test/bubblewrap.test.ts` (append two tests inside the `BubblewrapSandbox enforcement` describe block, after the last `"Landlock floor: ..."` test at ~line 275)
- Modify: `packages/sandbox/test/deny-set.test.ts:244-247` (comment only)

**Interfaces:**
- Consumes: Task 2's re-bind behavior (end-to-end through `BubblewrapSandbox.run`, which threads `homeDir` into both `generateBwrapArgs` and `landlockAllowPaths`).
- Produces: nothing consumed later — these are the regression proof. They use the file's existing imports (`realpathSync`, `mkdtempSync`, `mkdirSync`, `writeFileSync`, `join`, `tmpdir`, `BubblewrapSandbox`, `Capability`) and the existing `skipNoHelper` gate (line 17).

- [ ] **Step 1: Add the two effect tests**

Append inside the `BubblewrapSandbox enforcement` describe block, after the `"Landlock floor: the same outside-floor exec WITHOUT the grant stays denied"` test:

```ts
  test("Landlock floor: a process: path grant under $HOME is re-exposed and execs (issue #28)", { skip: skipNoHelper }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-homegrant-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const toolDir = join(home, "tools", "bin"); mkdirSync(toolDir, { recursive: true });
    const tool = join(toolDir, "x");
    writeFileSync(tool, "#!/bin/sh\necho HOME-TOOL-OK\n", { mode: 0o755 });
    // The ~-form grant exercises expandHome against the run's homeDir end-to-end:
    // it must land in BOTH the Landlock --allow set (#25) and the ro re-binds (#28).
    const approved: Capability[] = [{ kind: "process", target: "~/tools/bin/x", evidence: [] }];
    const res = new BubblewrapSandbox().run(`"${tool}"`, { cwd: proj, approved, homeDir: home, projectRoot: proj });
    assert.equal(res.exitCode, 0, res.stderr);
    assert.match(res.stdout, /HOME-TOOL-OK/);
    assert.equal(res.violation, undefined);
  });

  test("Landlock floor: the same under-$HOME exec WITHOUT the grant stays contained (tmpfs ENOENT)", { skip: skipNoHelper }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-homenogrant-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const toolDir = join(home, "tools", "bin"); mkdirSync(toolDir, { recursive: true });
    const tool = join(toolDir, "x");
    writeFileSync(tool, "#!/bin/sh\necho HOME-TOOL-OK\n", { mode: 0o755 });
    const res = new BubblewrapSandbox().run(`"${tool}"`, { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    assert.notEqual(res.exitCode, 0);
    assert.doesNotMatch(res.stdout, /HOME-TOOL-OK/);
    // Containment-only: the tmpfs makes the path ENOENT, which carries no perm
    // signature, so NO violation classification is asserted (the accepted
    // Seatbelt/bwrap telemetry asymmetry, ADR-0038/ADR-0023).
  });
```

- [ ] **Step 2: Flip the deny-set test comment**

In `packages/sandbox/test/deny-set.test.ts`, the `"a ~-form path grant expands against homeDir"` test (~line 244) — add a comment as the first line of the test body (no assertion changes):

```ts
  test("a ~-form path grant expands against homeDir", () => {
    // runtime visibility: fixed by #28 — generateBwrapArgs re-exposes under-$HOME
    // grants inside the tmpfs (see the bubblewrap "re-exposed and execs" effect test).
    const ds = computeDenySet([procCap("~/tools/bin/x")], { ...L, landlockFloor: true });
    assert.ok(ds.execAllowedPaths!.includes("/home/test/tools/bin/x"));
  });
```

- [ ] **Step 3: Verify nothing broke on darwin**

```bash
npx tsx --test packages/sandbox/test/bubblewrap.test.ts packages/sandbox/test/deny-set.test.ts
```

Expected: ALL PASS on darwin; the `BubblewrapSandbox enforcement` block reports as skipped ("requires Linux"). The two new tests execute only on Linux CI with a built `landlock-exec` helper.

- [ ] **Step 4: Commit**

```bash
git add packages/sandbox/test/bubblewrap.test.ts packages/sandbox/test/deny-set.test.ts
git commit -m "test(sandbox): #28 Linux effect tests — under-\$HOME grant execs; ungranted stays contained"
```

---

### Task 4: CLAUDE.md test notes + full verification

**Files:**
- Modify: `CLAUDE.md` (the `npm test` comment block under "Build / test / run")

**Interfaces:**
- Consumes: all prior tasks (needs their tests present for the count).
- Produces: nothing — documentation + final gate.

- [ ] **Step 1: Full build and test**

```bash
npm run build && npm test
```

Expected: build clean; on darwin all tests pass with 2 skips (plus the describe-level Linux skips). **Record the actual printed test count** — do not compute it.

- [ ] **Step 2: Update CLAUDE.md's test notes**

In CLAUDE.md's `npm test` comment block, the sentence beginning `# The four Landlock bwrap effect tests in bubblewrap.test.ts` — update it to say **six** and append the two new test names to its parenthesized list:

`"Landlock floor: a process: path grant under $HOME is re-exposed and execs (issue #28)", and "Landlock floor: the same under-$HOME exec WITHOUT the grant stays contained (tmpfs ENOENT)"`

Then, after the sentence about the issue #25 tests in the `Phase 2 (Landlock)` test-notes passage (`...plus the issue #25 path-grant execAllowedPaths lift + landlockAllowPaths non-drift tests (deny-set.test.ts),`), append a clause:

`plus the issue #28 hermetic tests (the isSafeGrantTarget bare-~ reject and landlockAllowPaths drop in deny-set.test.ts, the under-$HOME grant-visibility generateBwrapArgs describe in bwrap.test.ts, and the bare-~ profile guard test in profile.test.ts — platform-neutral, in the darwin count),`

If `npm test`'s actual count differs from the documented `775`, update the documented number to the actual count.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: CLAUDE.md test notes for the #28 under-\$HOME path-grant visibility fix"
```

- [ ] **Step 4: Finish**

Implementation complete. Use superpowers:finishing-a-development-branch. Repo conventions: PR to `git-agentic/pkg-registry` (like #25 → PR #29), and note in the PR body that merging closes #28 (`Fixes #28`). No ADR changes (per the spec: this makes ADR-0038/0044's documented grant semantics true; reverses nothing).
