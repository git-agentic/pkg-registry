# Fix #21: merged-usr sibling defeats a path-form `process:` grant — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On merged-usr Linux (Debian/Ubuntu `/bin` → `/usr/bin`), a path-form grant like `--approve process:/usr/bin/curl` must actually lift the exfil-tool carve-out — today the ungranted sibling literal `/bin/curl` resolves back to `/usr/bin/curl` and re-masks it, and `computeDenySet` drifts from the generator.

**Architecture:** One rule applied in two places: *a carve-out candidate literal is lifted when a path grant covers the literal, OR when the grant's resolved form covers the candidate's resolved form.* `generateBwrapArgs` (packages/sandbox/src/bwrap.ts) already has an injectable `realpath`; `computeDenySet` (packages/sandbox/src/deny-set.ts) gains the same optional injectable (identity default, stays pure), and `BubblewrapSandbox.run` (packages/sandbox/src/bubblewrap.ts) passes `safeRealpath` to it. `execDeniedPaths` keeps emitting invocation-form **literals** (the shell prints the invocation form in a denial line) — resolution is used only for the grant-coverage decision. No changes to `classifyViolation`, the darwin branch, or scoring.

**Tech Stack:** TypeScript (ESM, NodeNext — internal imports use `.js` specifiers even from `.ts`), `node:test` + `tsx`, npm workspaces.

**Spec:** `docs/superpowers/specs/2026-07-10-issue-21-merged-usr-path-grant-design.md`

## Global Constraints

- ESM only; internal imports use `.js` specifiers (e.g. `import { pathCovers } from "./path-cover.js"`).
- No new dependencies.
- Hermetic tests only in `npm test` on the dev host (darwin): the merged-usr resolver is *injected* (`/bin/<x>` → `/usr/bin/<x>`), never read from the real filesystem. The one effect test (Task 3) goes inside the existing describe-level-skip-on-darwin `BubblewrapSandbox enforcement` block and runs only on Linux CI.
- `npm run build` = `tsc --build`. If a rebuild misbehaves, use `npx tsc --build --force packages/sandbox` — do NOT `rm -rf dist/` (mount denies rm with EPERM).
- Work on a branch (e.g. `fix-21-merged-usr-path-grant`), commit per task. Commit messages end with the Claude-Session trailer used in this repo.
- Definition of done: `npm run build` clean, `npm test` green on darwin (762 pass-count grows by the new hermetic tests; the Linux effect test is not in the darwin count), existing carve-out behavior without grants byte-identical.

---

### Task 1: Generator fix — `generateBwrapArgs` lifts a candidate whose *resolved* form a *resolved* grant covers

**Files:**
- Modify: `packages/sandbox/src/bwrap.ts` (exec carve-out loop, ~lines 94–114)
- Test: `packages/sandbox/test/bwrap.test.ts` (append inside `describe("generateBwrapArgs — exfil-tool carve-out (Phase 29)")`, after the existing merged-usr mask test at ~line 234)

**Interfaces:**
- Consumes: existing `generateBwrapArgs(approved, opts)` with `opts.realpath?: (p: string) => string`; test helpers `proc(target)`, `lopts(extra?)`, `devNullMasks(argv)` already defined in `bwrap.test.ts` (~lines 172–187).
- Produces: fixed masking behavior other tasks rely on: with grant `/usr/bin/curl` and merged-usr resolution, **neither** `/usr/bin/curl` **nor** `/bin/curl` is masked. (Note: with the test's `pathExists: () => true`, unrelated candidates like `/usr/local/bin/curl` legitimately stay masked — they resolve to a *different* file. Assert on the two sibling literals, not "no curl mask at all".)

- [ ] **Step 1: Write the failing tests**

Append inside the `describe("generateBwrapArgs — exfil-tool carve-out (Phase 29)", ...)` block in `packages/sandbox/test/bwrap.test.ts`, after the existing test `"a merged-usr symlink ancestor (e.g. /bin -> /usr/bin) is masked at its real path, not the symlinked literal, and only once"`:

```ts
  test("merged-usr: a path Grant on the real path lifts its /bin sibling candidate too (issue #21)", () => {
    // Without this, /bin/curl (not literally covered by the grant) resolves to
    // /usr/bin/curl and re-masks the very inode the grant approved.
    const realpath = (p: string) => (p.startsWith("/bin/") ? p.replace(/^\/bin\//, "/usr/bin/") : p);
    const masks = devNullMasks(generateBwrapArgs([proc("/usr/bin/curl")], lopts({ realpath })));
    assert.ok(!masks.includes("/usr/bin/curl"), "the granted real path must not be re-masked via its /bin sibling");
    assert.ok(!masks.includes("/bin/curl"), "the sibling literal itself must be lifted, not just deduped");
    assert.ok(masks.includes("/usr/bin/wget"), "other commands' candidates stay masked");
  });

  test("merged-usr: the inverse grant form (/bin/curl) resolves and lifts both siblings (issue #21)", () => {
    const realpath = (p: string) => (p.startsWith("/bin/") ? p.replace(/^\/bin\//, "/usr/bin/") : p);
    const masks = devNullMasks(generateBwrapArgs([proc("/bin/curl")], lopts({ realpath })));
    assert.ok(!masks.includes("/usr/bin/curl"), "a /bin-form grant must lift the /usr/bin real path");
    assert.ok(!masks.includes("/bin/curl"), "and its own literal");
    assert.ok(masks.includes("/usr/bin/wget"), "wget stays masked");
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx tsx --test packages/sandbox/test/bwrap.test.ts`
Expected: the two new tests FAIL — the first on `"the granted real path must not be re-masked via its /bin sibling"` (masks contain `/usr/bin/curl`), the second similarly. All pre-existing tests PASS.

- [ ] **Step 3: Implement the resolved-coverage check**

In `packages/sandbox/src/bwrap.ts`, the exec carve-out loop currently reads (~lines 94–114):

```ts
  if (!execWildcard) {
    // ... existing merged-usr comment ...
    const maskedReal = new Set<string>();
    for (const cmd of SENSITIVE_EXECUTABLES) {
      if (grantedCmds.has(cmd)) continue;
      for (const lit of execCarveOutPaths(cmd)) {
        if (execPathGrants.some((g) => pathCovers(g, lit))) continue;
        if (!exists(lit)) continue;
        const real = resolve(lit);
        if (maskedReal.has(real)) continue;
        maskedReal.add(real);
        args.push("--ro-bind", "/dev/null", real);
      }
    }
  }
```

Change it to (new lines marked; keep the existing block comment above the loop and extend it):

```ts
  if (!execWildcard) {
    // ... existing merged-usr comment, then append:
    // A PATH grant must agree with that resolution (issue #21): compare grants and
    // candidates in resolved space too, or a grant on /usr/bin/curl is defeated by
    // its ungranted /bin/curl sibling resolving back onto the same inode.
    const resolvedGrants = execPathGrants.map(resolve);
    const maskedReal = new Set<string>();
    for (const cmd of SENSITIVE_EXECUTABLES) {
      if (grantedCmds.has(cmd)) continue;
      for (const lit of execCarveOutPaths(cmd)) {
        if (execPathGrants.some((g) => pathCovers(g, lit))) continue;
        if (!exists(lit)) continue;
        const real = resolve(lit);
        if (resolvedGrants.some((g) => pathCovers(g, real))) continue;
        if (maskedReal.has(real)) continue;
        maskedReal.add(real);
        args.push("--ro-bind", "/dev/null", real);
      }
    }
  }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx tsx --test packages/sandbox/test/bwrap.test.ts`
Expected: PASS, including all pre-existing carve-out tests (the no-grant path is unchanged: `resolvedGrants` is empty, the new `.some()` is always false).

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/bwrap.ts packages/sandbox/test/bwrap.test.ts
git commit -m "fix(sandbox): a path-form process: grant lifts its merged-usr sibling candidate (#21)

Claude-Session: https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf"
```

---

### Task 2: Deny-set mirror — `computeDenySet` gains an injectable `realpath` and applies the same lift rule

**Files:**
- Modify: `packages/sandbox/src/deny-set.ts` (opts type ~line 71, Linux branch ~lines 90–113, branch comment ~lines 85–89)
- Modify: `packages/sandbox/src/bubblewrap.ts` (the `computeDenySet` call, ~lines 117–121)
- Test: `packages/sandbox/test/deny-set.test.ts` (the `computeDenySet ↔ generateBwrapArgs Linux non-drift (Phase 29)` describe block, ~line 122, and the Landlock describe at ~line 174)

**Interfaces:**
- Consumes: Task 1's fixed `generateBwrapArgs`; existing `procCap(target)` helper in `deny-set.test.ts`; the `L` fixture object `{ homeDir: "/home/test", platform: "linux", nodePrefix: "/usr", projectRoot: "/work/pkg", cwd: "/work/pkg", tmpDir: "/tmp/x" }`.
- Produces: `computeDenySet(approved, opts)` accepts `opts.realpath?: (p: string) => string` (identity default). With a merged-usr resolver and grant `/usr/bin/curl`, `execDeniedPaths` excludes **both** `/bin/curl` and `/usr/bin/curl` and still emits all other candidates as **literals** (never resolved). `BubblewrapSandbox.run` passes `realpath: safeRealpath`.

- [ ] **Step 1: Write the failing tests**

In `packages/sandbox/test/deny-set.test.ts`, append inside `describe("computeDenySet ↔ generateBwrapArgs Linux non-drift (Phase 29)", ...)` (after the existing `"non-drift under live merged-usr path resolution (Phase 29)"` test):

```ts
  test("merged-usr: a path grant excludes BOTH sibling literals from execDeniedPaths (issue #21)", () => {
    const mergedUsrResolve = (p: string): string => (p.startsWith("/bin/") ? "/usr/bin/" + p.slice(5) : p);
    const ds = computeDenySet([procCap("/usr/bin/curl")], { ...L, realpath: mergedUsrResolve });
    assert.ok(!ds.execDeniedPaths!.includes("/usr/bin/curl"), "the granted literal is lifted");
    assert.ok(!ds.execDeniedPaths!.includes("/bin/curl"), "the merged-usr sibling literal is lifted too");
    assert.ok(ds.execDeniedPaths!.includes("/usr/bin/wget"), "other commands stay denied");
    assert.ok(ds.execDeniedPaths!.includes("/bin/wget"), "…in BOTH literal forms (invocation-form matching)");
  });

  test("non-drift under live merged-usr path resolution with a PATH grant (issue #21)", () => {
    const mergedUsrResolve = (p: string): string => (p.startsWith("/bin/") ? "/usr/bin/" + p.slice(5) : p);
    const approved: Capability[] = [procCap("/usr/bin/curl")];
    const ds = computeDenySet(approved, { ...L, realpath: mergedUsrResolve });
    const argv = generateBwrapArgs(approved, {
      homeDir: L.homeDir, cwd: L.cwd, tmpDir: L.tmpDir, nodePrefix: L.nodePrefix,
      projectRoot: L.projectRoot, pathExists: () => true, realpath: mergedUsrResolve,
    });
    const masks: string[] = [];
    for (let i = 0; i < argv.length - 2; i++) {
      if (argv[i] === "--ro-bind" && argv[i + 1] === "/dev/null") {
        const mask = argv[i + 2];
        if (SENSITIVE_EXECUTABLES.some((cmd) => mask.endsWith("/" + cmd))) masks.push(mask);
      }
    }
    assert.ok(!masks.includes("/usr/bin/curl") && !masks.includes("/bin/curl"), "the generator lifts both curl siblings");
    for (const m of masks) assert.ok(ds.execDeniedPaths!.includes(m), `deny set must include exec-carve-out masked ${m}`);
  });
```

And inside `describe("computeDenySet — Linux Landlock floor mode (Phase 2)", ...)`:

```ts
  test("Landlock floor mode shares the merged-usr path-grant filter (issue #21)", () => {
    const mergedUsrResolve = (p: string): string => (p.startsWith("/bin/") ? "/usr/bin/" + p.slice(5) : p);
    const ds = computeDenySet([procCap("/usr/bin/curl")], { ...L, landlockFloor: true, realpath: mergedUsrResolve });
    assert.equal(ds.execFloorMode, "linux-landlock");
    assert.ok(!ds.execDeniedPaths!.includes("/bin/curl"), "the sibling literal is lifted in floor mode too");
  });
```

(`procCap` and `L` already exist in this file; `L` in the Landlock describe is a separate const with the same shape — use whichever is in scope for each block.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx tsx --test packages/sandbox/test/deny-set.test.ts`
Expected: TypeScript/`tsx` may fail to compile on the unknown `realpath` option, or the tests FAIL on `"the merged-usr sibling literal is lifted too"`. All pre-existing tests PASS.

- [ ] **Step 3: Implement the injectable realpath + filter**

In `packages/sandbox/src/deny-set.ts`:

(a) Widen the opts type (~line 71):

```ts
  opts: {
    homeDir: string; platform: "darwin" | "linux"; nodePrefix?: string; projectRoot?: string;
    cwd?: string; tmpDir?: string; landlockFloor?: boolean;
    /** resolves symlinks for the Linux path-grant coverage check ONLY (issue #21);
     *  defaults to identity (kept pure for tests). Real callers pass realpathSync-ish. */
    realpath?: (p: string) => string;
  },
```

(b) In the Linux branch, extend the branch comment ("Paths are NOT firmlink-canonicalized on Linux.") with:

```ts
  // execDeniedPaths stays INVOCATION-FORM literals (the shell prints the invoked
  // path in a denial line, and execCarveOutPaths already enumerates both /bin and
  // /usr/bin forms); `realpath` is used only so the grant-coverage decision agrees
  // with generateBwrapArgs's resolved masking on merged-usr systems (issue #21).
```

and change the `lDenied` computation (~lines 94–100) to:

```ts
    const lPathGrants = lProcTargets
      .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
      .map((p) => expandHome(p, opts.homeDir));
    const lResolve = opts.realpath ?? ((p: string) => p);
    const lResolvedGrants = lPathGrants.map(lResolve);
    const lDenied = lWildcard ? [] : SENSITIVE_EXECUTABLES
      .filter((cmd) => !lGrantedCmds.has(cmd))
      .flatMap((cmd) => execCarveOutPaths(cmd))
      .filter((p) => !lPathGrants.some((g) => pathCovers(g, p)))
      .filter((p) => !lResolvedGrants.some((g) => pathCovers(g, lResolve(p))));
```

(Both the Landlock and advisory returns already consume `lDenied`, so this covers both modes.)

(c) In `packages/sandbox/src/bubblewrap.ts`, add `realpath: safeRealpath` to the `computeDenySet` call:

```ts
    const denySet = computeDenySet(opts.approved, {
      homeDir: opts.homeDir, platform: "linux",
      nodePrefix, projectRoot, cwd: opts.cwd, tmpDir: tmpdir(),
      landlockFloor: useLandlock,
      realpath: safeRealpath,
    });
```

(`safeRealpath` is already defined at the top of `bubblewrap.ts` and already passed to `generateBwrapArgs` in the same method.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx tsx --test packages/sandbox/test/deny-set.test.ts`
Expected: PASS, including the pre-existing darwin non-drift and Phase 29/Phase 2 tests (default identity `realpath` leaves all existing behavior byte-identical).

- [ ] **Step 5: Build + full sandbox test file sweep**

Run: `npm run build && npx tsx --test packages/sandbox/test/`
Expected: build clean; all sandbox tests PASS on darwin (the `BubblewrapSandbox enforcement` describe skips).

- [ ] **Step 6: Commit**

```bash
git add packages/sandbox/src/deny-set.ts packages/sandbox/src/bubblewrap.ts packages/sandbox/test/deny-set.test.ts
git commit -m "fix(sandbox): computeDenySet mirrors the resolved path-grant lift (injectable realpath) (#21)

Claude-Session: https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf"
```

---

### Task 3: Linux CI effect test, full verification, and the follow-up issue

**Files:**
- Modify: `packages/sandbox/test/bubblewrap.test.ts` (inside the `describe("BubblewrapSandbox enforcement", { skip }, ...)` block, after the existing test `"the curl carve-out is denied without a Grant and lifted by process:curl"` at ~line 169)

**Interfaces:**
- Consumes: Tasks 1–2 merged behavior; existing imports in `bubblewrap.test.ts` (`BubblewrapSandbox`, `Capability`, `mkdtempSync`, `mkdirSync`, `realpathSync`, `readFileSync`, `join`, `tmpdir`).
- Produces: the real regression test — ubuntu-latest **is** merged-usr, so this exercises the exact #21 scenario end-to-end.

- [ ] **Step 1: Write the effect test**

```ts
  test("a PATH-form Grant (process:/usr/bin/curl) lifts the carve-out on merged-usr (issue #21)", () => {
    // ubuntu-latest is merged-usr (/bin -> /usr/bin): before the #21 fix, the
    // ungranted /bin/curl sibling resolved back to /usr/bin/curl and re-masked it.
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-exec-pathgrant-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const out = join(proj, "curl-out.txt");
    const approved: Capability[] = [{ kind: "process", target: "/usr/bin/curl", evidence: [] }];
    new BubblewrapSandbox().run(`/usr/bin/curl --version > "${out}"`,
      { cwd: proj, approved, homeDir: home, projectRoot: proj });
    assert.ok(readFileSync(out, "utf8").includes("curl"), "a path-form process Grant must lift the merged-usr carve-out");

    // The symlinked invocation form must work under the same grant too:
    new BubblewrapSandbox().run(`/bin/curl --version > "${out}"`,
      { cwd: proj, approved, homeDir: home, projectRoot: proj });
    assert.ok(readFileSync(out, "utf8").includes("curl"), "the /bin symlink invocation form must run under the same grant");
  });
```

- [ ] **Step 2: Verify it is cleanly skipped on darwin and the whole suite is green**

Run: `npm run build && npm test`
Expected: build clean; test suite green on darwin with the pre-existing skip pattern (`BubblewrapSandbox enforcement` skips as a block; the new hermetic tests from Tasks 1–2 are in the passing count). Note the exact new totals for the PR description.

- [ ] **Step 3: Commit**

```bash
git add packages/sandbox/test/bubblewrap.test.ts
git commit -m "test(sandbox): Linux effect test — path-form process: grant lifts the merged-usr carve-out (#21)

Claude-Session: https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf"
```

- [ ] **Step 4: File the out-of-scope follow-up issue (from the spec's follow-ups section)**

```bash
gh issue create --repo git-agentic/pkg-registry --label bug --title "Linux Landlock: approved process: path grants outside the floor are never added to the helper's --allow set" --body "Found while fixing #21 (see docs/superpowers/specs/2026-07-10-issue-21-merged-usr-path-grant-design.md, Out of scope).

The Landlock exec floor is built from \`linuxExecFloor({nodePrefix, projectRoot})\` only (\`packages/sandbox/src/bubblewrap.ts\`, the \`inner\` argv) — approved \`process:\` **path grants** are never appended as \`--allow\` entries, and \`computeDenySet\`'s Landlock branch mirrors that (\`execAllowedPaths\` = floor only). So on a Landlock-active host, a grant like \`process:/opt/vendor/bin/tool\` outside the floor is exec-denied anyway. macOS lifts path grants into the Seatbelt exec allow (and its deny-set branch includes them in \`execAllowedPaths\`); Linux Landlock does not.

Direction is fail-closed (over-blocks; no exec escape). Grants inside floor dirs (e.g. \`/usr/bin/...\`) are unaffected — the carve-out mask, fixed by #21, is the only deny mechanism for those.

Fix sketch: append safe (\`isSafeGrantTarget\`) expanded path-grant targets as extra \`--allow\` args to the landlock-exec invocation, and include them in the Landlock branch's \`execAllowedPaths\` (mirroring the macOS pattern). Not #24 — that is denial-shape classification.

Refs: \`packages/sandbox/src/bubblewrap.ts\`, \`packages/sandbox/src/deny-set.ts\` (Landlock branch), ADR-0044.

https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf"
```

Expected: issue created; note its number.

- [ ] **Step 5: Finish the branch**

Use the superpowers:finishing-a-development-branch skill. The PR (if that route is chosen) should say "Closes #21", summarize the fix rule, and note that the real regression coverage is the Linux CI effect test. Linux CI green is required before merge — the effect test cannot run on the darwin dev host.

---

## Self-Review (done at plan-writing time)

- **Spec coverage:** fix rule → Task 1 (generator) + Task 2 (deny-set + call site); literal-emission requirement → Task 2 Step 1 asserts both `/bin/wget` and `/usr/bin/wget` remain; both grant directions → Task 1's two tests; non-drift path-grant variant → Task 2; Linux CI effect test → Task 3; docs (no ADR change) → none needed; follow-up issue → Task 3 Step 4. One deliberate refinement vs the spec's shorthand: the spec said "no curl mask in the argv at all", but with the hermetic `pathExists: () => true` the `/usr/local/bin/curl` and `/opt/homebrew/bin/curl` candidates legitimately stay masked (different files) — the tests assert on the two sibling literals instead, which is the actual bug surface.
- **Placeholder scan:** none.
- **Type consistency:** `realpath?: (p: string) => string` matches `generateBwrapArgs`'s existing option; `procCap`/`L`/`proc`/`lopts`/`devNullMasks` all match the existing test helpers verified in source.
