# Phase 29 — Linux exec carve-out + advisory floor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On Linux, deny exec of the known exfil tools (`curl`/`wget`/`nc`/…) by `/dev/null`-masking them under bwrap (pure TypeScript), surface a denied carve-out exec as a `confirmed` process violation, and honestly document the Linux exec *floor* as advisory (bwrap cannot `noexec`).

**Architecture:** Extend the Linux backend (`packages/sandbox`) reusing Phase 28's shared pure helpers (`SENSITIVE_EXECUTABLES`, `execCarveOutPaths`, `classifyProcessTarget`). `generateBwrapArgs` gains `--ro-bind /dev/null <literal>` masks (the pattern the repo already uses for sensitive reads); `computeDenySet` gains a **Linux carve-out branch with no floor**; `classifyViolation` gains a Linux exec-denial branch that only ever confirms on a known masked literal — leaving the macOS exec branch byte-unchanged. There is **no exec floor on Linux** (bwrap can't path-gate exec); that gap is documented, not enforced.

**Tech Stack:** TypeScript ESM (NodeNext, `.js` specifiers), `node:test` + `tsx`, Linux `bwrap`. No native dependency.

**Spec:** `docs/superpowers/specs/2026-07-10-phase-29-linux-exec-deny-design.md`

## Global Constraints

- ESM only; internal imports use `.js` specifiers even from `.ts` sources.
- Generators (`generateBwrapArgs`, `computeDenySet`) and `classifyViolation` are **pure/deterministic**: no `Date.now()`, no fs calls, no PATH resolution (except the injected `pathExists` bwrap already uses).
- **The macOS/Seatbelt path and the pre-existing bwrap filesystem/read/write/network logic stay byte-unchanged.** Adding the Linux carve-out must not perturb `generateProfile`, the macOS exec branch of `computeDenySet`/`classifyViolation`, or the existing bwrap mounts.
- **No exec floor on Linux.** `execAllowFloor` is deliberately NOT used on Linux. Linux exec violations are only ever `confirmed` on a masked literal — never `suspected`, never `exec-default-deny`.
- Reuse Phase 28 helpers unchanged; no duplication of the carve-out list or grant-shape logic.
- Synthetic malware fixtures are never executed; effect tests use benign probes only.
- Build artifacts may be un-`rm`-able (EPERM on this mount) — use `npx tsc --build --force packages/sandbox` instead of deleting `dist/`.
- Single test file: `node --import tsx --test packages/sandbox/test/<file>.test.ts`. Full suite: `npm test`.
- **The Linux enforcement path runs only in CI** (ubuntu-latest) — it cannot be exercised on the macOS dev host. Generator/deny-set/classifier logic is unit-tested hermetically and **platform-neutrally** (runs on macOS). Only the **effect tests** need Linux; they are `describe`-gated to skip on darwin, exactly like the existing `BubblewrapSandbox` suite, and their real proof is a CI run.
- Commit messages: `feat(sandbox):`/`docs:`/`test(sandbox):`, ending with the `Claude-Session:` trailer used in recent commits.
- **#8 stays OPEN** — the carve-out does not enforce a cross-platform exec floor. This phase comments on #8; it does not close it.

---

### Task 1: Carve-out masking in `generateBwrapArgs`

**Files:**
- Modify: `packages/sandbox/src/bwrap.ts` (imports at top; add a process/carve-out block near the SENSITIVE-mask loop, lines ~61-69)
- Test: `packages/sandbox/test/bwrap.test.ts` (append a new `describe` block)

**Interfaces:**
- Consumes: `SENSITIVE_EXECUTABLES`, `execCarveOutPaths`, `classifyProcessTarget` (`packages/sandbox/src/sensitive-executables.ts`); existing local `isSafeGrantTarget`, `expandHome`, `pathCovers`, the injected `exists` (`pathExists`).
- Produces: `generateBwrapArgs` argv gains `--ro-bind /dev/null <literal>` entries; Task 2's non-drift test and Task 4's effect test rely on them.

- [ ] **Step 1: Create the Phase 29 branch**

```bash
git checkout main && git pull --ff-only && git checkout -b phase-29-linux-exec-carveout
```

- [ ] **Step 2: Write the failing tests** (append to `packages/sandbox/test/bwrap.test.ts`; reuse the file's existing helpers — inspect the top of the file for its `cap`/`opts` builders and match them. The block below constructs capabilities inline so it is self-contained.)

```ts
const proc = (target: string): Capability => ({ kind: "process", target, evidence: [] });
const L_HOME = "/home/test";
// all candidate literals "exist" so masks are emitted:
const allExist = () => true;
const lopts = (extra?: Partial<Parameters<typeof generateBwrapArgs>[1]>) => ({
  homeDir: L_HOME, cwd: "/work/pkg", tmpDir: "/tmp/x",
  nodePrefix: "/usr", projectRoot: "/work/pkg", pathExists: allExist, ...extra,
});
// helper: pull the mask target that follows each "--ro-bind /dev/null" in argv
function devNullMasks(argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length - 2; i++) {
    if (argv[i] === "--ro-bind" && argv[i + 1] === "/dev/null") out.push(argv[i + 2]);
  }
  return out;
}

describe("generateBwrapArgs — exfil-tool carve-out (Phase 29)", () => {
  test("masks curl/wget/nc/… literals with --ro-bind /dev/null when they exist", () => {
    const masks = devNullMasks(generateBwrapArgs([], lopts()));
    assert.ok(masks.includes("/usr/bin/curl"), "curl must be masked");
    assert.ok(masks.includes("/usr/bin/wget"), "wget must be masked");
    assert.ok(masks.includes("/bin/nc") || masks.includes("/usr/bin/nc"), "nc must be masked");
  });

  test("skips a literal that does not exist (pathExists=false)", () => {
    const masks = devNullMasks(generateBwrapArgs([], lopts({ pathExists: () => false })));
    assert.ok(!masks.some((m) => m.endsWith("/curl")), "non-existent literals must not be masked");
  });

  test("a command Grant lifts exactly that command's masks", () => {
    const masks = devNullMasks(generateBwrapArgs([proc("curl")], lopts()));
    assert.ok(!masks.some((m) => m.endsWith("/curl")), "process:curl lifts curl masks");
    assert.ok(masks.some((m) => m.endsWith("/wget")), "siblings stay masked");
  });

  test("a path Grant covering a literal lifts that literal's mask", () => {
    const masks = devNullMasks(generateBwrapArgs([proc("/usr/bin/curl")], lopts()));
    assert.ok(!masks.includes("/usr/bin/curl"), "path grant lifts the covered literal");
    assert.ok(masks.includes("/bin/curl") || masks.some((m) => m.endsWith("/wget")), "other candidates stay masked");
  });

  test("the * Grant lifts all carve-out masks", () => {
    const masks = devNullMasks(generateBwrapArgs([proc("*")], lopts()));
    assert.ok(!masks.some((m) => SENSITIVE_EXECUTABLES.some((c) => m.endsWith("/" + c))), "* lifts every mask");
  });

  test("does not disturb the existing SENSITIVE read masks or network/floor args", () => {
    const a = generateBwrapArgs([], lopts());
    const b = generateBwrapArgs([proc("curl")], lopts());
    // the non-carve-out argv (everything except the /dev/null carve-out masks) is identical:
    const strip = (argv: string[]) => JSON.stringify(argv);
    // only the curl masks differ; assert both contain the shared floor/network structure:
    assert.ok(a.includes("--unshare-net") && b.includes("--unshare-net"));
    assert.ok(a.includes("--tmpfs") && b.includes("--tmpfs"));
    assert.notEqual(strip(a), strip(b)); // they DO differ (curl masks) — sanity
  });

  test("deterministic for the same inputs", () => {
    assert.deepEqual(generateBwrapArgs([proc("curl")], lopts()), generateBwrapArgs([proc("curl")], lopts()));
  });
});
```

- [ ] **Step 3: Run to verify the new block fails**

Run: `node --import tsx --test packages/sandbox/test/bwrap.test.ts`
Expected: existing tests PASS; the new block FAILS (no `/dev/null` masks for curl/wget/nc yet).

- [ ] **Step 4: Implement** — add imports and a carve-out block in `generateBwrapArgs`. Add to the imports at the top of `bwrap.ts`:

```ts
import { SENSITIVE_EXECUTABLES, execCarveOutPaths, classifyProcessTarget } from "./sensitive-executables.js";
```

Then, inside `generateBwrapArgs`, insert this block **immediately after** the existing SENSITIVE-masks loop (the `for (const sp of sensitivePathsFor("linux"))` loop that ends at `bwrap.ts:69`) and **before** `if (!hasNetwork) args.push("--unshare-net");`:

```ts
  // Exfil-tool carve-out (Phase 29): mask each SENSITIVE_EXECUTABLES literal with
  // /dev/null so exec of it fails (execve on a non-regular file → EACCES), unless an
  // approved `process:` Grant covers it. Reuses the SENSITIVE-read mask pattern above.
  // There is NO exec FLOOR on Linux — bwrap can't path-gate exec (advisory by decision,
  // ADR-0043); only these known literals are exec-denied.
  const procTargets = approved.filter((c) => c.kind === "process").map((c) => c.target);
  const grantedCmds = new Set(procTargets.filter((t) => classifyProcessTarget(t) === "command"));
  const execWildcard = procTargets.some((t) => classifyProcessTarget(t) === "wildcard");
  const execPathGrants = procTargets
    .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
    .map((p) => expandHome(p, home));
  if (!execWildcard) {
    for (const cmd of SENSITIVE_EXECUTABLES) {
      if (grantedCmds.has(cmd)) continue;
      for (const lit of execCarveOutPaths(cmd)) {
        if (execPathGrants.some((g) => pathCovers(g, lit))) continue;
        if (!exists(lit)) continue;
        args.push("--ro-bind", "/dev/null", lit);
      }
    }
  }
```

- [ ] **Step 5: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/bwrap.test.ts`
Expected: PASS (existing + new block).

- [ ] **Step 6: Build + commit**

```bash
npx tsc --build --force packages/sandbox
git add packages/sandbox/src/bwrap.ts packages/sandbox/test/bwrap.test.ts
git commit -m "feat(sandbox): Linux exfil-tool carve-out — /dev/null-mask curl/wget/nc/… under bwrap (Phase 29)"
```

---

### Task 2: Linux carve-out branch in `computeDenySet`

**Files:**
- Modify: `packages/sandbox/src/deny-set.ts` (restructure the exec guard at lines 83-85 to add a Linux branch before the darwin path)
- Test: `packages/sandbox/test/deny-set.test.ts` (append)

**Interfaces:**
- Consumes: `SENSITIVE_EXECUTABLES`, `execCarveOutPaths`, `classifyProcessTarget` (already imported in deny-set.ts); local `expandHome`, `isSafeGrantTarget`, `pathCovers`.
- Produces: for `platform: "linux"`, `DenySet` gains `execDenied` (true iff masked literals exist) and `execDeniedPaths` (the masked literals) — **no** `execAllowedPaths`/`writeAllowedPaths` (no floor). Task 3's classifier and Task 4's wiring rely on this.

- [ ] **Step 1: Write the failing tests** (append to `packages/sandbox/test/deny-set.test.ts`; reuse its `HOME`/`fsCap` helpers)

```ts
const procCap = (target: string): Capability => ({ kind: "process", target, evidence: [] });
const L = { homeDir: "/home/test", platform: "linux" as const, nodePrefix: "/usr", projectRoot: "/work/pkg", cwd: "/work/pkg", tmpDir: "/tmp/x" };

describe("computeDenySet — Linux carve-out (Phase 29)", () => {
  test("lists the carve-out literals as execDeniedPaths, sets execDenied, and models NO floor", () => {
    const ds = computeDenySet([], L);
    assert.equal(ds.execDenied, true);
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/curl")), "curl literal denied");
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/wget")), "wget literal denied");
    assert.equal(ds.execAllowedPaths, undefined, "Linux has NO exec floor");
    assert.equal(ds.writeAllowedPaths, undefined, "Linux has NO write floor in the exec model");
  });

  test("a command Grant removes that command's literals; a path Grant removes a covered literal", () => {
    const ds = computeDenySet([procCap("curl"), procCap("/bin/wget")], L);
    assert.ok(!ds.execDeniedPaths!.some((p) => p.endsWith("/curl")), "process:curl lifts curl");
    assert.ok(!ds.execDeniedPaths!.includes("/bin/wget"), "path grant lifts /bin/wget");
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/nc")), "nc stays denied");
  });

  test("the * Grant empties the carve-out and clears execDenied", () => {
    const ds = computeDenySet([procCap("*")], L);
    assert.deepEqual(ds.execDeniedPaths, []);
    assert.equal(ds.execDenied, false);
  });

  test("Linux paths are NOT firmlink-canonicalized (no /private rewrite)", () => {
    const ds = computeDenySet([], L);
    assert.ok(ds.execDeniedPaths!.every((p) => !p.startsWith("/private/")), "no macOS canon on linux");
  });

  test("legacy Linux call without exec opts still returns the base shape unchanged", () => {
    const ds = computeDenySet([], { homeDir: "/home/test", platform: "linux" });
    assert.ok(ds.deniedPaths.length >= 0);
    // exec fields may be present (carve-out needs no nodePrefix), but must be internally consistent:
    if (ds.execDenied) assert.ok(Array.isArray(ds.execDeniedPaths));
  });
});
```

- [ ] **Step 2: Run to verify the new block fails**

Run: `node --import tsx --test packages/sandbox/test/deny-set.test.ts`
Expected: existing tests PASS; the new block FAILS (linux returns `base`, no exec fields).

- [ ] **Step 3: Implement** — replace the single darwin guard line

```ts
  // Exec gating (Phase 28, darwin only) — MUST mirror generateProfile's exec
  // section exactly (the non-drift test enforces this).
  if (opts.platform !== "darwin" || !opts.nodePrefix || !opts.projectRoot) return base;
```

with a Linux branch followed by the (unchanged) darwin guard:

```ts
  // Linux exec (Phase 29): carve-out only — no floor (bwrap can't path-gate exec,
  // ADR-0043). Mirror generateBwrapArgs's /dev/null masks: the masked exfil-tool
  // literals are the exec-deny set; execAllowedPaths/writeAllowedPaths are intentionally
  // absent so classifyViolation only ever confirms on a masked literal (never the macOS
  // floor guess). Paths are NOT firmlink-canonicalized on Linux.
  if (opts.platform === "linux") {
    const lProcTargets = approved.filter((c) => c.kind === "process").map((c) => c.target);
    const lGrantedCmds = new Set(lProcTargets.filter((t) => classifyProcessTarget(t) === "command"));
    const lWildcard = lProcTargets.some((t) => classifyProcessTarget(t) === "wildcard");
    const lPathGrants = lProcTargets
      .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
      .map((p) => expandHome(p, opts.homeDir));
    const lDenied = lWildcard ? [] : SENSITIVE_EXECUTABLES
      .filter((cmd) => !lGrantedCmds.has(cmd))
      .flatMap((cmd) => execCarveOutPaths(cmd))
      .filter((p) => !lPathGrants.some((g) => pathCovers(g, p)));
    return { ...base, execDenied: lDenied.length > 0, execDeniedPaths: lDenied };
  }

  // Exec gating (Phase 28, darwin only) — MUST mirror generateProfile's exec
  // section exactly (the non-drift test enforces this).
  if (!opts.nodePrefix || !opts.projectRoot) return base;
```

(The darwin exec code below this guard is unchanged.)

**Backward-compat note:** after this change, an existing Linux call `computeDenySet(approved, { homeDir, platform: "linux" })` (no exec opts — as `bubblewrap.ts:50` does today, until Task 4 enriches it) now returns `execDenied`/`execDeniedPaths` instead of the bare base shape. This is benign — the carve-out needs no `nodePrefix`/`projectRoot`, the new fields are correct, and `classifyViolation`'s Linux branch only fires on a masked-literal exec (existing network/fs classification is unchanged). If any pre-existing test asserts a Linux `DenySet` has NO exec fields, update it to the new shape (it is not a regression).

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/deny-set.test.ts`
Expected: PASS (all, including the pre-existing darwin non-drift test — untouched).

- [ ] **Step 5: Add the Linux non-drift test** (append) — every literal the bwrap argv masks must appear in the deny set (argv ⊆ deny set; the argv is existence-gated, the deny set is the pure superset)

```ts
import { generateBwrapArgs } from "../src/bwrap.js";  // add at top of file if not present

describe("computeDenySet ↔ generateBwrapArgs Linux non-drift (Phase 29)", () => {
  test("every /dev/null-masked literal in the argv is in execDeniedPaths", () => {
    const approved: Capability[] = [procCap("curl")]; // curl lifted, others masked
    const ds = computeDenySet(approved, L);
    const argv = generateBwrapArgs(approved, {
      homeDir: L.homeDir, cwd: L.cwd, tmpDir: L.tmpDir, nodePrefix: L.nodePrefix,
      projectRoot: L.projectRoot, pathExists: () => true,
    });
    const masks: string[] = [];
    for (let i = 0; i < argv.length - 2; i++) {
      if (argv[i] === "--ro-bind" && argv[i + 1] === "/dev/null") masks.push(argv[i + 2]);
    }
    for (const m of masks) assert.ok(ds.execDeniedPaths!.includes(m), `deny set must include masked ${m}`);
  });
});
```

- [ ] **Step 6: Run + build + commit**

Run: `node --import tsx --test packages/sandbox/test/deny-set.test.ts`
Expected: PASS.

```bash
npx tsc --build --force packages/sandbox
git add packages/sandbox/src/deny-set.ts packages/sandbox/test/deny-set.test.ts
git commit -m "feat(sandbox): DenySet Linux carve-out branch (no floor), mirrored from bwrap masks (Phase 29)"
```

---

### Task 3: Linux exec-denial branch in `classifyViolation`

**Files:**
- Modify: `packages/sandbox/src/violation.ts` (add Linux regexes beside the existing exec ones ~lines 33-38; add a Linux branch after the network branch, before the macOS exec branch at line 99)
- Test: `packages/sandbox/test/violation.test.ts` (append)

**Interfaces:**
- Consumes: the Task 2 `DenySet` Linux shape (`execDenied` true, `execDeniedPaths` set, `execAllowedPaths` absent).
- Produces: a `kind: "process"`, `confidence: "confirmed"` violation for a denied masked-literal exec on Linux; Task 4's effect test asserts on it.

**IMPORTANT — probe-driven regexes (CI-validated in Task 4).** The exact Linux shell exec-denial stderr shape is host-shell-specific: ubuntu's `/bin/sh` is `dash`, which prints an EACCES exec failure roughly as `/bin/sh: <lineno>: <path>: Permission denied` (note the `<lineno>:` between the shell prefix and the path — different from macOS's `/bin/sh: <path>: Operation not permitted`). The regexes below are the **best guess**; Task 4 runs the effect test in CI and, if dash's real shape differs, corrects them there. Keep the two-linear-regex (detect-line + extract-path) split to stay ReDoS-safe, matching the existing `SH_EXEC_*` style.

- [ ] **Step 1: Write the failing tests** (append to `packages/sandbox/test/violation.test.ts`)

```ts
const LINUX_DS = {
  deniedPaths: ["/home/test/.ssh"],
  networkDenied: true,
  execDenied: true,
  execDeniedPaths: ["/usr/bin/curl", "/bin/curl", "/usr/bin/wget"],
  // NO execAllowedPaths, NO writeAllowedPaths → Linux carve-out mode
};
const failL = (stderr: string) => ({ exitCode: 126, stdout: "", stderr });

describe("classifyViolation — Linux carve-out (Phase 29)", () => {
  test("a denied masked-literal exec (dash EACCES shape) is a confirmed process violation", () => {
    const v = classifyViolation(failL("/bin/sh: 1: /usr/bin/curl: Permission denied"), LINUX_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "/usr/bin/curl");
  });

  test("also handles the no-lineno shell shape", () => {
    const v = classifyViolation(failL("/bin/sh: /usr/bin/wget: Permission denied"), LINUX_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.deniedResource, "/usr/bin/wget");
  });

  test("a Permission-denied error on a NON-masked path is not a process violation (no floor to guess)", () => {
    // /usr/bin/make is not in execDeniedPaths → falls through, no process attribution
    const v = classifyViolation(failL("/bin/sh: 1: /usr/bin/make: Permission denied"), LINUX_DS);
    assert.ok(v === null || v.kind !== "process", "must not fabricate a process violation off the floor");
  });

  test("never emits suspected/exec-default-deny on Linux (no floor)", () => {
    const v = classifyViolation(failL("/bin/sh: 1: /tmp/dropped: Permission denied"), LINUX_DS);
    assert.ok(v === null || v.confidence !== "suspected", "Linux never guesses a floor denial");
    assert.notEqual(v?.deniedResource, "exec-default-deny");
  });

  test("exit 0 (swallowed) stays null", () => {
    assert.equal(classifyViolation({ exitCode: 0, stdout: "", stderr: "" }, LINUX_DS), null);
  });
});
```

- [ ] **Step 2: Run to verify the new block fails**

Run: `node --import tsx --test packages/sandbox/test/violation.test.ts`
Expected: existing tests PASS; the new block FAILS (no Linux exec branch).

- [ ] **Step 3: Implement** — add the Linux regexes beside the existing exec regexes (after line 38):

```ts
// Linux exec-denial (Phase 29, CI-validated). ubuntu /bin/sh is dash: a masked-literal
// exec fails EACCES ("Permission denied"), printed roughly as
// "/bin/sh: <lineno>: <path>: Permission denied" (lineno optional across shells). Two
// linear tests (detect + extract), mirroring the SH_EXEC split, to stay ReDoS-safe.
const LINUX_EXEC_PERM = /[Pp]ermission denied/;
const LINUX_EXEC_PATH = /(?:^|[/\s])(?:sh|bash|dash|zsh): (?:\d+: )?(\/[^:\n]+):/;
```

Add the helper (beside `firstShExecLine`):

```ts
/** First stderr line carrying BOTH a shell prefix and "Permission denied" (Linux exec-deny). */
function firstLinuxExecLine(stderr: string): string | null {
  for (const line of stderr.split(/\r?\n/)) {
    if (LINUX_EXEC_PATH.test(line) && LINUX_EXEC_PERM.test(line)) return line.trim();
  }
  return null;
}
```

Insert the Linux branch **after** the network branch (after line 97) and **before** the macOS exec branch (`const execLine = firstShExecLine(...)` at line 108):

```ts
  // Linux carve-out (Phase 29): no exec floor — only masked exfil-tool literals are
  // exec-denied. Distinct from the macOS exec branch below (which needs "Operation not
  // permitted" + a floor). Fires only in Linux carve-out mode (execDenied, denied
  // literals, and NO floor modeled), and only ever confirms on a known masked literal —
  // a Permission-denied on anything else falls through (no floor to guess from).
  const linuxCarveMode = !!denySet.execDenied
    && (denySet.execAllowedPaths?.length ?? 0) === 0
    && (denySet.execDeniedPaths?.length ?? 0) > 0;
  if (linuxCarveMode) {
    const line = firstLinuxExecLine(stderr);
    const target = line ? LINUX_EXEC_PATH.exec(line)?.[1] ?? null : null;
    if (line && target) {
      const carved = denySet.execDeniedPaths!.find((p) => p === target || pathCovers(p, target));
      if (carved) {
        return {
          kind: "process", target, confidence: "confirmed", deniedResource: carved,
          evidence: { exitCode: result.exitCode, stderrExcerpt: excerpt(line) },
        };
      }
    }
    // not a masked-literal exec → fall through (no floor to attribute against).
  }
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/violation.test.ts`
Expected: PASS (all — the pre-existing macOS exec / network / fs / swallowed-denial tests must be untouched, since the Linux branch only fires in Linux carve-out mode).

- [ ] **Step 5: Build + commit**

```bash
npx tsc --build --force packages/sandbox
git add packages/sandbox/src/violation.ts packages/sandbox/test/violation.test.ts
git commit -m "feat(sandbox): classify a denied Linux carve-out exec as a confirmed process violation (Phase 29)"
```

---

### Task 4: Wire `BubblewrapSandbox` + Linux effect tests (CI-validated)

**Files:**
- Modify: `packages/sandbox/src/bubblewrap.ts` (the `generateBwrapArgs` call at lines 20-25 already passes the exec opts; the `computeDenySet` call at line 50 needs the exec opts added)
- Test: `packages/sandbox/test/bubblewrap.test.ts` (append to the existing Linux-gated `describe` block)

**Interfaces:**
- Consumes: Task 2's Linux `computeDenySet`; Task 1's masks; Task 3's classifier.
- Produces: end-to-end Linux carve-out enforcement + violation surfacing.

- [ ] **Step 1: Enrich the deny-set call** — in `bubblewrap.ts`, replace line 50:

```ts
    const denySet = computeDenySet(opts.approved, { homeDir: opts.homeDir, platform: "linux" });
```

with:

```ts
    const denySet = computeDenySet(opts.approved, {
      homeDir: opts.homeDir, platform: "linux",
      nodePrefix: nodeInstallPrefix(process.execPath),
      projectRoot: opts.projectRoot ?? opts.cwd,
      cwd: opts.cwd, tmpDir: tmpdir(),
    });
```

(`nodeInstallPrefix`, `tmpdir` are already imported. `nodePrefix`/`projectRoot` aren't used by the Linux deny-set branch but are passed for a uniform call shape with the darwin site.)

- [ ] **Step 2: Write the Linux effect tests** (append inside the existing `describe("BubblewrapSandbox …", { skip: !linux … }, …)` block in `bubblewrap.test.ts` — match the file's existing skip guard and helpers; benign probes only)

```ts
  test("the curl carve-out is denied without a Grant and lifted by process:curl", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-exec-curl-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const out = join(proj, "curl-out.txt");
    // curl masked → exec fails; script writes nothing useful:
    new BubblewrapSandbox().run(`/usr/bin/curl --version > "${out}" 2>/dev/null || true`,
      { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    const denied = existsSync(out) ? readFileSync(out, "utf8") : "";
    assert.ok(!denied.includes("curl"), "curl must not run without a Grant");

    const approved: Capability[] = [{ kind: "process", target: "curl", evidence: [] }];
    new BubblewrapSandbox().run(`/usr/bin/curl --version > "${out}"`,
      { cwd: proj, approved, homeDir: home, projectRoot: proj });
    assert.ok(readFileSync(out, "utf8").includes("curl"), "an approved process:curl must run");
  });

  test("a denied curl exec surfaces a confirmed process violation", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-exec-viol-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const res = new BubblewrapSandbox().run(`/usr/bin/curl --version`,
      { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    assert.notEqual(res.exitCode, 0);
    assert.equal(res.violation?.kind, "process");
    assert.equal(res.violation?.confidence, "confirmed");
  });

  test("positive control: a node_modules/.bin shim and node still run (carve-out doesn't over-block)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-exec-pos-")));
    const proj = join(home, "proj"); mkdirSync(join(proj, "node_modules", ".bin"), { recursive: true });
    const shim = join(proj, "node_modules", ".bin", "hello");
    writeFileSync(shim, "#!/bin/sh\necho SHIM-OK\n", { mode: 0o755 });
    const res = new BubblewrapSandbox().run(`node -e "console.log('NODE-OK')" && "${shim}"`,
      { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    assert.equal(res.exitCode, 0, res.stderr);
    assert.match(res.stdout, /NODE-OK/);
    assert.match(res.stdout, /SHIM-OK/);
  });
```

- [ ] **Step 3: Build + run the hermetic suite locally (macOS)**

Run: `npx tsc --build --force packages/sandbox && node --import tsx --test packages/sandbox/test/*.test.ts`
Expected: PASS; the new Linux effect tests SKIP on darwin (describe-gated). The generator/deny-set/classifier unit tests (Tasks 1-3) all pass here.

- [ ] **Step 4: Commit, push, and validate on Linux CI**

```bash
git add packages/sandbox/src/bubblewrap.ts packages/sandbox/test/bubblewrap.test.ts
git commit -m "feat(sandbox): wire Linux carve-out deny-set into BubblewrapSandbox + Linux effect tests (Phase 29)"
git push -u origin phase-29-linux-exec-carveout
```

Then watch CI (the effect tests run on ubuntu-latest, Node 22 + 24):

```bash
gh run watch --repo git-agentic/pkg-registry --exit-status || true
gh run view --repo git-agentic/pkg-registry --log-failed | grep -A3 -i "permission denied\|process violation\|SHIM-OK" | head -40
```

- [ ] **Step 5: Reconcile the classifier regex against real dash output (probe-in-CI)**

If the "confirmed process violation" effect test FAILS while the "curl denied" effect test PASSES, containment holds but the Task 3 regex didn't match dash's real EACCES shape. Read the actual `res.stderr` from the CI log (the effect test's assertion failure prints it), then amend `LINUX_EXEC_PATH`/`LINUX_EXEC_PERM` in `packages/sandbox/src/violation.ts` to match the real shape (keep the two-linear-regex split), add a Task-3 unit test with the verbatim real line, and re-push. Do NOT weaken the effect-test assertion. Iterate until CI is green.

```bash
# after fixing:
npx tsc --build --force packages/sandbox
node --import tsx --test packages/sandbox/test/violation.test.ts   # local: new verbatim-line test passes
git commit -am "fix(sandbox): correct Linux exec-deny regex to dash's real EACCES shape (Phase 29, CI-verified)"
git push
```

- [ ] **Step 6: Full suite + demo**

Once CI is green, locally confirm nothing regressed and record the count:

```bash
npm test        # record exact pass/fail/skip for Task 5's CLAUDE.md update
npm run demo    # must still end in the 403 (malicious fixture still blocked)
```

---

### Task 5: ADR-0043 + docs sweep + #8 comment + finish

**Files:**
- Create: `docs/adr/0043-linux-exec-carveout-advisory-floor.md`
- Modify: `ARCHITECTURE.md` (§3.6 enforcement-scope), `sentinel-threat-model.md` (§3.9 + §4 bullet), `README.md` (sandbox section), `CLAUDE.md` (Phase 3 note + new Phase 29 paragraph + test count)

- [ ] **Step 1: Write ADR-0043** (match the house header style — check `docs/adr/0042-*.md`: `**Status:**`/`**Date:**` lines, extends/supersedes as body prose)

```markdown
# ADR-0043: Linux exec — exfil-tool carve-out enforced, exec floor advisory

**Status:** Accepted (Phase 29)
**Date:** 2026-07-10

Follows ADR-0042 (macOS exec deny-by-default); supersedes nothing. Does not close
issue #8 — a cross-platform exec floor is not achieved (Linux floor stays advisory).

## Context

ADR-0042 enforces the `process` capability on macOS via Seatbelt `process-exec*`.
The intended Linux equivalent was a bwrap `noexec` mount of the writable-non-project
floor (pure TypeScript, no native code). A decisive check killed it: **bwrap has no
`noexec` mechanism** — confirmed against the `bwrap(1)` man page (no mount-flags option)
and the open, unimplemented feature request containers/bubblewrap#349. A CAP_SYS_ADMIN
inner-remount was rejected as a security regression (granting a powerful cap into an
untrusted script's context). The only route to a true Linux exec floor is Landlock,
which needs a native syscall piece — a first-party compiled dependency in a pure-TS
supply-chain-security tool — deferred as too large a commitment for pre-1.0.

## Decision

On Linux, ship in pure TypeScript:

1. **Exfil-tool carve-out (enforced).** Mask each `SENSITIVE_EXECUTABLES` literal
   (curl/wget/nc/ncat/socat/scp/sftp) with `--ro-bind /dev/null <literal>` under bwrap
   (execve on `/dev/null` fails EACCES), unless an approved `process:` Grant covers it —
   reusing the sensitive-read mask pattern. A denied carve-out exec surfaces as a
   `confirmed` `process` violation.
2. **Exec floor advisory (documented, not enforced).** bwrap cannot deny exec of a
   binary dropped into a writable location; that gap stays open on Linux by decision.
   The dropped binary is still filesystem+network confined (can't read credentials or
   exfil without an approved `network` cap), so the residual is arbitrary local
   computation within existing confinement — the state ADR-0042 documents for the
   pre-enforcement posture.

`native` stays advisory on both platforms. The macOS floor + carve-out (ADR-0042) is
unchanged. `computeDenySet`'s Linux branch models no floor, so `classifyViolation` only
ever confirms a Linux `process` violation on a masked literal — never a floor guess.

## Consequences

- Linux gains real defense-in-depth against exfil-tool exec (valuable most when a
  `network` cap is approved; with none, `--unshare-net` already blocks exfil).
- The dropped-binary-exec gap remains on Linux — documented, fs+net confined.
- Platform asymmetry: macOS enforces the exec floor + carve-out; Linux enforces the
  carve-out only. Same "each platform enforces what it can" precedent as the
  ADR-0023/0038 telemetry and /dev asymmetries.
- #8 stays open. Landlock (a native Linux floor) is the only route to close it; deferred.

## Rejected / deferred alternatives

- bwrap `noexec` floor — impossible (no bwrap option; #349 open).
- CAP_SYS_ADMIN inner-remount — security regression, rejected.
- Native Landlock helper — deferred; compiled dependency + arch/kernel matrix +
  supply-chain-binary tension; its own design pass. Landlock is also allow-list-only and
  cannot express the carve-out, which would still rely on this phase's masking.
- seccomp execve filter — can't inspect execve's path argument.
```

- [ ] **Step 2: Update ARCHITECTURE.md §3.6** — change the enforcement-scope paragraph so it reads: `process` exec **floor** enforced on macOS (Seatbelt), **advisory on Linux** (bwrap cannot path-gate exec — no `noexec`, ADR-0043); the exfil-tool **carve-out** enforced on **both** (Seatbelt literals / bwrap `/dev/null` masks); `native` advisory both; Landlock the only route to a Linux floor, deferred (#8 open). Keep the existing macOS description intact; add the Linux clause. Do not overclaim Linux floor enforcement.

- [ ] **Step 3: Update the threat model** — in `sentinel-threat-model.md` §3.9 and the §4 accepted-limitations bullet, state: macOS enforces the exec floor + carve-out; Linux enforces the carve-out (exfil tools) but the exec floor is advisory (a dropped binary can still exec, but stays fs+net confined); tracked in #8 (Landlock deferred). Adjust the existing "process enforced on macOS only" wording from Phase 28 to add the Linux carve-out nuance.

- [ ] **Step 4: Update README sandbox section** — extend the Phase 28 exec bullet (or add a sibling) noting: on Linux, the exfil tools (`curl`/`wget`/`nc`/…) are exec-denied via `/dev/null` masking (lifted by `process:` grants), but the exec floor is advisory (bwrap can't path-gate exec) — a dropped binary can still exec, still fs+net confined. Keep it one or two sentences, matching the bullet style.

- [ ] **Step 5: Update CLAUDE.md** — (a) adjust the Phase 3 enforcement note so `process` reads "enforced on macOS (floor+carve-out); Linux carve-out enforced, floor advisory (ADR-0043)"; (b) append a Phase 29 paragraph summarizing the carve-out mechanism, the no-floor-on-Linux decision, and the bwrap-noexec impossibility; (c) update the `npm test` count line to the exact total recorded in Task 4 Step 6, and append the Phase 29 tests to the inventory comment (bwrap carve-out generator, deny-set Linux branch + non-drift, classifier Linux branch — hermetic/platform-neutral; the three bwrap Linux effect tests — CI-only).

- [ ] **Step 6: Build + full suite + commit**

```bash
npm run build && npm test
git add docs/adr/0043-linux-exec-carveout-advisory-floor.md ARCHITECTURE.md sentinel-threat-model.md README.md CLAUDE.md
git commit -m "docs: ADR-0043 Linux exec carve-out + advisory floor + architecture/threat-model/README/CLAUDE sweep (Phase 29)"
```

- [ ] **Step 7: Comment on #8 (keep it OPEN) and finish the branch**

```bash
gh issue comment 8 --repo git-agentic/pkg-registry --body "Phase 29 (ADR-0043) adds Linux exec hardening in pure TypeScript: the exfil tools (curl/wget/nc/…) are exec-denied via \`/dev/null\` masking under bwrap (lifted by \`process:\` grants), and a denied carve-out exec surfaces as a confirmed process violation. But the Linux exec FLOOR stays advisory: bwrap has no \`noexec\` mechanism (confirmed vs the bwrap(1) man page + open request containers/bubblewrap#349), so a binary dropped into a writable location can still exec (still filesystem+network confined). A true Linux exec floor needs Landlock (a native syscall piece), deferred as too large a dependency for pre-1.0 — tracked in #18. **Keeping #8 open** until a cross-platform exec floor exists."
```

Then invoke `superpowers:finishing-a-development-branch` for `phase-29-linux-exec-carveout` (verify `npm run build && npm test` green and `git log --oneline main..HEAD` shows the Phase 29 commits first).

---

## Verification checklist (Definition of Done)

- [ ] `npm run build` clean, `npm test` green; CLAUDE.md count updated
- [ ] Linux CI (Node 22 + 24) green — the three bwrap effect tests pass on ubuntu; the classifier regex matches dash's real EACCES shape
- [ ] Malicious fixtures still blocked (`npm run demo` ends in 403)
- [ ] macOS/Seatbelt path and pre-existing bwrap logic byte-unchanged (only additive)
- [ ] ADR-0043 + ARCHITECTURE + threat model + README + CLAUDE agree: macOS floor+carve-out, Linux carve-out + advisory floor, no Linux-floor overclaim
- [ ] #8 commented and still OPEN; no doc claims it closed
