# Phase 28 — macOS exec deny-by-default (+ #4 README Status fix) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce the `process` capability kind on macOS via a Seatbelt exec deny-by-default layer (issue #8, Phase 28), and fix the README Status phase-count drift (issue #4) as a standalone rider.

**Architecture:** Mirrors Phase 25's write-deny layering exactly — blanket `(deny process-exec*)`, re-allow a fixed exec floor + approved `process:` path-Grants, then re-deny a curated `SENSITIVE_EXECUTABLES` carve-out unless a command/wildcard Grant lifts it (SBPL last-match-wins). `computeDenySet`/`classifyViolation` extend so a denied exec surfaces as a runtime violation. Linux is untouched (Phase 29 via Landlock, new issue); `native` is formally advisory-only (ADR-0042).

**Tech Stack:** TypeScript ESM (NodeNext, `.js` import specifiers), `node:test` + `tsx`, macOS `sandbox-exec` (SBPL).

**Spec:** `docs/superpowers/specs/2026-07-10-phase-28-exec-deny-design.md`

## Global Constraints

- ESM only; internal imports use `.js` specifiers even from `.ts` sources.
- Generators (`generateProfile`, `execAllowFloor`, `computeDenySet`, `classifyViolation`) are **pure and deterministic**: no `Date.now()`, no fs calls, no PATH resolution — same inputs ⇒ same output (invariant #1 discipline).
- Scoring, the approval/manifest model, `bwrap.ts`, and the proxy are **untouched**.
- Synthetic malware fixtures are never executed; effect tests use benign probes only.
- Build artifacts may not be `rm`-able (EPERM on this mount) — use `npx tsc --build --force packages/sandbox` instead of deleting `dist/`.
- Run a single test file with: `node --import tsx --test packages/sandbox/test/<file>.test.ts`. Full suite: `npm test` (expect the CLAUDE.md-documented count plus this phase's new tests).
- Commit messages follow repo style (`feat(sandbox): …`, `docs: …`, `test(sandbox): …`) and end with the Claude-Session trailer used in recent commits.
- The darwin effect tests must be gated exactly like the existing ones: `describe("...", { skip: darwin ? false : "requires macOS sandbox-exec" }, ...)`.

---

### Task 1: Issue #4 — README Status / Phase-log consistency fix (standalone branch)

**Files:**
- Modify: `README.md:29-42` (Status section) and `README.md:705-707` (Phase log opening line)

**Interfaces:** none (docs only). Produces: a merged `fix/readme-status` branch; issue #4 closed.

- [ ] **Step 1: Branch off main**

```bash
git checkout main && git checkout -b fix/readme-status
```

- [ ] **Step 2: Rewrite the Status section**

Replace the Status paragraph (starts `**Pre-1.0; built through Phase 25 (deny-by-default install sandbox).**`) with — note the only changes are dropping the phase-count claim and pointing at the ADR log; no capability claims added or removed:

```markdown
**Pre-1.0.** The auditing proxy, policy gate, deny-by-default install sandbox
(macOS Seatbelt / Linux bubblewrap), CLI, MCP server, and GitHub Action work
end-to-end and are covered by the full test suite (Linux CI on Node 22 and 24;
macOS Seatbelt enforcement is exercised on maintainers' machines) — but this
has not yet been hardened by production use, and APIs may change without
notice. The complete phase-by-phase build log lives in
[docs/adr/](./docs/adr/) (one ADR per phase). **No npm packages are
published yet**: build from source (Quickstart below). Threat model:
[sentinel-threat-model.md](./sentinel-threat-model.md) · Homepage:
[git-agentic.com/sentinel](https://git-agentic.com/sentinel)
```

- [ ] **Step 3: Fix the Phase log opening line**

In the `## Phase log` section, replace the sentence `Phases 1–25 are built; see [CLAUDE.md](./CLAUDE.md) for the complete log.` with:

```markdown
The complete phase-by-phase log lives in [CLAUDE.md](./CLAUDE.md) and [docs/adr/](./docs/adr/); highlights:
```

(The per-phase narrative below it is a descriptive history, not a completeness claim — leave it.)

- [ ] **Step 4: Verify no other phase-count claims remain**

Run: `grep -n "built through\|are built\|Phases 1–" README.md`
Expected: no matches (the narrative's "Phases 3–6 add…" descriptions are fine and will not match these patterns).

- [ ] **Step 5: Commit, merge --no-ff, close #4**

```bash
git add README.md
git commit -m "docs: README Status drops phase numbering — capability list + ADR-log pointer (closes #4)"
git checkout main && git merge --no-ff fix/readme-status -m "Merge fix/readme-status: README Status consistency (#4)"
gh issue close 4 --repo git-agentic/pkg-registry --comment "Fixed: Status and the Phase log no longer make a phase-count claim; both point at docs/adr/ (one ADR per phase) as the authoritative build log. Capability claims unchanged."
```

---

### Task 2: Probe — verify SBPL `process-exec*` semantics on this darwin host

**Files:**
- Create: `<scratchpad>/probe-exec/probe.sb` and `<scratchpad>/probe-exec/run.sh` (throwaway — NOT in the repo)

**Interfaces:** Produces: confirmed SBPL syntax for the exec layer, and the **exact stderr formats** for a shell-denied exec and a node-denied spawn — Task 7's regexes must be written against what this probe actually prints. If any probe expectation fails, STOP and revisit the design with the human before writing repo code (probe-before-spec).

- [ ] **Step 1: Write the probe profile and script**

```bash
SCRATCH="<your session scratchpad directory>"   # from the system prompt; never inside the repo
mkdir -p "$SCRATCH/probe-exec" && cd "$SCRATCH/probe-exec"
PAYLOAD_DIR=$(mktemp -d)   # under /var/folders (NOT under /bin, /usr/bin, node prefix)
cat > probe.sb <<EOF
(version 1)
(allow default)
(deny process-exec*)
(allow process-exec* (subpath "/bin") (subpath "/usr/bin") (subpath "/usr/sbin") (subpath "/usr/local") (subpath "/opt/homebrew") (subpath "/Library/Developer") (subpath "$(dirname $(dirname $(which node)))"))
(deny process-exec* (literal "/usr/bin/curl"))
EOF
printf '#!/bin/sh\necho PWNED\n' > "$PAYLOAD_DIR/payload"; chmod +x "$PAYLOAD_DIR/payload"
```

- [ ] **Step 2: Probe the four behaviors, capturing stderr**

```bash
# (a) positive control — floor exec works
sandbox-exec -f probe.sb /bin/sh -c '/bin/echo FLOOR-OK'
# expected stdout: FLOOR-OK, exit 0

# (b) exec from a non-floor dir is denied — CAPTURE the exact stderr line
sandbox-exec -f probe.sb /bin/sh -c "$PAYLOAD_DIR/payload"; echo "exit=$?"
# expected: no PWNED, non-zero exit, stderr like "sh: <path>: Operation not permitted"

# (c) the carve-out literal is denied even inside the floor
sandbox-exec -f probe.sb /bin/sh -c '/usr/bin/curl --version'; echo "exit=$?"
# expected: denied, same stderr shape

# (d) node's spawn error shape — CAPTURE for the SPAWN regex
sandbox-exec -f probe.sb node -e "try{require('child_process').execFileSync('$PAYLOAD_DIR/payload')}catch(e){console.error(e.message)}"
# expected: a message containing EPERM (record the exact format)
```

- [ ] **Step 3: Record results**

Write the four observed stderr lines into `<scratchpad>/probe-exec/RESULTS.txt`. Task 7 copies its regexes from these. If (a) fails or (b)/(c) are NOT denied, stop: the SBPL syntax assumption is wrong — escalate to the human before continuing.

---

### Task 3: `execAllowFloor` (new `packages/sandbox/src/exec-floor.ts`)

**Files:**
- Create: `packages/sandbox/src/exec-floor.ts`
- Test: `packages/sandbox/test/exec-floor.test.ts`

**Interfaces:**
- Produces: `execAllowFloor(opts: { nodePrefix: string; projectRoot: string }): string[]` — consumed by Task 5 (`profile.ts`) and Task 6 (`deny-set.ts`).

- [ ] **Step 1: Branch for Phase 28**

```bash
git checkout main && git checkout -b phase-28-exec-deny
```

- [ ] **Step 2: Write the failing test**

```ts
// packages/sandbox/test/exec-floor.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { execAllowFloor } from "../src/exec-floor.js";

describe("execAllowFloor", () => {
  const floor = execAllowFloor({ nodePrefix: "/Users/x/.nvm/versions/node/v24.1.0", projectRoot: "/work/pkg" });

  test("contains the system, toolchain, and Homebrew prefixes", () => {
    for (const p of ["/bin", "/usr/bin", "/usr/sbin", "/Library/Developer", "/Applications/Xcode.app", "/opt/homebrew", "/usr/local"]) {
      assert.ok(floor.includes(p), `floor must include ${p}`);
    }
  });

  test("contains the node prefix and the project root", () => {
    assert.ok(floor.includes("/Users/x/.nvm/versions/node/v24.1.0"));
    assert.ok(floor.includes("/work/pkg"));
  });

  test("does NOT contain the writable staging areas (tmp, $HOME, /dev)", () => {
    for (const p of ["/tmp", "/private/tmp", "/dev"]) {
      assert.ok(!floor.includes(p), `floor must not include ${p}`);
    }
  });

  test("deterministic for the same inputs", () => {
    assert.deepEqual(floor, execAllowFloor({ nodePrefix: "/Users/x/.nvm/versions/node/v24.1.0", projectRoot: "/work/pkg" }));
  });
});
```

- [ ] **Step 3: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/exec-floor.test.ts`
Expected: FAIL — cannot find module `../src/exec-floor.js`.

- [ ] **Step 4: Implement**

```ts
// packages/sandbox/src/exec-floor.ts
/**
 * The fixed set of subpaths where process-exec is allowed WITHOUT a `process`
 * Grant under exec-deny-by-default (Phase 28, ADR-0042). Pure — the caller
 * canonicalizes. Deliberately NOT operator-configurable (same stance as the
 * Phase 25 write floor): widening it silently reopens the dropped-binary class.
 *
 * `projectRoot` is included by decision — `node_modules/.bin` shims and local
 * build scripts must run without approvals. The residual (a package can write
 * a binary into its own tree and exec it) is recorded in ADR-0042; what this
 * floor kills is exec from ANY writable-but-not-project location (/tmp, caches,
 * ~/Downloads, …).
 */
export function execAllowFloor(opts: { nodePrefix: string; projectRoot: string }): string[] {
  return [
    "/bin",
    "/usr/bin",
    "/usr/sbin",
    opts.nodePrefix,          // the node runtime itself (nvm/fnm/volta under $HOME included)
    opts.projectRoot,         // node_modules/.bin shims, local scripts
    "/Library/Developer",     // CommandLineTools (node-gyp → make/cc)
    "/Applications/Xcode.app",
    "/opt/homebrew",          // Homebrew (arm64)
    "/usr/local",             // Homebrew (Intel), user-installed tools
  ];
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/exec-floor.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add packages/sandbox/src/exec-floor.ts packages/sandbox/test/exec-floor.test.ts
git commit -m "feat(sandbox): fixed exec-allow floor for exec deny-by-default (Phase 28)"
```

---

### Task 4: `SENSITIVE_EXECUTABLES` carve-out table (new `packages/sandbox/src/sensitive-executables.ts`)

**Files:**
- Create: `packages/sandbox/src/sensitive-executables.ts`
- Test: `packages/sandbox/test/sensitive-executables.test.ts`

**Interfaces:**
- Produces (consumed by Tasks 5–7):
  - `SENSITIVE_EXECUTABLES: readonly string[]` — command names
  - `execCarveOutPaths(cmd: string): string[]` — fixed candidate literals
  - `classifyProcessTarget(target: string): "command" | "path" | "wildcard"`

- [ ] **Step 1: Write the failing test**

```ts
// packages/sandbox/test/sensitive-executables.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { SENSITIVE_EXECUTABLES, execCarveOutPaths, classifyProcessTarget } from "../src/sensitive-executables.js";

describe("SENSITIVE_EXECUTABLES", () => {
  test("covers the exfil-capable set from the spec", () => {
    for (const cmd of ["curl", "wget", "nc", "ncat", "socat", "osascript", "scp", "sftp"]) {
      assert.ok(SENSITIVE_EXECUTABLES.includes(cmd), `must include ${cmd}`);
    }
  });

  test("execCarveOutPaths expands one command across the floor's bin dirs", () => {
    const paths = execCarveOutPaths("curl");
    assert.deepEqual(paths, ["/bin/curl", "/usr/bin/curl", "/opt/homebrew/bin/curl", "/usr/local/bin/curl"]);
  });
});

describe("classifyProcessTarget", () => {
  test("a bare word is a command name", () => {
    assert.equal(classifyProcessTarget("curl"), "command");
    assert.equal(classifyProcessTarget("node-gyp"), "command");
  });
  test("a target containing / or starting with ~ is a path", () => {
    assert.equal(classifyProcessTarget("/opt/tools/foo"), "path");
    assert.equal(classifyProcessTarget("~/bin/tool"), "path");
    assert.equal(classifyProcessTarget("tools/foo"), "path");
  });
  test("* is the wildcard", () => {
    assert.equal(classifyProcessTarget("*"), "wildcard");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/sensitive-executables.test.ts`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement**

```ts
// packages/sandbox/src/sensitive-executables.ts
/**
 * Exfil-capable commands re-denied AFTER the exec floor allow (Phase 28,
 * ADR-0042) unless a `process` Grant lifts them — the exec analog of
 * SENSITIVE_PATHS' carve-out-after-floor. Static and fixed: candidates are
 * enumerated across the floor's bin dirs with NO PATH resolution, so the
 * profile generator stays pure and deterministic.
 */
export const SENSITIVE_EXECUTABLES: readonly string[] = [
  "curl", "wget",             // arbitrary-egress download/upload
  "nc", "ncat", "socat",      // raw sockets / reverse shells
  "osascript",                // AppleScript automation (keychain prompts, UI scripting)
  "scp", "sftp",              // file exfil over ssh
];

/** Bin dirs (all inside the exec floor) where a sensitive executable may reside. */
const EXEC_BIN_DIRS = ["/bin", "/usr/bin", "/opt/homebrew/bin", "/usr/local/bin"];

/** Fixed candidate literals for one command across the floor's bin dirs. Pure. */
export function execCarveOutPaths(cmd: string): string[] {
  return EXEC_BIN_DIRS.map((d) => `${d}/${cmd}`);
}

/**
 * A `process` Grant target's shape (spec §Grant semantics): a target containing
 * `/` (or starting with `~`) is a PATH Grant (appended to the exec allow); a
 * bare word is a COMMAND Grant (lifts that command's carve-out literals only);
 * `*` (the detector's target for a bare child_process import) lifts the entire
 * carve-out but opens no non-floor paths.
 */
export function classifyProcessTarget(target: string): "command" | "path" | "wildcard" {
  if (target === "*") return "wildcard";
  if (target.startsWith("~") || target.includes("/")) return "path";
  return "command";
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/sensitive-executables.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/sensitive-executables.ts packages/sandbox/test/sensitive-executables.test.ts
git commit -m "feat(sandbox): SENSITIVE_EXECUTABLES carve-out table + process-grant target shapes (Phase 28)"
```

---

### Task 5: Exec section in `generateProfile` (`packages/sandbox/src/profile.ts`)

**Files:**
- Modify: `packages/sandbox/src/profile.ts` (imports at top; insert the exec section between the write carve-out loop ending at line 78 and the network deny at line 80)
- Test: `packages/sandbox/test/profile.test.ts` (append a new `describe` block)

**Interfaces:**
- Consumes: `execAllowFloor` (Task 3), `SENSITIVE_EXECUTABLES`/`execCarveOutPaths`/`classifyProcessTarget` (Task 4), existing `canon`, `isSafeGrantTarget`, `pathCovers`.
- Produces: the profile string gains three exec lines; Task 6's non-drift test and Task 8's effect tests rely on them.

- [ ] **Step 1: Write the failing tests** (append to `packages/sandbox/test/profile.test.ts`; reuse the file's existing `withOpts` helper — note its floor-relevant values: `nodePrefix: "/usr/local"`, `projectRoot: "/work/pkg"`)

```ts
const proc = (target: string): Capability => ({ kind: "process", target, evidence: [] });

describe("generateProfile — exec deny-by-default (Phase 28)", () => {
  test("blanket exec deny, then floor re-allow (last-match-wins order)", () => {
    const p = generateProfile([], withOpts({ homeDir: HOME }));
    assert.match(p, /\(deny process-exec\*\)/);
    const denyIdx = p.indexOf("(deny process-exec*)");
    const allowIdx = p.indexOf("(allow process-exec*");
    assert.ok(denyIdx >= 0 && allowIdx > denyIdx, "floor allow must FOLLOW the blanket deny");
    assert.match(p, /\(allow process-exec\* [^\n]*\(subpath "\/bin"\)/);
    assert.match(p, /\(subpath "\/work\/pkg"\)/);           // projectRoot
    assert.match(p, /\(subpath "\/Library\/Developer"\)/);
  });

  test("carve-out literals are re-denied AFTER the floor allow", () => {
    const p = generateProfile([], withOpts({ homeDir: HOME }));
    assert.match(p, /\(deny process-exec\* [^\n]*\(literal "\/usr\/bin\/curl"\)/);
    const allowIdx = p.indexOf("(allow process-exec*");
    const carveIdx = p.indexOf('(literal "/usr/bin/curl")');
    assert.ok(carveIdx > allowIdx, "carve-out must FOLLOW the floor allow");
  });

  test("a command Grant lifts exactly that command's carve-out", () => {
    const p = generateProfile([proc("curl")], withOpts({ homeDir: HOME }));
    assert.doesNotMatch(p, /literal "\/usr\/bin\/curl"/);
    assert.match(p, /literal "\/usr\/bin\/wget"/);          // siblings stay denied
  });

  test("a path Grant is appended to the exec allow (with ~ expansion)", () => {
    const p = generateProfile([proc("~/tools/bin")], withOpts({ homeDir: HOME }));
    assert.match(p, /\(allow process-exec\* [^\n]*\(subpath "\/Users\/test\/tools\/bin"\)/);
  });

  test("a path Grant covering a carve-out literal lifts it", () => {
    const p = generateProfile([proc("/usr/bin/curl")], withOpts({ homeDir: HOME }));
    assert.doesNotMatch(p, /literal "\/usr\/bin\/curl"/);
    assert.match(p, /literal "\/opt\/homebrew\/bin\/curl"/); // other candidates stay denied
  });

  test("the * Grant lifts the whole carve-out but opens no paths", () => {
    const p = generateProfile([proc("*")], withOpts({ homeDir: HOME }));
    assert.doesNotMatch(p, /\(deny process-exec\* \(literal/);
    assert.match(p, /\(deny process-exec\*\)/);              // blanket deny still present
    // no allow entries beyond the floor:
    const allowLine = p.split("\n").find((l) => l.startsWith("(allow process-exec*"))!;
    assert.doesNotMatch(allowLine, /Users\/test/);
  });

  test("an unsafe path Grant is dropped fail-closed", () => {
    const p = generateProfile([proc("/"), proc("a/../b")], withOpts({ homeDir: HOME }));
    const allowLine = p.split("\n").find((l) => l.startsWith("(allow process-exec*"))!;
    assert.doesNotMatch(allowLine, /subpath "\/"\)/);
    assert.doesNotMatch(allowLine, /a\/\.\.\/b/);
  });

  test("process Grants do not disturb the write or read sections", () => {
    const a = generateProfile([], withOpts({ homeDir: HOME }));
    const b = generateProfile([proc("curl")], withOpts({ homeDir: HOME }));
    const writeAndRead = (s: string) => s.split("\n").filter((l) => l.includes("file-write") || l.includes("file-read")).join("\n");
    assert.equal(writeAndRead(a), writeAndRead(b));
  });
});
```

- [ ] **Step 2: Run to verify the new block fails**

Run: `node --import tsx --test packages/sandbox/test/profile.test.ts`
Expected: existing tests PASS; the 8 new tests FAIL (no `process-exec` lines emitted).

- [ ] **Step 3: Implement** — add imports and insert the exec section in `generateProfile` after the write carve-out loop (currently ending line 78) and before `if (!hasNetwork) …` (line 80):

```ts
// add to imports at top of profile.ts:
import { execAllowFloor } from "./exec-floor.js";
import { SENSITIVE_EXECUTABLES, execCarveOutPaths, classifyProcessTarget } from "./sensitive-executables.js";
```

```ts
  // Exec: deny by default (Phase 28, ADR-0042) — blanket deny, re-allow the fixed
  // exec floor + approved process PATH-Grants, then re-deny the sensitive-executable
  // carve-out (SBPL last-match-wins) unless a command/wildcard/covering-path Grant
  // lifts it. process-fork stays allowed: only exec is gated. The initial
  // sandbox-exec → /bin/sh exec is itself covered by /bin in the floor.
  const procTargets = approved.filter((c) => c.kind === "process").map((c) => c.target);
  const grantedCmds = new Set(procTargets.filter((t) => classifyProcessTarget(t) === "command"));
  const execWildcard = procTargets.some((t) => classifyProcessTarget(t) === "wildcard");
  const execPathGrants = procTargets
    .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
    .map(canon);
  lines.push("(deny process-exec*)");
  const execFloor = execAllowFloor({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot }).map(canon);
  lines.push(`(allow process-exec* ${[...execFloor, ...execPathGrants].map((p) => `(subpath "${p}")`).join(" ")})`);
  const carveItems = execWildcard ? [] : SENSITIVE_EXECUTABLES
    .filter((cmd) => !grantedCmds.has(cmd))
    .flatMap((cmd) => execCarveOutPaths(cmd))
    .map(canon)
    .filter((p) => !execPathGrants.some((g) => pathCovers(g, p)));
  if (carveItems.length > 0) {
    lines.push(`(deny process-exec* ${carveItems.map((p) => `(literal "${p}")`).join(" ")})`);
  }
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/profile.test.ts`
Expected: PASS (all, including the pre-existing determinism and write/read tests).

- [ ] **Step 5: Run the whole sandbox suite for regressions**

Run: `node --import tsx --test packages/sandbox/test/*.test.ts`
Expected: PASS except possibly `deny-set.test.ts`'s non-drift test — it must still pass at this point since `computeDenySet` is unchanged; if anything else fails, fix before committing.

- [ ] **Step 6: Commit**

```bash
git add packages/sandbox/src/profile.ts packages/sandbox/test/profile.test.ts
git commit -m "feat(sandbox): Seatbelt exec deny-by-default — floor + process Grants + carve-out (Phase 28)"
```

---

### Task 6: Extend `DenySet` / `computeDenySet` (`packages/sandbox/src/deny-set.ts`)

**Files:**
- Modify: `packages/sandbox/src/deny-set.ts` (interface at lines 5-10; `computeDenySet` at lines 56-71)
- Test: `packages/sandbox/test/deny-set.test.ts` (append)

**Interfaces:**
- Consumes: Task 3/4 exports, `writeAllowFloor` (existing).
- Produces (consumed by Task 7's classifier and Task 8's wiring):

```ts
export interface DenySet {
  deniedPaths: string[];
  networkDenied: boolean;
  execDenied?: boolean;          // true when the profile denies exec by default (darwin + exec opts present)
  execAllowedPaths?: string[];   // floor + safe process path-Grants, expanded + canonicalized
  execDeniedPaths?: string[];    // uncovered carve-out literals, canonicalized
  writeAllowedPaths?: string[];  // the write floor, expanded + canonicalized (disambiguates exec vs write denials)
}
// computeDenySet(approved, { homeDir, platform, nodePrefix?, projectRoot?, cwd?, tmpDir? })
```

New opts are **optional**: existing callers (bubblewrap.ts, tests) compile unchanged and get the old shape (`execDenied` absent ⇒ classifier skips the exec branch).

- [ ] **Step 1: Write the failing tests** (append to `packages/sandbox/test/deny-set.test.ts`)

```ts
const procCap = (target: string): Capability => ({ kind: "process", target, evidence: [] });
const EXEC_OPTS = { homeDir: HOME, platform: "darwin" as const, nodePrefix: "/usr/local", projectRoot: "/work/pkg", cwd: "/work/pkg", tmpDir: "/private/tmp/tmpdir-x" };

describe("computeDenySet — exec (Phase 28)", () => {
  test("darwin with exec opts: execDenied, floor in execAllowedPaths, carve-out in execDeniedPaths", () => {
    const ds = computeDenySet([], EXEC_OPTS);
    assert.equal(ds.execDenied, true);
    assert.ok(ds.execAllowedPaths!.includes("/bin"));
    assert.ok(ds.execAllowedPaths!.includes("/work/pkg"));
    assert.ok(ds.execDeniedPaths!.includes("/usr/bin/curl"));
    assert.ok(ds.writeAllowedPaths!.includes("/work/pkg"));
    assert.ok(ds.writeAllowedPaths!.some((p) => p.startsWith("/private/tmp")));
  });

  test("without exec opts (legacy callers / linux): exec fields absent", () => {
    const ds = computeDenySet([], { homeDir: HOME, platform: "linux" });
    assert.equal(ds.execDenied, undefined);
    assert.equal(ds.execDeniedPaths, undefined);
  });

  test("a command Grant removes its carve-out entries; a path Grant lands in execAllowedPaths", () => {
    const ds = computeDenySet([procCap("curl"), procCap("~/tools")], EXEC_OPTS);
    assert.ok(!ds.execDeniedPaths!.some((p) => p.endsWith("/curl")));
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/wget")));
    assert.ok(ds.execAllowedPaths!.includes("/Users/test/tools"));
  });

  test("non-drift: every execDeniedPath and execAllowedPath appears in the generated profile", () => {
    const approved: Capability[] = [procCap("curl"), procCap("~/tools")];
    const ds = computeDenySet(approved, EXEC_OPTS);
    const profile = generateProfile(approved, { homeDir: HOME, cwd: "/work/pkg", tmpDir: "/private/tmp/tmpdir-x", nodePrefix: "/usr/local", projectRoot: "/work/pkg" });
    for (const p of ds.execDeniedPaths!) assert.ok(profile.includes(`(literal "${p}")`), `profile must carve out ${p}`);
    for (const p of ds.execAllowedPaths!) assert.ok(profile.includes(`(subpath "${p}")`), `profile must exec-allow ${p}`);
  });
});
```

- [ ] **Step 2: Run to verify the new block fails**

Run: `node --import tsx --test packages/sandbox/test/deny-set.test.ts`
Expected: existing tests PASS; new block FAILS (`execDenied` undefined everywhere).

- [ ] **Step 3: Implement** — in `deny-set.ts`, extend the interface as shown in **Interfaces** above (with those exact doc comments), add imports, and extend `computeDenySet`:

```ts
// add to imports at top of deny-set.ts:
import { execAllowFloor } from "./exec-floor.js";
import { SENSITIVE_EXECUTABLES, execCarveOutPaths, classifyProcessTarget } from "./sensitive-executables.js";
import { writeAllowFloor } from "./write-floor.js";
```

(`canonicalizeMacPath`, `expandHome`, and `isSafeGrantTarget` are already local to this file — no import.)

```ts
export function computeDenySet(
  approved: Capability[],
  opts: { homeDir: string; platform: "darwin" | "linux"; nodePrefix?: string; projectRoot?: string; cwd?: string; tmpDir?: string },
): DenySet {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const networkDenied = !approved.some((c) => c.kind === "network");
  const deniedPaths: string[] = [];
  for (const sp of sensitivePathsFor(opts.platform)) {
    for (const dp of sp.denyPaths) {
      if (approvedFs.some((t) => pathCovers(t, dp))) continue;
      const expanded = expandHome(dp, opts.homeDir);
      deniedPaths.push(opts.platform === "darwin" ? canonicalizeMacPath(expanded) : expanded);
    }
  }
  const base: DenySet = { deniedPaths, networkDenied };

  // Exec gating (Phase 28, darwin only) — MUST mirror generateProfile's exec
  // section exactly (the non-drift test enforces this).
  if (opts.platform !== "darwin" || !opts.nodePrefix || !opts.projectRoot) return base;
  const canon = (p: string) => canonicalizeMacPath(expandHome(p, opts.homeDir));
  const procTargets = approved.filter((c) => c.kind === "process").map((c) => c.target);
  const grantedCmds = new Set(procTargets.filter((t) => classifyProcessTarget(t) === "command"));
  const execWildcard = procTargets.some((t) => classifyProcessTarget(t) === "wildcard");
  const execPathGrants = procTargets
    .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
    .map(canon);
  const execAllowedPaths = [
    ...execAllowFloor({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot }).map(canon),
    ...execPathGrants,
  ];
  const execDeniedPaths = execWildcard ? [] : SENSITIVE_EXECUTABLES
    .filter((cmd) => !grantedCmds.has(cmd))
    .flatMap((cmd) => execCarveOutPaths(cmd))
    .map(canon)
    .filter((p) => !execPathGrants.some((g) => pathCovers(g, p)));
  const writeAllowedPaths = opts.cwd && opts.tmpDir
    ? writeAllowFloor({ cwd: opts.cwd, tmpDir: opts.tmpDir }).map(canon)
    : [];
  return { ...base, execDenied: true, execAllowedPaths, execDeniedPaths, writeAllowedPaths };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/deny-set.test.ts`
Expected: PASS (all, including the pre-existing non-drift test).

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/deny-set.ts packages/sandbox/test/deny-set.test.ts
git commit -m "feat(sandbox): DenySet carries the exec allow/deny sets, mirrored from the profile (Phase 28)"
```

---

### Task 7: Exec classification in `classifyViolation` (`packages/sandbox/src/violation.ts`)

**Files:**
- Modify: `packages/sandbox/src/violation.ts` (new regexes beside lines 10-14; new branch between the network branch ending line 57 and the fs branch starting line 59)
- Test: `packages/sandbox/test/violation.test.ts` (append)

**Interfaces:**
- Consumes: the Task 6 `DenySet` fields; `SandboxViolation.kind` already includes `"process"` (`packages/sandbox/src/types.ts:5` — no type change needed).
- Produces: `classifyViolation` returns `kind: "process"` violations; Task 8's effect test asserts on them.

**IMPORTANT:** the two regexes below assume the stderr shapes `sh: <path>: Operation not permitted` and a node message containing `spawn <path> EPERM`. Check them against Task 2's `RESULTS.txt` and adjust the literals to what the probe actually printed before implementing.

- [ ] **Step 1: Write the failing tests** (append to `packages/sandbox/test/violation.test.ts`; reuse the file's existing result-builder helpers if present, else construct `SandboxResult` literals as below)

```ts
const EXEC_DS = {
  deniedPaths: ["/Users/test/.ssh"],
  networkDenied: true,
  execDenied: true,
  execAllowedPaths: ["/bin", "/usr/bin", "/usr/local", "/work/pkg", "/Library/Developer"],
  execDeniedPaths: ["/usr/bin/curl", "/opt/homebrew/bin/curl"],
  writeAllowedPaths: ["/work/pkg", "/private/tmp/tmpdir-x", "/private/tmp", "/dev"],
};
const fail = (stderr: string) => ({ exitCode: 126, stdout: "", stderr });

describe("classifyViolation — exec (Phase 28)", () => {
  test("a denied carve-out exec is a confirmed process violation", () => {
    const v = classifyViolation(fail("sh: /usr/bin/curl: Operation not permitted"), EXEC_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "/usr/bin/curl");
  });

  test("a denied exec in a WRITABLE location is confirmed (cannot be a write denial there)", () => {
    const v = classifyViolation(fail("sh: /private/tmp/tmpdir-x/payload: Operation not permitted"), EXEC_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "exec-default-deny");
  });

  test("a perm error outside both the exec floor and the write floor is only suspected (exec/write ambiguity)", () => {
    const v = classifyViolation(fail("sh: /usr/share/thing: Operation not permitted"), EXEC_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "suspected");
  });

  test("an unquoted perm error on a SENSITIVE path stays a filesystem violation", () => {
    const v = classifyViolation(fail("sh: /Users/test/.ssh/id_rsa: Operation not permitted"), EXEC_DS);
    assert.equal(v?.kind, "filesystem");
    assert.equal(v?.confidence, "confirmed");
  });

  test("a perm error where exec IS allowed is ambient — null", () => {
    assert.equal(classifyViolation(fail("sh: /usr/bin/some-tool: Operation not permitted"), EXEC_DS), null);
  });

  test("node's pathless spawn EPERM is a suspected process violation", () => {
    const v = classifyViolation(fail("Error: spawn EPERM"), EXEC_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "suspected");
    assert.equal(v?.target, null);
  });

  test("without execDenied (legacy DenySet / linux) the exec branch never fires", () => {
    const legacy = { deniedPaths: [], networkDenied: true };
    assert.equal(classifyViolation(fail("sh: /private/tmp/x: Operation not permitted"), legacy), null);
  });
});
```

- [ ] **Step 2: Run to verify the new block fails**

Run: `node --import tsx --test packages/sandbox/test/violation.test.ts`
Expected: existing tests PASS; new block FAILS (all return null today).

- [ ] **Step 3: Implement** — add the regexes beside the existing ones and the branch between the network and filesystem branches:

```ts
// Exec-denial shapes (Phase 28). The shell reports a denied execve as an
// UNQUOTED "<shell>: <path>: Operation not permitted" line (probe-verified);
// node reports "spawn [<path>] EPERM". Keep the shell prefix narrow (sh|bash|zsh)
// so tool-level errors like "cat: …" don't enter the exec branch.
const SH_EXEC = /(?:^|[/\s])(?:sh|bash|zsh):(?:\s*line\s+\d+:)?\s*(\/[^:\n]+): [Oo]peration not permitted/;
const SPAWN_EXEC = /spawn(?:\s+(\/\S+))? (?:EPERM|EACCES)/;
```

```ts
  // Process/exec (Phase 28): a bare "sh: /path: Operation not permitted" line is
  // ambiguous between a denied exec and a denied write-redirect — disambiguate via
  // the deny/allow sets. A SENSITIVE-path hit is attributed as filesystem (better
  // than the quoted-only extraction alone); a hit in a WRITABLE location must be
  // the exec gate (writes succeed there), so it's confirmed; outside both floors
  // exec-vs-write is genuinely ambiguous → suspected. Only when the profile
  // actually denies exec (execDenied) — legacy/linux DenySets skip this entirely.
  const execLine = firstMatchingLine(stderr, SH_EXEC) ?? firstMatchingLine(stderr, SPAWN_EXEC);
  if (execLine && denySet.execDenied) {
    const target = SH_EXEC.exec(execLine)?.[1] ?? SPAWN_EXEC.exec(execLine)?.[1] ?? null;
    const evidence = { exitCode: result.exitCode, stderrExcerpt: excerpt(execLine) };
    if (!target) return { kind: "process", target: null, confidence: "suspected", deniedResource: null, evidence };
    const sensitive = (denySet.deniedPaths ?? []).find((dp) => pathCovers(dp, target));
    if (sensitive) return { kind: "filesystem", target, confidence: "confirmed", deniedResource: sensitive, evidence };
    const carved = (denySet.execDeniedPaths ?? []).find((p) => p === target || pathCovers(p, target));
    if (carved) return { kind: "process", target, confidence: "confirmed", deniedResource: carved, evidence };
    if ((denySet.execAllowedPaths ?? []).some((p) => pathCovers(p, target))) return null; // exec allowed there → ambient
    const writable = (denySet.writeAllowedPaths ?? []).some((p) => pathCovers(p, target));
    return {
      kind: "process", target,
      confidence: writable ? "confirmed" : "suspected",
      deniedResource: writable ? "exec-default-deny" : null,
      evidence,
    };
  }
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/violation.test.ts`
Expected: PASS (all — the pre-existing network/fs/swallowed-denial tests must be untouched).

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/violation.ts packages/sandbox/test/violation.test.ts
git commit -m "feat(sandbox): classify denied execs as process violations, write-floor-disambiguated (Phase 28)"
```

---

### Task 8: Wire `seatbelt.ts` + darwin effect tests

**Files:**
- Modify: `packages/sandbox/src/seatbelt.ts:45` (the `computeDenySet` call)
- Test: `packages/sandbox/test/seatbelt.test.ts` (append to the existing darwin-gated `describe("SeatbeltSandbox enforcement", …)` block)

**Interfaces:**
- Consumes: Task 6's extended `computeDenySet` opts; `nodeInstallPrefix` (already imported in seatbelt.ts).
- Produces: end-to-end kernel enforcement + violation surfacing; Task 9 documents it.

- [ ] **Step 1: Wire the deny-set call** — in `seatbelt.ts`, replace line 45:

```ts
      const denySet = computeDenySet(opts.approved, { homeDir: opts.homeDir, platform: "darwin" });
```

with:

```ts
      const denySet = computeDenySet(opts.approved, {
        homeDir: opts.homeDir, platform: "darwin",
        nodePrefix: nodeInstallPrefix(process.execPath),
        projectRoot: opts.projectRoot ?? opts.cwd,
        cwd: opts.cwd, tmpDir: tmpdir(),
      });
```

- [ ] **Step 2: Write the effect tests** (append inside the existing darwin-gated enforcement `describe`; benign probes only)

```ts
  test("exec floor positive control: /bin/echo and a node_modules/.bin shim still run", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-exec-pos-")));
    mkdirSync(join(home, "node_modules", ".bin"), { recursive: true });
    const shim = join(home, "node_modules", ".bin", "hello");
    writeFileSync(shim, "#!/bin/sh\necho SHIM-OK\n", { mode: 0o755 });
    const res = new SeatbeltSandbox().run(`/bin/echo FLOOR-OK && "${shim}"`, { cwd: home, approved: [], homeDir: home });
    assert.equal(res.exitCode, 0, res.stderr);
    assert.match(res.stdout, /FLOOR-OK/);
    assert.match(res.stdout, /SHIM-OK/);
  });

  test("a dropped binary in a writable non-project dir is denied and surfaces as a process violation", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-exec-home-")));
    const stash = realpathSync(mkdtempSync(join(tmpdir(), "sb-exec-stash-"))); // writable (under tmp floor), NOT under projectRoot
    const marker = join(stash, "marker.txt");
    // the script itself WRITES the payload (proving the location is writable), then tries to exec it
    const cmd = `printf '#!/bin/sh\\necho PWNED > "${marker}"\\n' > "${stash}/payload" && chmod +x "${stash}/payload" && "${stash}/payload"`;
    const res = new SeatbeltSandbox().run(cmd, { cwd: home, approved: [], homeDir: home });
    assert.ok(existsSync(join(stash, "payload")), "the write must have succeeded (writable location)");
    assert.ok(!existsSync(marker), "the dropped binary must NOT have executed");
    assert.notEqual(res.exitCode, 0);
    assert.equal(res.violation?.kind, "process");
    assert.equal(res.violation?.confidence, "confirmed");
  });

  test("the curl carve-out is denied without a Grant and lifted by process:curl", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-exec-curl-")));
    const out = join(home, "curl-out.txt");
    new SeatbeltSandbox().run(`/usr/bin/curl --version > "${out}" 2>/dev/null || true`, { cwd: home, approved: [], homeDir: home });
    const denied = existsSync(out) ? readFileSync(out, "utf8") : "";
    assert.ok(!denied.includes("curl"), "curl must not have run without a Grant");
    const approved: Capability[] = [{ kind: "process", target: "curl", evidence: [] }];
    new SeatbeltSandbox().run(`/usr/bin/curl --version > "${out}"`, { cwd: home, approved, homeDir: home });
    assert.ok(readFileSync(out, "utf8").includes("curl"), "an approved process:curl must run");
  });
```

- [ ] **Step 3: Run the effect tests on this darwin host**

Run: `node --import tsx --test packages/sandbox/test/seatbelt.test.ts`
Expected: PASS — including every pre-existing Phase 25 effect test (the new exec layer must not have broken write/read enforcement; the Phase 25 tests exercise scripts that spawn `cat`, `nc`, `node` — all floor-resident). If the dropped-binary test's violation assertion fails while containment holds, compare the actual stderr against Task 7's regexes (probe drift) and fix the regex, not the assertion.

**Note:** `nc` is used by a pre-existing Phase 25 network effect test AND is now carve-out-denied. That test (`a denied network connection never lands`) passes `nc … || true` and asserts the connection never lands — exec-denying `nc` still satisfies the assertion (the connection can't land if `nc` never runs), so it stays green. Do not "fix" it.

- [ ] **Step 4: Full suite**

Run: `npm test`
Expected: green (previous count + this phase's new tests; 2 pre-existing darwin skips unchanged). Record the new total for Task 9's CLAUDE.md update.

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/seatbelt.ts packages/sandbox/test/seatbelt.test.ts
git commit -m "feat(sandbox): wire exec deny-set into SeatbeltSandbox + darwin effect tests (Phase 28)"
```

---

### Task 9: ADR-0042 + documentation sweep

**Files:**
- Create: `docs/adr/0042-exec-deny-by-default-darwin.md`
- Modify: `ARCHITECTURE.md` (§3.6 enforcement-scope paragraph, lines ~165-174), `sentinel-threat-model.md` (§3.9 paragraph at ~264-269 and the §4 bullet at ~284-289), `README.md` (sandbox section heading + bullets, lines ~276-283), `CLAUDE.md` (Phase 3 note, new Phase 28 paragraph, test count)

**Interfaces:** none (docs). Consumes the shipped behavior from Tasks 3-8.

- [ ] **Step 1: Write ADR-0042**

Create `docs/adr/0042-exec-deny-by-default-darwin.md` (follow the house ADR format — check `docs/adr/0040-*.md` for the exact heading skeleton and mirror it):

```markdown
# ADR-0042: Exec deny-by-default on macOS; Landlock plan for Linux; `native` formally advisory

## Status

Accepted (2026-07-10). Extends ADR-0038 (deny-by-default sandbox) and
ADR-0023 (violation telemetry); supersedes nothing. Resolves the
enforce-or-formally-downgrade decision tracked in issue #8 for the
`process` kind on macOS; Linux enforcement is Phase 29.

## Context

The capability model exposes `process` and `native` as approvable kinds and
scores them (`capability-novelty`), but through Phase 27 neither sandbox
backend gated a spawn: Seatbelt had no `process-exec*` deny and bwrap adds
no exec restriction. An unapproved `child_process` spawn — including a
binary the script itself just downloaded — was permitted (issue #8,
documentation over-claim, P1).

Feasibility differs by platform. Seatbelt expresses path-based exec policy
natively (`process-exec*` + subpath/literal filters). Linux cannot do this
with bwrap alone: seccomp cannot inspect execve's path argument and bwrap
has no noexec mount option. Linux DOES have a path-based exec primitive —
Landlock (`LANDLOCK_ACCESS_FS_EXECUTE`, kernel ≥ 5.13) — but Node exposes
no Landlock syscalls, so it needs a small native piece (Phase 29,
probe-first). A runtime supervisor (seccomp-notify/pidfd) was considered
and rejected as Chrome-sandbox-class complexity for per-spawn decisions we
do not need; it remains the escalation path and layers on top of this
design without waste.

## Decision

macOS (Phase 28): exec is deny-by-default, mirroring the Phase 25 write
layering (SBPL last-match-wins):

1. `(deny process-exec*)` — blanket.
2. `(allow process-exec* …)` — a FIXED, non-configurable exec floor
   (`execAllowFloor`: /bin, /usr/bin, /usr/sbin, the node prefix, the
   project root, /Library/Developer, /Applications/Xcode.app,
   /opt/homebrew, /usr/local) plus approved `process:` PATH-Grants.
3. `(deny process-exec* (literal …))` — a curated `SENSITIVE_EXECUTABLES`
   carve-out (curl, wget, nc, ncat, socat, osascript, scp, sftp) expanded
   across the floor's bin dirs with no PATH resolution, re-denied unless a
   Grant lifts it.

`process` Grant target shapes: a bare word lifts that command's carve-out;
a target containing `/` (or starting `~`) is a path Grant appended to the
allow (guarded by `isSafeGrantTarget`); `*` lifts the whole carve-out but
opens no non-floor paths. `process-fork` stays allowed — only exec is
gated. `computeDenySet` mirrors the exec sets (non-drift-tested) and
`classifyViolation` attributes a denied exec, disambiguating the shell's
ambiguous "Operation not permitted" line via the write floor: denied in a
writable location ⇒ confirmed (a write there cannot fail); outside both
floors ⇒ suspected.

Linux: unchanged this phase — exec remains advisory pending Phase 29
(Landlock). `native` (dlopen/WASM): formally advisory-only on BOTH
platforms, permanently — no path-level primitive distinguishes loading an
artifact from reading it.

## Consequences

- Exec from any writable-but-not-project location (/tmp, ~/Downloads,
  caches) is kernel-denied on macOS — the dropped-binary pattern dies.
- Accepted residual: projectRoot is in the floor, so a package can write a
  binary into its own tree and exec it. Rejected alternative (a strict
  floor without projectRoot/Homebrew) breaks every node_modules/.bin shim
  and brew-installed build tool. Existing mitigations: `unscanned-content`
  surfaces bundled binaries (ADR-0041); `process` detection scores the
  spawn pattern.
- Platform asymmetry until Phase 29, documented in the threat model —
  same precedent as the ADR-0023/0038 telemetry and /dev asymmetries.
- Scoring, the approval model, bwrap, and the proxy are untouched
  (invariants #1–#7).

## Rejected alternatives

- Formalize advisory-only everywhere — leaves Seatbelt's native exec
  primitive unused while dropped binaries run.
- Strict floor (system + node only) — unacceptable default breakage.
- Operator-configurable floor — diverges from the Phase 25 precedent;
  widening the floor silently reopens the class.
- Runtime supervisor — complexity disproportionate to a pre-1.0 install
  sandbox; retained as the future escalation path.
```

- [ ] **Step 2: Update ARCHITECTURE.md §3.6** — replace the paragraph starting `**Enforcement scope — \`process\`/\`native\` are advisory-only (not enforced).**` (~lines 165-174) with:

```markdown
**Enforcement scope — `process` enforced on macOS (Phase 28); Linux pending; `native`
advisory by decision.** The Seatbelt profile denies `process-exec*` by default,
re-allows a fixed exec floor (`execAllowFloor`: system dirs, the node prefix, the
project root, Apple/Homebrew toolchains) plus approved `process:` path-Grants, then
re-denies a curated `SENSITIVE_EXECUTABLES` carve-out (curl, wget, nc, …) unless a
command/wildcard Grant lifts it — so an unapproved exec of a dropped binary outside
the project tree is kernel-denied (ADR-0042). On Linux, exec remains advisory until
the Landlock-based Phase 29 lands (bwrap alone cannot path-filter exec). `native`
(dlopen/WASM) is formally advisory-only on both platforms — no path-level primitive
distinguishes loading an artifact from reading it. The projectRoot-in-floor residual
(a package executing a binary written into its own tree) is a recorded ADR-0042
trade-off, mitigated by `unscanned-content` (ADR-0041) and `process` capability
scoring. Enforce-vs-advisory for Linux exec is tracked in
[#8](https://github.com/git-agentic/pkg-registry/issues/8).
```

- [ ] **Step 3: Update the threat model** — in `sentinel-threat-model.md` §3.9, replace the sentence block at ~264-269 (`detected and fed to scoring (advisory signal), but neither backend enforces them — …`) with:

```markdown
detected and fed to scoring, and on macOS (Phase 28, ADR-0042) an exec is
enforced deny-by-default: a spawn is kernel-permitted only from the fixed exec
floor (system dirs, node prefix, project tree, developer/Homebrew toolchains)
or an approved `process:` Grant, with exfil-capable tools (curl, wget, nc, …)
re-denied inside the floor unless granted. On Linux exec remains advisory until
the Landlock-based Phase 29 lands; `native` is advisory-only on both platforms
by decision. A spawned child inherits the filesystem/network confinement on
both platforms. Remaining Linux work is tracked in
[issue #8](https://github.com/git-agentic/pkg-registry/issues/8).
```

and replace the §4 accepted-limitations bullet (~284-289, the one beginning `are advisory scoring signal, not an enforced gate (see §3.9).`) — keep the bullet's opening clause about `process`/`native` from its preceding line intact and rewrite the remainder to:

```markdown
- **`process` is enforced on macOS only (for now); `native` is advisory
  everywhere.** On macOS an unapproved exec outside the floor is kernel-denied
  (ADR-0042), with two recorded residuals: a package may exec a binary written
  into its own project tree (floor decision), and Linux exec gating awaits
  Phase 29 (Landlock). `native` loading is not distinguishable from reading at
  the path level and stays a scoring signal. See §3.9;
  [issue #8](https://github.com/git-agentic/pkg-registry/issues/8).
```

- [ ] **Step 4: Update README sandbox section** — change the heading `### Sandbox — default-deny (Phases 3–5 + 25; macOS Seatbelt / Linux bubblewrap)` to `### Sandbox — default-deny (Phases 3–5, 25, 28; macOS Seatbelt / Linux bubblewrap)` and add this bullet after the `$HOME reads` bullet:

```markdown
- **Exec** (macOS, Phase 28) is denied outside a fixed floor — system dirs, the node
  prefix, the project tree, Apple/Homebrew toolchains — plus approved `process:`
  grants (`process:curl` lifts one tool's carve-out; `process:/path` opens a path;
  `process:*` lifts the carve-out only), and exfil-capable tools (`curl`, `wget`,
  `nc`, …) are re-denied inside the floor unless granted. A dropped binary in `/tmp`
  or a cache is kernel-denied. Linux exec gating (Landlock) is Phase 29 — until it
  lands, exec on Linux remains advisory (ADR-0042).
```

- [ ] **Step 5: Update CLAUDE.md** — three edits:

1. In the Phase 3 paragraph, replace `Note: the \`process\` and \`native\` capability kinds are **detected and scored (advisory-only), not enforced** — neither backend restricts process execution, so a child process inherits the filesystem/network confinement but the act of spawning it is ungated (tracked in #8).` with `Note: as of Phase 28 the `process` kind is **enforced on macOS** (exec deny-by-default, ADR-0042); on Linux it remains advisory until Phase 29 (Landlock), and `native` is advisory-only on both platforms by decision (tracked in #8).`
2. Append a Phase 28 paragraph after the Phase 27 paragraph:

```markdown
Phase 28 enforces the `process` capability on macOS: Seatbelt gains an
**exec deny-by-default** layer mirroring Phase 25's write layering —
`(deny process-exec*)`, re-allow a fixed `execAllowFloor` (`packages/sandbox/
src/exec-floor.ts`: /bin, /usr/bin, /usr/sbin, node prefix, project root,
/Library/Developer, /Applications/Xcode.app, /opt/homebrew, /usr/local) plus
approved `process:` path-Grants, then re-deny a curated `SENSITIVE_EXECUTABLES`
carve-out (`sensitive-executables.ts`: curl, wget, nc, ncat, socat, osascript,
scp, sftp — fixed literals across the floor's bin dirs, no PATH resolution)
unless a command/wildcard Grant lifts it. Grant shapes: bare word ⇒ lifts that
command's carve-out; contains `/` or starts `~` ⇒ path Grant (guarded by
`isSafeGrantTarget`); `*` ⇒ lifts the whole carve-out, opens no paths.
`process-fork` stays allowed. `computeDenySet` mirrors the exec sets
(non-drift-tested) and `classifyViolation` attributes denied execs, using the
write floor to disambiguate the shell's ambiguous "Operation not permitted"
line (writable location ⇒ confirmed; outside both floors ⇒ suspected).
Accepted residual: projectRoot is in the floor, so a package can exec a binary
written into its own tree (mitigated by `unscanned-content` + `process`
scoring). Linux exec is unchanged pending Phase 29 (Landlock, needs a small
native piece); `native` is formally advisory-only on both platforms. Scoring
and the approval model are untouched (invariants #1–#7, ADR-0042).
```

3. Update the test-count line in the Build/test section with the actual `npm test` total recorded in Task 8 Step 4, and append to the long parenthetical test-inventory comment: `Phase 28's exec-floor/sensitive-executables/profile-exec/deny-set-exec/violation-exec unit tests are hermetic and platform-neutral; its three Seatbelt exec effect tests (floor positive control, dropped-binary denial + confirmed process violation, curl carve-out lift) are darwin-gated and RUN on darwin.`

- [ ] **Step 6: Build + full suite + commit**

```bash
npm run build && npm test
git add docs/adr/0042-exec-deny-by-default-darwin.md ARCHITECTURE.md sentinel-threat-model.md README.md CLAUDE.md
git commit -m "docs: ADR-0042 exec deny-by-default (darwin) + architecture/threat-model/README/CLAUDE.md sweep (Phase 28)"
```

Expected: build clean, tests green.

---

### Task 10: File Phase 29 issue, update #8, finish the branch

**Files:** none (GitHub + branch mechanics).

- [ ] **Step 1: File the Phase 29 (Linux/Landlock) issue**

```bash
gh issue create --repo git-agentic/pkg-registry \
  --title "Phase 29: Linux exec deny-by-default via Landlock" \
  --label security \
  --body "Phase 28 (ADR-0042) enforces the \`process\` capability on macOS via Seatbelt \`process-exec*\`. Linux needs the equivalent: **Landlock** (\`LANDLOCK_ACCESS_FS_EXECUTE\`, kernel ≥ 5.13, enabled on Ubuntu CI kernels) expresses the same path-based model — exec allowed only beneath the exec floor + approved \`process:\` path-Grants.

**Probe first (probe-before-spec):** Node exposes no Landlock syscalls, so this needs a small native piece (N-API addon or tiny helper). Feasibility questions to probe on ubuntu-latest before speccing: Landlock available in the CI kernel/LSM list? addon-vs-helper trade-off given the repo's pure-TS, build-from-source posture? fallback semantics on kernels without Landlock (documented advisory vs fail-closed refusal)?

Same floor/carve-out/Grant model as ADR-0042 (\`execAllowFloor\`, \`SENSITIVE_EXECUTABLES\`, target shapes). \`native\` stays advisory by decision.

Blocks closing #8 (its claim is cross-platform)."
```

- [ ] **Step 2: Comment on #8**

```bash
gh issue comment 8 --repo git-agentic/pkg-registry --body "Decision recorded in ADR-0042 (Phase 28, merged from branch \`phase-28-exec-deny\`): **enforce**, per-platform. macOS now denies exec by default — fixed floor + \`process:\` Grants + a curl/wget/nc/… carve-out — so an unapproved dropped-binary exec is kernel-denied, and a denied exec surfaces as a runtime \`process\` violation. \`native\` is formally advisory-only on both platforms (no path-level primitive distinguishes dlopen from read). Linux enforcement via Landlock is tracked as the Phase 29 issue; leaving #8 open until it lands, since this issue's claim is cross-platform."
```

- [ ] **Step 3: Finish the branch**

Invoke the `superpowers:finishing-a-development-branch` skill for the `phase-28-exec-deny` branch (the user's established pattern is a local `--no-ff` merge to main). Verify first: `npm run build && npm test` green, and `git log --oneline main..HEAD` shows the seven Phase 28 commits (Tasks 3–9).

---

## Verification checklist (Definition of Done)

- [ ] `npm run build` clean, `npm test` green; CLAUDE.md count updated
- [ ] All three darwin effect tests pass on this host; Phase 25 effect tests unbroken
- [ ] Malicious fixtures still blocked (`npm run demo` still ends in the 403 panel)
- [ ] ADR-0042 + ARCHITECTURE + threat model + README + CLAUDE.md all agree on the new enforcement scope
- [ ] #4 closed; Phase 29 issue filed; #8 commented and still open
