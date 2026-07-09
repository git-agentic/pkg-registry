# Phase 25 Slice 2 — Sandbox `$HOME`-Read-Deny (ADR-0038) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the sandbox default-deny model by inverting the read posture for `$HOME`: deny reads of the home directory by default, re-allowing only what a lifecycle script legitimately needs (system paths, the node runtime, the project tree, and the build caches), so credential theft is closed as a whole class rather than an enumerated list.

**Architecture:** A new pure `read-allow.ts` computes the in-`$HOME` read-allow list from `{homeDir, nodePrefix, projectRoot}` and resolves the two new inputs (`resolveProjectRoot` from npm's `INIT_CWD`, `nodeInstallPrefix` from `process.execPath`). Both backend generators gain a `$HOME`-read-deny + re-allow layer, keeping the slice-1 write-deny untouched. `Sandbox.run` gains a `projectRoot` input, threaded from the script-shell shim and `runLifecycleScripts`; the backends derive `nodePrefix` from `process.execPath`. The bwrap `--tmpfs $HOME` masks yield `ENOENT`, so credential-read telemetry stays Seatbelt-only (the accepted asymmetry, confirmed by slice-1 CI).

**Tech Stack:** Node 24 / TypeScript, macOS Seatbelt (SBPL), Linux bubblewrap (`bwrap`), `node:test` + `tsx`.

**Spec:** `docs/superpowers/specs/2026-07-09-security-hardening-phases-design.md` (Phase 25 section, grilling-refined — Slice 2). Domain vocabulary in `CONTEXT.md`. Slice 1 (write-deny) is merged.

## Global Constraints

- ESM only, NodeNext: internal imports use `.js` specifiers even from `.ts` sources.
- **This is Slice 2 (reads) only.** Do NOT change the slice-1 write-deny (blanket `(deny file-write*)` + floor + carve-out on Seatbelt; `--ro-bind / /` + rw floor on bwrap). Reads were allow-default-minus-`SENSITIVE`; this slice inverts `$HOME` reads.
- Profile/argv generation stays **pure**: same inputs ⇒ same output. `nodePrefix`, `projectRoot`, and `tmpDir` are passed in — never read from `process.execPath`/`INIT_CWD`/`os.tmpdir()` *inside* a generator.
- **Read-allow list = system paths (via allow-default / `--ro-bind / /`) + the node install prefix + the project root + `~/.node-gyp` + `~/.cache`.** Everything else in `$HOME` is denied. `/etc/passwd` and `/etc/shadow` stay denied by the **existing** `SENSITIVE_PATHS` read carve-out (they live in read-allowed `/etc`) — do not remove it.
- `SENSITIVE_PATHS` is **not edited**.
- **Telemetry asymmetry (accepted, ADR-0023):** Seatbelt read-deny → EPERM → `classifyViolation` reports a confirmed violation; bwrap `--tmpfs` mask → ENOENT → contained but not reported. Effect tests assert **containment on both** backends and gate the violation-**record** assertion to darwin (the pattern established by the slice-1 enforce test).
- Seatbelt effect tests run on **darwin only**; bwrap effect tests run on **Linux CI only** (`describe`-level skip on darwin). Match the existing `const darwin = process.platform === "darwin"` gating.
- Enforcement tested with **benign probes only**; synthetic malware never executed.
- Run one test file: `node --import tsx --test packages/sandbox/test/<file>.test.ts`. Full suite: `npm test`. Build: `npm run build` (EPERM on `rm dist/` ⇒ `npx tsc --build --force packages/sandbox`).
- Commit style: `feat(phase25s2): …` / `test(phase25s2): …` / `docs(phase25s2): …`.
- Current full-suite baseline on darwin (post-slice-1 merge): **640 tests, 638 pass, 2 skipped**.

---

### Task 1: Exploratory probe gate (throwaway, darwin) — confirm the read-allow list + node-under-`$HOME`

**Produces NO commit.** A design gate: prove a native build + cross-package `require()` still work under `$HOME`-read-deny before locking the generators, and that the node runtime is reachable even when it lives under `$HOME`. If a needed read path is missing, **stop and report it** so Tasks 2/4/5 encode it.

**Files:**
- Create (scratchpad, not committed): `<scratchpad>/phase25s2-read-probe.sh`

**Read-allow hypothesis** (what Tasks 2/4/5 will encode): the node install prefix (`dirname(dirname(node))`), the project root, `~/.node-gyp`, `~/.cache`. Deny the rest of `$HOME`.

- [ ] **Step 1: Write the probe**

```bash
#!/bin/bash
# Phase 25 Slice 2 read-deny probe (darwin). Runs a native build + a require()
# across the project tree under a prototype $HOME-read-deny SBPL profile, and
# proves a credential read is denied while the node prefix stays readable.
set -u
HOME_DIR=$(mktemp -d); export HOME="$HOME_DIR"
PROJ="$HOME_DIR/app"; mkdir -p "$PROJ"
PKG="$PROJ/node_modules/native-probe"; mkdir -p "$PKG"
PROFILE=$(mktemp)
NODE_PREFIX=$(cd "$(dirname "$(dirname "$(command -v node)")")" && pwd -P)
canon() { case "$1" in /var/*|/etc/*|/tmp/*) echo "/private$1";; *) echo "$1";; esac; }

# Plant a credential (must stay unreadable) and a project-sibling module (must resolve).
mkdir -p "$HOME_DIR/.ssh"; echo SECRET > "$HOME_DIR/.ssh/id_rsa"
mkdir -p "$PROJ/node_modules/dep"; echo 'module.exports=42' > "$PROJ/node_modules/dep/index.js"

cat > "$PKG/binding.gyp" <<EOF
{ "targets": [ { "target_name": "np", "sources": ["np.c"] } ] }
EOF
cat > "$PKG/np.c" <<EOF
#include <node_api.h>
napi_value Init(napi_env e, napi_value x){ return x; }
NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
EOF
echo '{"name":"native-probe","version":"1.0.0"}' > "$PKG/package.json"
cat > "$PKG/build.js" <<EOF
require('dep');                       // resolves via $PROJ/node_modules (project root)
require('fs').readFileSync(process.execPath); // reads the node binary (node prefix)
console.log('REQUIRE+NODE_OK');
EOF

cat > "$PROFILE" <<EOF
(version 1)
(allow default)
(deny file-read* (subpath "$(canon "$HOME_DIR")"))
(allow file-read*
  (subpath "$(canon "$NODE_PREFIX")")
  (subpath "$(canon "$PROJ")")
  (subpath "$(canon "$HOME_DIR")/.node-gyp")
  (subpath "$(canon "$HOME_DIR")/.cache"))
EOF

echo "=== native build under \$HOME-read-deny (expect success) ==="
( cd "$PKG" && sandbox-exec -f "$PROFILE" /bin/sh -c "npx node-gyp configure build 2>&1 | tail -6; echo GYP=\${PIPESTATUS[0]:-\$?}" )
echo "built.node: $([ -f "$PKG/build/Release/np.node" ] && echo YES || echo NO)"

echo "=== require() across project tree + read node binary (expect REQUIRE+NODE_OK) ==="
( cd "$PKG" && sandbox-exec -f "$PROFILE" node build.js 2>&1 )

echo "=== credential read under the deny (expect DENIED) ==="
sandbox-exec -f "$PROFILE" /bin/sh -c "cat '$HOME_DIR/.ssh/id_rsa' 2>&1 || echo READ_DENIED"

rm -rf "$HOME_DIR" "$PROFILE"
```

- [ ] **Step 2: Run the probe**

Run: `bash <scratchpad>/phase25s2-read-probe.sh`

Expected: `GYP=0` and `built.node: YES`; `REQUIRE+NODE_OK` (project `require()` + node-binary read work under the deny); the credential read prints `Operation not permitted` / `READ_DENIED` (not `SECRET`).

- [ ] **Step 3: Record findings and decide**

If all hold, the read-allow list is confirmed — proceed. **If the native build or `require()` fails** with a read EPERM on a path *not* in the allow-list (likely suspects: `~/.cache/node/corepack`, a compiler toolchain path under `$HOME`, a `~/.npmrc`-derived config read), record it and add it to the read-allow list in Tasks 2/4/5 before implementing. **If node lives under `$HOME` and the run fails to find its stdlib**, confirm `nodeInstallPrefix` covers the right directory. Report the confirmed list. (No commit — the committed guarantee is Tasks 4/5's effect tests.)

---

### Task 2: `read-allow.ts` — read-allow list + input resolution

**Files:**
- Create: `packages/sandbox/src/read-allow.ts`
- Test: `packages/sandbox/test/read-allow.test.ts`

**Interfaces:**
- Produces (used by Tasks 3–5):
  - `readAllowList(opts: { nodePrefix: string; projectRoot: string }): string[]` — pure; the in-`$HOME` read-allowed paths as raw strings (callers expand `~`/canonicalize). Uses the probe-confirmed list.
  - `nodeInstallPrefix(execPath: string): string` — `dirname(dirname(execPath))`.
  - `resolveProjectRoot(cwd: string, initCwd: string | undefined): string` — `initCwd` when it is a non-empty absolute path, else the nearest ancestor of `cwd` containing a `package.json`, else `cwd`.

- [ ] **Step 1: Write the failing tests**

```typescript
// packages/sandbox/test/read-allow.test.ts
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { readAllowList, nodeInstallPrefix, resolveProjectRoot } from "../src/read-allow.js";

describe("readAllowList", () => {
  test("includes the node prefix, project root, and the build caches", () => {
    assert.deepEqual(readAllowList({ nodePrefix: "/usr/local", projectRoot: "/work/app" }), [
      "/usr/local",
      "/work/app",
      "~/.node-gyp",
      "~/.cache",
    ]);
  });
  test("is pure", () => {
    const a = readAllowList({ nodePrefix: "/n", projectRoot: "/p" });
    assert.deepEqual(a, readAllowList({ nodePrefix: "/n", projectRoot: "/p" }));
  });
});

describe("nodeInstallPrefix", () => {
  test("strips bin/node to the install prefix", () => {
    assert.equal(nodeInstallPrefix("/usr/local/bin/node"), "/usr/local");
  });
  test("handles a node-under-$HOME version-manager layout", () => {
    assert.equal(nodeInstallPrefix("/home/x/.nvm/versions/node/v24.0.0/bin/node"), "/home/x/.nvm/versions/node/v24.0.0");
  });
});

describe("resolveProjectRoot", () => {
  test("uses INIT_CWD when it is an absolute path", () => {
    assert.equal(resolveProjectRoot("/work/app/node_modules/pkg", "/work/app"), "/work/app");
  });
  test("ignores a blank/relative INIT_CWD and walks up to the nearest package.json", () => {
    const root = mkdtempSync(join(tmpdir(), "pr-"));
    writeFileSync(join(root, "package.json"), "{}");
    const deep = join(root, "node_modules", "pkg", "lib");
    mkdirSync(deep, { recursive: true });
    assert.equal(resolveProjectRoot(deep, ""), root);
    assert.equal(resolveProjectRoot(deep, "relative/path"), root);
  });
  test("falls back to cwd when no ancestor package.json exists", () => {
    const bare = mkdtempSync(join(tmpdir(), "bare-"));
    assert.equal(resolveProjectRoot(bare, undefined), bare);
  });
  test("does not require the caller to have created any file for the INIT_CWD path", () => {
    assert.ok(!existsSync("/nonexistent-x")); // sanity; INIT_CWD is trusted as-is when absolute
    assert.equal(resolveProjectRoot("/a/b", "/nonexistent-x"), "/nonexistent-x");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/read-allow.test.ts`
Expected: FAIL — `Cannot find module '../src/read-allow.js'`

- [ ] **Step 3: Write the implementation**

```typescript
// packages/sandbox/src/read-allow.ts
import { existsSync } from "node:fs";
import { dirname, isAbsolute, parse } from "node:path";

/**
 * The in-`$HOME` read-allow list under Phase 25 Slice 2 `$HOME`-read-deny (ADR-0038).
 * System paths stay readable via the backends' allow-default / `--ro-bind / /`; this
 * covers what lives *inside* `$HOME`: the node install prefix (so a node-under-`$HOME`
 * runtime — nvm/fnm/volta — can load its stdlib), the project root (so a lifecycle
 * script's `require()` resolves across the project tree), and the build caches. Pure;
 * callers expand `~` and canonicalize.
 */
export function readAllowList(opts: { nodePrefix: string; projectRoot: string }): string[] {
  return [opts.nodePrefix, opts.projectRoot, "~/.node-gyp", "~/.cache"];
}

/** The node runtime's install prefix: `dirname(dirname(execPath))` (…/prefix/bin/node → …/prefix). */
export function nodeInstallPrefix(execPath: string): string {
  return dirname(dirname(execPath));
}

/**
 * The project root a lifecycle script resolves `require()` against — distinct from the
 * Install directory (`cwd`, deep in `node_modules`). npm sets `INIT_CWD` to the install's
 * originating dir (the project root); trust it when it's an absolute path. Otherwise walk
 * up from `cwd` to the nearest ancestor with a `package.json`; failing that, use `cwd`.
 */
export function resolveProjectRoot(cwd: string, initCwd: string | undefined): string {
  if (initCwd && isAbsolute(initCwd)) return initCwd;
  let dir = cwd;
  for (;;) {
    if (existsSync(`${dir}/package.json`)) return dir;
    const parent = dirname(dir);
    if (parent === dir || parent === parse(dir).root) return existsSync(`${parent}/package.json`) ? parent : cwd;
    dir = parent;
  }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/read-allow.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/read-allow.ts packages/sandbox/test/read-allow.test.ts
git commit -m "feat(phase25s2): read-allow list + node-prefix/project-root resolution helpers (ADR-0038)"
```

---

### Task 3: Thread `projectRoot` + `nodePrefix` through `run()`, the shim, and the runner

**Files:**
- Modify: `packages/sandbox/src/types.ts` (`Sandbox.run` opts)
- Modify: `packages/sandbox/src/seatbelt.ts`, `packages/sandbox/src/bubblewrap.ts` (derive `nodePrefix`, pass both to the generators — generators ignore them until Tasks 4/5)
- Modify: `packages/cli/src/script-shell.ts` (pass `projectRoot` from `INIT_CWD`)
- Modify: `packages/sandbox/src/runner.ts` (`runLifecycleScripts` accepts + forwards `projectRoot`)
- Test: `packages/sandbox/test/runner.test.ts` (forwarding)

**Interfaces:**
- Consumes: `resolveProjectRoot`, `nodeInstallPrefix` (Task 2).
- Produces:
  - `Sandbox.run(cmd, opts: { cwd; approved; homeDir; env?; projectRoot?: string }): SandboxResult` — new optional `projectRoot` (defaults to `cwd` when absent).
  - Generator opts (consumed by Tasks 4/5): both gain `nodePrefix: string; projectRoot: string`.
  - `runLifecycleScripts(opts: { …; projectRoot?: string })`.

- [ ] **Step 1: Write the failing test**

```typescript
// add to packages/sandbox/test/runner.test.ts (read the file first for its existing imports;
// add any of these that are missing — do not duplicate an existing import)
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runLifecycleScripts } from "../src/runner.js";
import type { Sandbox } from "../src/types.js";

test("runLifecycleScripts forwards projectRoot to the sandbox", () => {
  let seen: string | undefined = "UNSET";
  const spy: Sandbox = {
    run(_cmd, opts) { seen = opts.projectRoot; return { exitCode: 0, stdout: "", stderr: "" }; },
  };
  const dir = mkdtempSync(join(tmpdir(), "runner-pr-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ scripts: { postinstall: "echo hi" } }));
  runLifecycleScripts({ packageDir: dir, sandbox: spy, homeDir: "/home/x", projectRoot: "/work/app" });
  assert.equal(seen, "/work/app");
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/runner.test.ts`
Expected: FAIL — `runLifecycleScripts` doesn't accept/forward `projectRoot`.

- [ ] **Step 3: Implement the threading**

In `packages/sandbox/src/types.ts`, extend the `run` opts:

```typescript
export interface Sandbox {
  /** Run `cmd` (via `sh -c`) under a sandbox compiled from the APPROVED capabilities, in `cwd`. */
  run(cmd: string, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv; projectRoot?: string }): SandboxResult;
}
```

In `packages/sandbox/src/runner.ts` — add `projectRoot` to the opts and forward it:

```typescript
export function runLifecycleScripts(opts: {
  packageDir: string;
  sandbox: Sandbox;
  approved?: Capability[];
  homeDir: string;
  projectRoot?: string;
}): { results: ScriptResult[]; failed: boolean } {
```

and in the loop:

```typescript
    const r = opts.sandbox.run(command, { cwd: opts.packageDir, approved, homeDir: opts.homeDir, env, projectRoot: opts.projectRoot });
```

In `packages/sandbox/src/seatbelt.ts` — derive `nodePrefix`, pass both to `generateProfile` (which will accept them in Task 4). Add the import and change the call:

```typescript
import { nodeInstallPrefix } from "./read-allow.js";
// …
    const profile = generateProfile(opts.approved, {
      homeDir: opts.homeDir, cwd: opts.cwd, tmpDir: tmpdir(),
      nodePrefix: nodeInstallPrefix(process.execPath),
      projectRoot: opts.projectRoot ?? opts.cwd,
    });
```

In `packages/sandbox/src/bubblewrap.ts` — same:

```typescript
import { nodeInstallPrefix } from "./read-allow.js";
// …
    const args = [
      ...generateBwrapArgs(opts.approved, {
        homeDir: opts.homeDir, cwd: opts.cwd, tmpDir: tmpdir(), pathExists: existsSync,
        nodePrefix: nodeInstallPrefix(process.execPath),
        projectRoot: opts.projectRoot ?? opts.cwd,
      }),
      "/bin/sh", "-c", cmd,
    ];
```

(The generators don't yet read `nodePrefix`/`projectRoot` — that lands in Tasks 4/5. Add the params to their opts types now, unused, so this compiles: in `generateProfile` and `generateBwrapArgs` opts add `nodePrefix: string; projectRoot: string`.)

In `packages/cli/src/script-shell.ts` — pass `projectRoot` resolved from `INIT_CWD`:

```typescript
import { resolveProjectRoot } from "@sentinel/sandbox";
// …
  const r = sandbox.run(cmd, { cwd, approved, homeDir: homedir(), env, projectRoot: resolveProjectRoot(cwd, process.env.INIT_CWD) });
```

(Export `resolveProjectRoot`/`nodeInstallPrefix`/`readAllowList` from `packages/sandbox/src/index.ts`.)

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/runner.test.ts`
Expected: PASS. Also run `npm run build` — must be clean (the generator opts now include the unused params).

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/types.ts packages/sandbox/src/runner.ts packages/sandbox/src/seatbelt.ts packages/sandbox/src/bubblewrap.ts packages/sandbox/src/index.ts packages/cli/src/script-shell.ts packages/sandbox/test/runner.test.ts
git commit -m "feat(phase25s2): thread projectRoot (INIT_CWD) + nodePrefix (execPath) into the sandbox (ADR-0038)"
```

---

### Task 4: Seatbelt `$HOME`-read-deny generator + effect test

**Files:**
- Modify: `packages/sandbox/src/profile.ts`
- Test: `packages/sandbox/test/profile.test.ts`, `packages/sandbox/test/seatbelt.test.ts`

**Interfaces:**
- Consumes: `readAllowList` (Task 2); `nodePrefix`/`projectRoot` opts (Task 3).
- Produces: `generateProfile` emits, after `(allow default)` and before the existing SENSITIVE read-deny carve-out: `(deny file-read* (subpath "<$HOME>"))` then `(allow file-read* …readAllowList…)` (all canonicalized). The SENSITIVE read-deny loop stays as the final read carve-out (keeps `/etc/passwd` denied).

- [ ] **Step 1: Write the failing tests**

Add to `packages/sandbox/test/profile.test.ts` (extend `OPTS` with the new inputs):

```typescript
const OPTS2 = { homeDir: "/Users/x", cwd: "/Users/x/app/node_modules/pkg", tmpDir: "/var/folders/z/T", nodePrefix: "/usr/local", projectRoot: "/Users/x/app" };

describe("generateProfile — $HOME-read-deny (Phase 25 Slice 2)", () => {
  test("denies reads of $HOME then re-allows the read-allow list, in that order", () => {
    const p = generateProfile([], OPTS2);
    const denyHome = p.indexOf(`(deny file-read* (subpath "/Users/x")`);
    const allowList = p.indexOf(`(allow file-read*`);
    assert.ok(denyHome !== -1, "$HOME read-deny present");
    assert.ok(allowList > denyHome, "read-allow list comes AFTER the $HOME read-deny (last-match-wins)");
    for (const frag of [`(subpath "/usr/local")`, `(subpath "/Users/x/app")`, `(subpath "/Users/x/.node-gyp")`, `(subpath "/Users/x/.cache")`]) {
      assert.ok(p.includes(frag), `read-allow must include ${frag}`);
    }
  });
  test("the SENSITIVE read carve-out (incl. /etc/passwd) still comes after the re-allows", () => {
    const p = generateProfile([], OPTS2);
    const allowList = p.indexOf(`(allow file-read*`);
    const carve = p.indexOf(`(deny file-read* (literal "/private/etc/passwd")`);
    assert.ok(carve > allowList, "/etc/passwd read-deny is a carve-out after the re-allows");
  });
  test("write-deny (slice 1) is unchanged", () => {
    const p = generateProfile([], OPTS2);
    assert.ok(p.includes("(deny file-write*)"), "slice-1 blanket write-deny still present");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/profile.test.ts`
Expected: FAIL — no `$HOME` read-deny / read-allow list emitted.

- [ ] **Step 3: Implement the read-deny layer**

In `packages/sandbox/src/profile.ts`, import `readAllowList`:

```typescript
import { readAllowList } from "./read-allow.js";
```

Change the opts type to include the new inputs, and insert the read-deny + re-allow **before** the existing SENSITIVE read-deny loop (which becomes the final carve-out). Replace the read section (currently `// Reads: unchanged … for (const sp …) { … }`) with:

```typescript
export function generateProfile(
  approved: Capability[],
  opts: { homeDir: string; cwd: string; tmpDir: string; nodePrefix: string; projectRoot: string },
): string {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");
  const canon = (p: string) => canonicalizeMacPath(expandHome(p, opts.homeDir));

  const lines = ["(version 1)", "(allow default)"];

  // Reads: deny $HOME by default (Slice 2), then re-allow the read-allow list —
  // the node install prefix (node-under-$HOME still loads its stdlib), the project
  // root (require() resolves the tree), and the build caches. System paths stay
  // readable via (allow default).
  lines.push(`(deny file-read* (subpath "${canon(opts.homeDir)}"))`);
  const readAllow = readAllowList({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot }).map(canon);
  lines.push(`(allow file-read* ${readAllow.map((p) => `(subpath "${p}")`).join(" ")})`);

  // SENSITIVE read carve-out (last-match-wins): re-deny credential paths even if
  // they fell under a re-allow, and deny /etc/passwd + /etc/shadow (which live in
  // read-allowed /etc). A directional Grant covering the path lifts its deny.
  for (const sp of sensitivePathsFor("darwin")) {
    if (!sp.modes.includes("read")) continue;
    const uncovered = sp.denyPaths.filter((dp) => !approvedFs.some((t) => pathCovers(t, dp)));
    if (uncovered.length === 0) continue;
    const items = uncovered.map((dp) => `(${sp.denyKind} "${canon(dp)}")`).join(" ");
    lines.push(`(deny file-read* ${items})`);
  }
```

(The write-deny section below — `(deny file-write*)` … carve-out … network — is UNCHANGED. Leave it exactly as slice 1 has it.)

- [ ] **Step 4: Run the unit tests**

Run: `node --import tsx --test packages/sandbox/test/profile.test.ts`
Expected: PASS. (Update any existing profile.test.ts call that passed the old 3-field opts to include `nodePrefix`/`projectRoot`.)

- [ ] **Step 5: Add the Seatbelt effect test (darwin)**

Add to the `describe("SeatbeltSandbox enforcement", …)` block in `packages/sandbox/test/seatbelt.test.ts`:

```typescript
  test("a $HOME read outside the read-allow list is denied; the project tree + a build stay readable", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-read-")));
    const proj = join(home, "app"); mkdirSync(join(proj, "node_modules", "dep"), { recursive: true });
    writeFileSync(join(proj, "node_modules", "dep", "index.js"), "module.exports=1");
    writeFileSync(join(home, "secret.txt"), "TOPSECRET");           // in $HOME, NOT in the allow list
    const cwd = join(proj, "node_modules", "pkg"); mkdirSync(cwd, { recursive: true });
    const r = new SeatbeltSandbox().run(
      `node -e "require('${join(proj, "node_modules", "dep", "index.js")}'); process.stdout.write('DEP_OK'); try{require('fs').readFileSync('${join(home, "secret.txt")}');process.stdout.write('LEAK')}catch(e){process.stdout.write('READ_DENIED')}"`,
      { cwd, approved: [], homeDir: home, projectRoot: proj },
    );
    assert.ok(r.stdout.includes("DEP_OK"), "the project tree must be readable (require resolves)");
    assert.ok(r.stdout.includes("READ_DENIED") && !r.stdout.includes("LEAK"), "a non-allow-listed $HOME read must be denied");
  });
```

- [ ] **Step 6: Run the effect test + regressions**

Run: `node --import tsx --test packages/sandbox/test/seatbelt.test.ts`
Expected: the new test PASSES; existing enforcement tests still pass. NOTE: the slice-1 "credential read surfaces a confirmed violation" test now has the read denied by the *blanket* `$HOME` deny (still EPERM → still confirmed) — confirm it still passes.

- [ ] **Step 7: Commit**

```bash
git add packages/sandbox/src/profile.ts packages/sandbox/test/profile.test.ts packages/sandbox/test/seatbelt.test.ts
git commit -m "feat(phase25s2): Seatbelt \$HOME-read-deny + read-allow list + /etc carve-out (ADR-0038)"
```

---

### Task 5: bwrap `$HOME`-read-deny generator + Linux effect test

**Files:**
- Modify: `packages/sandbox/src/bwrap.ts`
- Test: `packages/sandbox/test/bwrap.test.ts`, `packages/sandbox/test/bubblewrap.test.ts`

**Interfaces:**
- Consumes: `readAllowList` (Task 2); `nodePrefix`/`projectRoot` opts (Task 3).
- Produces: `generateBwrapArgs` masks `$HOME` reads with `--tmpfs "<$HOME>"` (emptying it), then re-binds the read-allow list read-only and re-binds the write-floor's in-`$HOME` paths read-write on top. `pathExists`-gated where a mount point may be absent.

- [ ] **Step 1: Write the failing tests**

Add to `packages/sandbox/test/bwrap.test.ts` (extend `OPTS2` with the new inputs, and reuse `binds`):

```typescript
const OPTS3 = { homeDir: "/home/x", cwd: "/home/x/app/node_modules/pkg", tmpDir: "/tmp/build", nodePrefix: "/home/x/.nvm/versions/node/v24/prefix", projectRoot: "/home/x/app" };

describe("generateBwrapArgs — $HOME-read-deny (Phase 25 Slice 2)", () => {
  test("masks $HOME with a tmpfs, then re-binds the node prefix + project root read-only", () => {
    const args = generateBwrapArgs([], OPTS3);
    assert.ok(binds(args, "--tmpfs").includes("/home/x"), "$HOME is tmpfs-masked (reads denied)");
    const ro = binds(args, "--ro-bind-try"); // node prefix / project root are bound with -try (may be absent)
    assert.ok(ro.includes("/home/x/.nvm/versions/node/v24/prefix"), "node prefix re-bound read-only (node-under-$HOME)");
    assert.ok(ro.includes("/home/x/app"), "project root re-bound read-only (require resolves)");
  });
  test("mount order: $HOME tmpfs, THEN the ro read-allow, THEN the rw cwd on top (cwd stays writable)", () => {
    const args = generateBwrapArgs([], OPTS3);
    const tmpfsHome = args.indexOf("/home/x");                       // --tmpfs <home>
    const roProj = args.indexOf("/home/x/app");                      // --ro-bind-try <projectRoot>
    const rwCwd = args.indexOf("/home/x/app/node_modules/pkg");      // --bind-try <cwd>
    assert.ok(tmpfsHome !== -1 && roProj > tmpfsHome, "ro read-allow comes after the $HOME tmpfs");
    assert.ok(rwCwd > roProj, "the rw cwd bind comes AFTER the ro project bind, so cwd stays writable");
  });
  test("write-deny (slice 1) root is still read-only", () => {
    assert.deepEqual(binds(generateBwrapArgs([], OPTS3), "--ro-bind").slice(0, 1), ["/"]);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/bwrap.test.ts`
Expected: FAIL — no `--tmpfs <home>` / node-prefix / project-root re-binds.

- [ ] **Step 3: Implement the bwrap read-deny**

The mount ORDER is load-bearing (bwrap: later mount wins for an overlapping path). Because `cwd` sits *under* `projectRoot`, the broad read-only `projectRoot` bind must come **before** the narrow read-write `cwd` bind — otherwise the read-only project bind overmounts `cwd` and build writes fail. Correct order: `--ro-bind / /` → `--tmpfs $HOME` (empty it) → read-allow **ro** binds (broad) → write-floor **rw** binds (narrow, on top) → SENSITIVE masks. Replace `generateBwrapArgs` in `packages/sandbox/src/bwrap.ts` with the full restructured version:

```typescript
import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";
import { expandHome, isSafeGrantTarget } from "./deny-set.js";
import { writeAllowFloor } from "./write-floor.js";
import { readAllowList } from "./read-allow.js";

/**
 * Generate `bwrap` argv from a package's APPROVED capabilities (Phase 25).
 * Slice 1: root read-only (`--ro-bind / /`) → writes denied by default, floor +
 * Grants re-bound read-write. Slice 2: `$HOME` reads denied by default — empty it
 * with `--tmpfs` — then re-bind the read-allow list read-only (node prefix so a
 * node-under-$HOME runtime loads its stdlib; project root so `require()` resolves)
 * and re-apply the write floor read-write ON TOP (a broad ro project bind must
 * precede the narrow rw `cwd` bind, or `cwd` becomes read-only). SENSITIVE masks
 * carve out last. `pathExists` gates masks whose mount point may be absent.
 * Pure: same inputs ⇒ same argv.
 */
export function generateBwrapArgs(
  approved: Capability[],
  opts: { homeDir: string; cwd: string; tmpDir: string; nodePrefix: string; projectRoot: string; pathExists?: (p: string) => boolean },
): string[] {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");
  const exists = opts.pathExists ?? (() => true);

  const args = ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"];

  // Slice 2 reads: empty $HOME (deny its reads), then re-expose the read-allow list ro.
  args.push("--tmpfs", opts.homeDir);
  for (const ro of readAllowList({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot })) {
    const target = expandHome(ro, opts.homeDir);
    args.push("--ro-bind-try", target, target); // -try: node-gyp/cache dirs may be absent
  }

  // Slice 1 writes: re-bind the write floor + Grants READ-WRITE on top (narrow wins over
  // the broad ro project bind above; `--dev /dev` already provides an isolated writable /dev,
  // so drop host /dev from the rw binds — re-binding it would re-expose the host device tree).
  const floor = writeAllowFloor({ cwd: opts.cwd, tmpDir: opts.tmpDir });
  const rw = [...floor, ...approvedFs.filter(isSafeGrantTarget)]
    .map((p) => expandHome(p, opts.homeDir))
    .filter((p) => p !== "/dev");
  for (const p of rw) args.push("--bind-try", p, p);

  // SENSITIVE masks — carve-outs applied last (a bwrap tmpfs / ro-bind-devnull mask denies
  // read AND write). Skip an absent mount point (bwrap can't create it under a ro parent).
  for (const sp of sensitivePathsFor("linux")) {
    for (const dp of sp.denyPaths) {
      if (approvedFs.some((t) => pathCovers(t, dp))) continue;
      const target = expandHome(dp, opts.homeDir);
      if (!exists(target)) continue;
      if (sp.denyKind === "subpath") args.push("--tmpfs", target);
      else args.push("--ro-bind", "/dev/null", target);
    }
  }

  if (!hasNetwork) args.push("--unshare-net");
  return args;
}
```

This preserves every slice-1 property (ro root, rw floor, `/dev` exclusion, Grant guard, existence-filtered masks) and adds the read-deny in the correct mount order.

- [ ] **Step 4: Run the unit tests**

Run: `node --import tsx --test packages/sandbox/test/bwrap.test.ts`
Expected: PASS. (Update existing bwrap.test.ts calls to pass `nodePrefix`/`projectRoot`.)

- [ ] **Step 5: Add the bwrap effect test (Linux CI only — containment; report is Seatbelt-only)**

Add to the Linux-gated `describe("BubblewrapSandbox enforcement", …)` in `packages/sandbox/test/bubblewrap.test.ts`:

```typescript
  test("a $HOME read outside the read-allow list is contained; the project tree stays readable", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-read-")));
    const proj = join(home, "app"); mkdirSync(join(proj, "node_modules", "dep"), { recursive: true });
    writeFileSync(join(proj, "node_modules", "dep", "index.js"), "module.exports=1");
    writeFileSync(join(home, "secret.txt"), "TOPSECRET");
    const cwd = join(proj, "node_modules", "pkg"); mkdirSync(cwd, { recursive: true });
    const r = new BubblewrapSandbox().run(
      `node -e "require('${join(proj, "node_modules", "dep", "index.js")}'); process.stdout.write('DEP_OK'); try{require('fs').readFileSync('${join(home, "secret.txt")}');process.stdout.write('LEAK')}catch(e){process.stdout.write('READ_DENIED')}"`,
      { cwd, approved: [], homeDir: home, projectRoot: proj },
    );
    assert.ok(r.stdout.includes("DEP_OK"), "the project tree must be readable");
    // Containment only — bwrap tmpfs → ENOENT, which classifyViolation does not classify
    // (the accepted Seatbelt/bwrap telemetry asymmetry; report is Seatbelt-only, ADR-0023).
    assert.ok(r.stdout.includes("READ_DENIED") && !r.stdout.includes("LEAK"), "the non-allow-listed $HOME read must be contained");
  });
```

- [ ] **Step 6: Run the unit tests (darwin) + note the Linux gate**

Run: `node --import tsx --test packages/sandbox/test/bwrap.test.ts`
Expected: PASS (pure argv tests run on darwin). The `bubblewrap.test.ts` effect test skips on darwin and runs on Linux CI. Do not attempt to run bwrap on darwin.

- [ ] **Step 7: Commit**

```bash
git add packages/sandbox/src/bwrap.ts packages/sandbox/test/bwrap.test.ts packages/sandbox/test/bubblewrap.test.ts
git commit -m "feat(phase25s2): bwrap \$HOME-read-deny via tmpfs + read-allow re-binds (ADR-0038)"
```

---

### Task 6: ADR-0038 read-slice update + docs + full gate

**Files:**
- Modify: `docs/adr/0038-sandbox-default-deny.md`, `docs/adr/README.md`, `ARCHITECTURE.md`, `CLAUDE.md`, `AGENTS.md`, `CONTEXT.md` (if a term sharpened)

- [ ] **Step 1: Update ADR-0038 with the read slice**

Change the ADR's Status/title framing from "(write slice)" to cover both slices, and add a "Decision (Slice 2 — reads)" section documenting: `$HOME`-read-deny + read-allow list (system paths, `nodeInstallPrefix(execPath)`, `resolveProjectRoot(cwd, INIT_CWD)`, `~/.node-gyp`, `~/.cache`); `/etc/passwd`/`/etc/shadow` stay denied via the existing SENSITIVE read carve-out; the two new sandbox inputs; the Seatbelt `(deny file-read* subpath $HOME)` + re-allow and bwrap `--tmpfs $HOME` + re-bind mechanics; and the **accepted telemetry asymmetry** — Seatbelt read-deny → EPERM → reported; bwrap tmpfs → ENOENT → contained-but-not-reported (an extension of ADR-0023, now confirmed by CI). Note that this **completes** the ADR-0016/0017/0018 supersession (reads + writes both inverted).

- [ ] **Step 2: Update the doc set**

- `docs/adr/README.md`: extend the ADR-0038 / Phase 25 entry to note both slices landed.
- `ARCHITECTURE.md`: extend the Phase 25 section with the read slice (both backends, the read-allow list, the two inputs, the telemetry asymmetry).
- `CLAUDE.md` **and** `AGENTS.md`: add a Phase 25 Slice 2 paragraph after the Slice 1 one in each; update the `CLAUDE.md` test-count comment with the real number from Step 3 and extend the per-phase enumeration.
- `CONTEXT.md`: the sandbox-capability terms already cover this; add a **Read-allow list** / **Node install prefix** entry only if it sharpens the model.

- [ ] **Step 3: Full gate**

Run: `npm run build` → clean.
Run: `npm test` → green; record the actual totals (baseline 640 + the new Slice 2 tests). The 2 skips remain. Record the count for `CLAUDE.md`.

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0038-sandbox-default-deny.md docs/adr/README.md ARCHITECTURE.md CLAUDE.md AGENTS.md CONTEXT.md
git commit -m "docs(phase25s2): ADR-0038 read slice; ARCHITECTURE/CLAUDE/AGENTS"
```

---

## Self-review notes

- **Spec coverage (Slice 2):** full `$HOME`-read-deny + allow-list (Tasks 2/4/5), `execPath` node prefix + `INIT_CWD` project root as new inputs (Tasks 2/3), `/etc/passwd` via the retained SENSITIVE read carve-out (Task 4), Seatbelt + bwrap mechanics (Tasks 4/5), accepted telemetry asymmetry surfaced in the effect tests + ADR (Tasks 5/6), probe gate first (Task 1). Write-deny (slice 1) explicitly untouched.
- **Type consistency:** `readAllowList({nodePrefix, projectRoot})`, `nodeInstallPrefix(execPath)`, `resolveProjectRoot(cwd, initCwd)` match across Tasks 2→3→4→5; generator opts `{homeDir, cwd, tmpDir, nodePrefix, projectRoot}` (+ bwrap `pathExists`) match Tasks 3/4/5; `Sandbox.run(..., { …, projectRoot? })` matches Task 3 and the shim/runner call sites.
- **Slice-1 learnings carried in:** bwrap mount points created on a writable `--tmpfs $HOME` (avoids the ro-parent-mkdir abort); `--ro-bind-try`/`--bind-try` for maybe-absent cache dirs; containment-asserted-both / report-darwin-only effect tests (the enforce-test pattern); firmlink canonicalization on every emitted Seatbelt path.
- **Probe-first honored:** Task 1 gates the read-allow list (esp. node-under-`$HOME`) before Tasks 2/4/5 lock it.
- **Not in scope:** the write slice (merged); any change to `computeDenySet`/`classifyViolation` (read attribution stays SENSITIVE-based — credential reads confirmed on Seatbelt, non-sensitive `$HOME` reads contained-but-ambient, consistent with slice-1 writes).
