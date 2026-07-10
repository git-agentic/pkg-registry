# Landlock Linux exec floor — Phase 2 (shippable) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce a real Linux exec floor — run each lifecycle script under a Landlock exec-allow ruleset (via a from-source helper inside bwrap) that denies exec of any binary outside the floor — with a fail-open fallback to Phase 29's advisory floor, closing #8.

**Architecture:** A tiny from-source C helper (`landlock-exec`, compiled by a `npm run build` step, no install hook) is prepended inside bwrap: `bwrap … landlock-exec --allow <floor> -- /bin/sh -c <script>`. It's used only when the binary exists AND a cached `--check` ABI probe confirms Landlock; otherwise the exact Phase 29 path runs plus a one-time advisory notice. `computeDenySet`/`classifyViolation` gain a Landlock-floor mode so a floor-outside exec denial attributes as a `confirmed` violation. macOS/Seatbelt is untouched.

**Tech Stack:** C (libc `syscall()`, no kernel headers), TypeScript ESM (NodeNext, `.js` specifiers), `node:test` + `tsx`, Linux `bwrap` + Landlock, `gh` CLI for CI validation.

**Spec:** `docs/superpowers/specs/2026-07-10-landlock-exec-floor-phase2-design.md`

## Global Constraints

- **`build-native.mjs` must no-op, never fail, on non-Linux or when `cc` is absent** — skip-with-log, exit 0 (else it breaks `npm run build` on the macOS dev host).
- **macOS/Seatbelt path byte-behavior-unchanged**: `generateProfile`, the darwin branches of `computeDenySet`/`classifyViolation`, `execAllowFloor`'s macOS use — untouched.
- **Phase 29 fallback path unchanged when Landlock is inactive**: the carve-out + advisory floor + `linuxCarveMode` classifier behavior must be byte-identical when the helper is not active.
- **Fail-open detection contract**: the helper is used iff `dist/landlock-exec` exists AND `landlock-exec --check` exits 0. Any negative ⇒ Phase 29 path. Never prepend the helper on an unverified host (it would exit 3 and every lifecycle script would fail).
- Generators/classifier stay **pure** (no fs); detection lives only in `BubblewrapSandbox`.
- No new npm/native *dependency* — the helper is first-party source we compile.
- ESM only; `.js` import specifiers. Build with `npx tsc --build --force packages/sandbox` (don't `rm dist/` — EPERM on this mount). Single test file: `node --import tsx --test packages/sandbox/test/<f>.test.ts`.
- The enforcement (effect) path is Linux-CI-only; generator/deny-set/classifier logic is hermetic + platform-neutral (runs on macOS). Commit trailer: `Claude-Session: https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf`.

---

### Task 1: Promote the helper + add `--check` mode

**Files:**
- Create: `packages/sandbox/native/landlock-exec.c` (promoted from the `landlock-spike-spec` branch, then extended)

**Interfaces:**
- Produces: the `landlock-exec` binary contract. `landlock-exec --check` → exit `0` (Landlock ABI ≥ 1 available) / `3` (unavailable), no ruleset, no execve. `landlock-exec --allow <path>… -- <cmd>…` → applies the exec floor, execs the command. Task 5 compiles it; Task 6 detects via `--check` and invokes it.

- [ ] **Step 1: Create the Phase 2 branch and promote the spike helper**

```bash
git checkout main && git pull --ff-only && git checkout -b phase2-landlock-floor
git show landlock-spike-spec:packages/sandbox/native/landlock-exec.c > packages/sandbox/native/landlock-exec.c
```

(The spike helper is already reviewed for syscall/ABI/struct correctness. Confirm it exists: `head -6 packages/sandbox/native/landlock-exec.c` shows the `landlock-exec:` header comment.)

- [ ] **Step 2: Add the `--check` mode** — insert at the very top of `main()`, immediately after `int main(int argc, char **argv) {`, before the `--allow`/`--` parsing:

```c
  /* --check: probe the Landlock ABI and exit 0 (available) / 3 (unavailable),
   * doing NO ruleset setup and NO execve. Used by the caller's pre-check so
   * detection is not failure-triggered. */
  if (argc == 2 && strcmp(argv[1], "--check") == 0) {
    long abi = ll_create(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    return abi >= 1 ? 0 : 3;
  }
```

- [ ] **Step 3: Make a missing `--allow` path non-silent under debug** — find `if (pfd < 0) continue;` in the `--allow` loop and replace it with:

```c
    if (pfd < 0) {
      if (getenv("SENTINEL_DEBUG")) fprintf(stderr, "landlock-exec: skip unopenable --allow %s: %s\n", allows[a], strerror(errno));
      continue; /* a missing floor entry is simply not granted (merged-usr tolerance) */
    }
```

- [ ] **Step 4: Eyeball-check (no local compile — Linux-only C; CI compiles it in Task 5)**

Confirm: `--check` runs BEFORE any parsing and returns 0/3 without execve; the debug log is `getenv("SENTINEL_DEBUG")`-gated (silent by default); nothing else in the helper changed. Do NOT run `cc` on macOS.

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/native/landlock-exec.c
git commit -m "feat(sandbox): promote landlock-exec helper + --check ABI-probe mode (Phase 2, closes #8 groundwork)"
```

---

### Task 2: `linuxExecFloor` (exec floor + library/linker dirs)

**Files:**
- Modify: `packages/sandbox/src/exec-floor.ts` (add `linuxExecFloor`)
- Modify: `packages/sandbox/src/index.ts` (export it)
- Test: `packages/sandbox/test/exec-floor.test.ts` (append)

**Interfaces:**
- Consumes: existing `execAllowFloor({nodePrefix, projectRoot}): string[]`.
- Produces: `linuxExecFloor(opts: { nodePrefix: string; projectRoot: string }): string[]` = `execAllowFloor` entries **plus** `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`. Tasks 3 and 6 use it.

- [ ] **Step 1: Write the failing test** (append to `packages/sandbox/test/exec-floor.test.ts`)

```ts
import { linuxExecFloor } from "../src/exec-floor.js"; // add to the existing import if grouped

describe("linuxExecFloor", () => {
  const floor = linuxExecFloor({ nodePrefix: "/usr", projectRoot: "/work/pkg" });
  test("includes the exec floor entries plus the library/linker dirs", () => {
    for (const p of ["/bin", "/usr/bin", "/usr", "/work/pkg", "/lib", "/lib64", "/usr/lib", "/usr/lib64"]) {
      assert.ok(floor.includes(p), `linux floor must include ${p}`);
    }
  });
  test("the lib dirs are the Landlock-specific addition (FS_EXECUTE gates library mmap)", () => {
    const base = new Set(["/lib", "/lib64", "/usr/lib", "/usr/lib64"]);
    for (const p of base) assert.ok(floor.includes(p));
  });
  test("deterministic", () => {
    assert.deepEqual(floor, linuxExecFloor({ nodePrefix: "/usr", projectRoot: "/work/pkg" }));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/exec-floor.test.ts`
Expected: FAIL — `linuxExecFloor` not exported.

- [ ] **Step 3: Implement** — append to `packages/sandbox/src/exec-floor.ts`:

```ts
/**
 * The Linux exec floor: the shared `execAllowFloor` PLUS the dynamic-linker and
 * shared-library directories. Landlock's `LANDLOCK_ACCESS_FS_EXECUTE` gates
 * `mmap(PROT_EXEC)` as well as `execve`, so a dynamically-linked binary's ELF
 * interpreter (`/lib64/ld-linux-*`) and its libraries must be exec-granted or the
 * binary can't start — verified by the Phase 2 feasibility spike (the first CI run
 * failed precisely because these were omitted). macOS does NOT need these (dylib
 * loading is file-read there, not process-exec), so they live here, not in
 * `execAllowFloor`. Pure. The macOS-only entries `execAllowFloor` returns
 * (`/Library/Developer`, …) are harmless on Linux — the helper skips an `--allow`
 * path that doesn't exist.
 */
export function linuxExecFloor(opts: { nodePrefix: string; projectRoot: string }): string[] {
  return [...execAllowFloor(opts), "/lib", "/lib64", "/usr/lib", "/usr/lib64"];
}
```

Add the export to `packages/sandbox/src/index.ts`:

```ts
export { execAllowFloor, linuxExecFloor } from "./exec-floor.js";
```

(If `exec-floor.ts` isn't already exported from index, add this line; if `execAllowFloor` is already exported, extend that line.)

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/exec-floor.test.ts`
Expected: PASS.

- [ ] **Step 5: Build + commit**

```bash
npx tsc --build --force packages/sandbox
git add packages/sandbox/src/exec-floor.ts packages/sandbox/src/index.ts packages/sandbox/test/exec-floor.test.ts
git commit -m "feat(sandbox): linuxExecFloor — exec floor + library/linker dirs for Landlock (Phase 2)"
```

---

### Task 3: `computeDenySet` Landlock-floor mode

**Files:**
- Modify: `packages/sandbox/src/deny-set.ts` (the `DenySet` interface; the Linux branch of `computeDenySet`)
- Test: `packages/sandbox/test/deny-set.test.ts` (append)

**Interfaces:**
- Consumes: `linuxExecFloor` (Task 2).
- Produces: `computeDenySet` opts gain `landlockFloor?: boolean`. `DenySet` gains `execFloorMode?: "linux-landlock"`. When `landlockFloor` is true (and `nodePrefix`/`projectRoot` present), the Linux branch returns `execDenied: true`, `execDeniedPaths` (carve-out, unchanged), `execAllowedPaths: linuxExecFloor(...)`, and `execFloorMode: "linux-landlock"`. Default (opt absent/false) ⇒ the exact Phase 29 shape. Task 4's classifier reads `execFloorMode`/`execAllowedPaths`; Task 6 passes `landlockFloor`.

- [ ] **Step 1: Write the failing tests** (append to `packages/sandbox/test/deny-set.test.ts`; reuse the `L`/`procCap` helpers the Phase 29 Linux tests use)

```ts
describe("computeDenySet — Linux Landlock floor mode (Phase 2)", () => {
  test("landlockFloor populates execAllowedPaths (linuxExecFloor) + sets execFloorMode + execDenied", () => {
    const ds = computeDenySet([], { ...L, landlockFloor: true });
    assert.equal(ds.execFloorMode, "linux-landlock");
    assert.equal(ds.execDenied, true);
    assert.ok(ds.execAllowedPaths!.includes("/bin"), "floor has /bin");
    assert.ok(ds.execAllowedPaths!.includes("/lib64"), "floor has the lib dirs");
    assert.ok(ds.execAllowedPaths!.includes("/work/pkg"), "floor has projectRoot");
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/curl")), "carve-out literals still present");
  });
  test("execDenied is true even when all carve-out is granted away (the floor still denies)", () => {
    const ds = computeDenySet([procCap("*")], { ...L, landlockFloor: true });
    assert.equal(ds.execDenied, true);
    assert.deepEqual(ds.execDeniedPaths, []);
    assert.ok((ds.execAllowedPaths?.length ?? 0) > 0);
  });
  test("without landlockFloor: EXACT Phase 29 shape (no floor, no execFloorMode)", () => {
    const ds = computeDenySet([], L);
    assert.equal(ds.execFloorMode, undefined);
    assert.equal(ds.execAllowedPaths, undefined);
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/curl")));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/deny-set.test.ts`
Expected: existing PASS; new block FAILS (`execFloorMode` undefined).

- [ ] **Step 3: Implement** — in `packages/sandbox/src/deny-set.ts`:

Add to the `DenySet` interface (beside `execDenied?`):

```ts
  /** "linux-landlock" when the Linux exec FLOOR is enforced (Landlock helper active); absent otherwise */
  execFloorMode?: "linux-landlock";
```

Add `landlockFloor?: boolean` to the `computeDenySet` opts type:

```ts
  opts: { homeDir: string; platform: "darwin" | "linux"; nodePrefix?: string; projectRoot?: string; cwd?: string; tmpDir?: string; landlockFloor?: boolean },
```

Add the import at the top:

```ts
import { linuxExecFloor } from "./exec-floor.js";
```

Replace the Linux branch's final `return`:

```ts
    return { ...base, execDenied: lDenied.length > 0, execDeniedPaths: lDenied };
```

with:

```ts
    // Phase 2: when the Landlock exec FLOOR is active, model a real floor so
    // classifyViolation can attribute a floor-outside exec denial. Otherwise the
    // exact Phase 29 shape (carve-out only, no floor).
    if (opts.landlockFloor && opts.nodePrefix && opts.projectRoot) {
      return {
        ...base,
        execDenied: true,
        execDeniedPaths: lDenied,
        execAllowedPaths: linuxExecFloor({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot }),
        execFloorMode: "linux-landlock",
      };
    }
    return { ...base, execDenied: lDenied.length > 0, execDeniedPaths: lDenied };
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/deny-set.test.ts`
Expected: PASS (all — the Phase 29 Linux tests and the darwin non-drift test unchanged).

- [ ] **Step 5: Build + commit**

```bash
npx tsc --build --force packages/sandbox
git add packages/sandbox/src/deny-set.ts packages/sandbox/test/deny-set.test.ts
git commit -m "feat(sandbox): computeDenySet Landlock-floor mode (execFloorMode + populated floor) (Phase 2)"
```

---

### Task 4: `classifyViolation` Landlock-floor branch

**Files:**
- Modify: `packages/sandbox/src/violation.ts` (add a branch gated on `execFloorMode === "linux-landlock"`)
- Test: `packages/sandbox/test/violation.test.ts` (append)

**Interfaces:**
- Consumes: `DenySet.execFloorMode` / `execAllowedPaths` / `execDeniedPaths` (Task 3); existing `firstLinuxExecLine`, `LINUX_EXEC_PATH`, `pathCovers`, `excerpt`.
- Produces: a `confirmed` `process` violation for a Landlock floor-outside exec denial (`deniedResource: "exec-floor-deny"`) and for a masked carve-out literal (`deniedResource` = the literal). Task 6's effect test asserts on it.

- [ ] **Step 1: Write the failing tests** (append to `packages/sandbox/test/violation.test.ts`)

```ts
const LL_DS = {
  deniedPaths: ["/home/test/.ssh"],
  networkDenied: true,
  execDenied: true,
  execFloorMode: "linux-landlock" as const,
  execAllowedPaths: ["/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib", "/usr/lib64", "/work/pkg"],
  execDeniedPaths: ["/usr/bin/curl", "/bin/curl"],
};
const failLL = (stderr: string) => ({ exitCode: 126, stdout: "", stderr });

describe("classifyViolation — Linux Landlock floor mode (Phase 2)", () => {
  test("a floor-OUTSIDE exec denial (dropped /tmp binary) is confirmed exec-floor-deny", () => {
    const v = classifyViolation(failLL("/bin/sh: 1: /tmp/spikestash/payload: Permission denied"), LL_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "exec-floor-deny");
    assert.equal(v?.target, "/tmp/spikestash/payload");
  });
  test("a masked carve-out literal is confirmed on the literal (curl under an allowed /usr/bin)", () => {
    const v = classifyViolation(failLL("/bin/sh: 1: /usr/bin/curl: Permission denied"), LL_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "/usr/bin/curl");
  });
  test("a denial UNDER the floor is ambient null (exec allowed there)", () => {
    assert.equal(classifyViolation(failLL("/bin/sh: 1: /usr/bin/make: Permission denied"), LL_DS), null);
  });
  test("does not fire without execFloorMode (a macOS DenySet is untouched)", () => {
    const macDs = { deniedPaths: [], networkDenied: true, execDenied: true, execAllowedPaths: ["/bin"], execDeniedPaths: ["/usr/bin/curl"] };
    // a macOS 'Permission denied' fs line must NOT be classified as an exec-floor violation
    assert.equal(classifyViolation(failLL("/bin/sh: /home/x/.ssh/id: Permission denied"), macDs as any)?.deniedResource, undefined);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/violation.test.ts`
Expected: existing PASS; new block FAILS.

- [ ] **Step 3: Implement** — in `packages/sandbox/src/violation.ts`, add a branch **immediately after** the existing `linuxCarveMode` block (the one ending `// not a masked-literal exec → fall through …`) and before the macOS exec branch:

```ts
  // Linux Landlock FLOOR mode (Phase 2): a real exec floor is modeled
  // (execFloorMode set, execAllowedPaths populated). A denied exec surfaces as the
  // dash EACCES shape ("/bin/sh: <n>: <path>: Permission denied"). Attribute: a
  // masked carve-out literal → confirmed on the literal; a floor-OUTSIDE target →
  // confirmed "exec-floor-deny" (the dropped-binary case); a floor-inside target →
  // ambient null. Gated on execFloorMode so a macOS DenySet (which never sets it)
  // is untouched, and its "Operation not permitted" shape stays with the macOS
  // branch below.
  if (denySet.execFloorMode === "linux-landlock") {
    const line = firstLinuxExecLine(stderr);
    const target = line ? LINUX_EXEC_PATH.exec(line)?.[1] ?? null : null;
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

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/violation.test.ts`
Expected: PASS (all — macOS exec, network, fs, swallowed-denial, and Phase 29 `linuxCarveMode` tests untouched).

- [ ] **Step 5: Build + full sandbox suite + commit**

```bash
npx tsc --build --force packages/sandbox
node --import tsx --test packages/sandbox/test/*.test.ts   # regression: macOS + Phase 29 branches green
git add packages/sandbox/src/violation.ts packages/sandbox/test/violation.test.ts
git commit -m "feat(sandbox): classifyViolation Landlock-floor mode — confirm a floor-outside exec denial (Phase 2)"
```

---

### Task 5: `build-native.mjs` compile step (no-op-not-fail off Linux)

**Files:**
- Create: `packages/sandbox/scripts/build-native.mjs`
- Modify: root `package.json` (the `build` script)
- Modify: `.gitignore` (ensure `packages/sandbox/dist/landlock-exec` isn't tracked)
- Test: `packages/sandbox/test/build-native.test.ts` (the macOS no-op behavior is hermetic)

**Interfaces:**
- Consumes: `packages/sandbox/native/landlock-exec.c` (Task 1).
- Produces: `packages/sandbox/dist/landlock-exec` on Linux+cc; a no-op (exit 0) otherwise. Task 6 detects the binary at `dist/landlock-exec`.

- [ ] **Step 1: Write the failing test** (the no-op-on-macOS behavior, runnable on the dev host)

```ts
// packages/sandbox/test/build-native.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, "..", "scripts", "build-native.mjs");

describe("build-native.mjs", () => {
  test("exits 0 and does not throw when run (no-op on non-Linux/no-cc)", () => {
    const r = spawnSync(process.execPath, [script], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    // On darwin it must print a skip notice, never error out.
    if (process.platform !== "linux") assert.match(r.stdout + r.stderr, /skip|not linux|no cc/i);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/build-native.test.ts`
Expected: FAIL — `build-native.mjs` doesn't exist (spawn ENOENT → non-zero).

- [ ] **Step 3: Implement** — create `packages/sandbox/scripts/build-native.mjs`:

```js
// Compile the Landlock helper from source as part of `npm run build`. Linux + cc
// only; a no-op (exit 0) everywhere else so it never breaks the build. This is
// deliberately a build STEP, not a postinstall hook (adding install-time script
// execution to a tool that guards against exactly that would be a posture violation).
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..", "native", "landlock-exec.c");
const outDir = join(here, "..", "dist");
const out = join(outDir, "landlock-exec");

if (process.platform !== "linux") {
  console.log(`[build-native] skip: not linux (${process.platform}) — advisory floor will be used`);
  process.exit(0);
}
const cc = spawnSync("cc", ["--version"], { encoding: "utf8" });
if (cc.error || cc.status !== 0) {
  console.log("[build-native] skip: no cc on PATH — advisory floor will be used");
  process.exit(0);
}
if (!existsSync(src)) {
  console.log(`[build-native] skip: source not found at ${src}`);
  process.exit(0);
}
if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
const r = spawnSync("cc", ["-O2", "-o", out, src], { stdio: "inherit" });
if (r.status !== 0) {
  console.log("[build-native] skip: compile failed — advisory floor will be used");
  process.exit(0);
}
console.log(`[build-native] built ${out}`);
```

- [ ] **Step 4: Wire it into the build** — in the root `package.json`, change:

```json
    "build": "tsc --build",
```

to:

```json
    "build": "tsc --build && node packages/sandbox/scripts/build-native.mjs",
```

- [ ] **Step 5: Gitignore the built binary** — check whether `packages/sandbox/dist/` is already ignored:

```bash
git check-ignore packages/sandbox/dist/landlock-exec && echo "already ignored" || echo "NEED to add"
```

If it prints `NEED to add`, append to `.gitignore`:

```
packages/sandbox/dist/landlock-exec
```

(If `dist/` is already ignored repo-wide, do nothing.)

- [ ] **Step 6: Run to verify it passes (on macOS: no-op)**

Run: `node --import tsx --test packages/sandbox/test/build-native.test.ts`
Expected: PASS (exit 0, skip notice on darwin).
Also run `npm run build` and confirm it still completes clean on macOS (the native step prints a skip line, exit 0).

- [ ] **Step 7: Commit**

```bash
git add packages/sandbox/scripts/build-native.mjs package.json .gitignore packages/sandbox/test/build-native.test.ts
git commit -m "feat(sandbox): build-native.mjs — compile landlock-exec in npm run build (Linux+cc only, no-op else) (Phase 2)"
```

---

### Task 6: `BubblewrapSandbox` wiring + fail-open detection + Linux effect tests

**Files:**
- Modify: `packages/sandbox/src/bubblewrap.ts`
- Test: `packages/sandbox/test/bubblewrap.test.ts` (append Linux-gated effect tests)

**Interfaces:**
- Consumes: Task 1's `--check`, Task 2's `linuxExecFloor`, Task 3's `landlockFloor` opt, Task 4's classifier, Task 5's `dist/landlock-exec`.
- Produces: end-to-end enforced Linux floor with fail-open fallback.

- [ ] **Step 1: Implement the wiring** — in `packages/sandbox/src/bubblewrap.ts`, add imports and module-level detection, and thread it through `run()`.

Add to imports:

```ts
import { linuxExecFloor } from "./exec-floor.js";
```

Add module-level (after the `NS_FAILURE` const, before the class):

```ts
/** Path to the compiled Landlock helper, a sibling of this module in dist/. */
function landlockHelperPath(): string {
  return fileURLToPath(new URL("./landlock-exec", import.meta.url));
}

let landlockActiveCache: boolean | undefined;
let advisoryNoticeShown = false;

/** Fail-open, pre-checked: the helper is active iff it exists AND `--check` (ABI probe)
 * exits 0. Cached once. Any negative ⇒ Phase 29 advisory path. Never prepend the helper
 * unverified — it exits 3 and would fail every lifecycle script on a Landlock-less host. */
function landlockActive(): boolean {
  if (landlockActiveCache !== undefined) return landlockActiveCache;
  const helper = landlockHelperPath();
  if (!existsSync(helper)) { landlockActiveCache = false; return false; }
  const r = spawnSync(helper, ["--check"], { encoding: "utf8" });
  landlockActiveCache = !r.error && r.status === 0;
  return landlockActiveCache;
}
```

Add `fileURLToPath` to the `node:url` import (add the import if absent):

```ts
import { fileURLToPath } from "node:url";
```

In `run()`, replace the `const args = [ …generateBwrapArgs(…), "/bin/sh", "-c", cmd ]` construction and the `computeDenySet(…)` call. Specifically, after computing `generateBwrapArgs(...)` (keep that call unchanged), build the inner command and thread `landlockFloor`:

```ts
    const useLandlock = landlockActive();
    const nodePrefix = nodeInstallPrefix(process.execPath);
    const projectRoot = opts.projectRoot ?? opts.cwd;

    if (!useLandlock && !advisoryNoticeShown) {
      advisoryNoticeShown = true;
      process.stderr.write(
        "sentinel: Landlock exec floor unavailable on this host — advisory floor active " +
        "(a dropped binary can exec but stays filesystem+network confined). " +
        "Build with a C compiler on Linux to enable the enforced floor.\n",
      );
    }

    const inner = useLandlock
      ? [landlockHelperPath(), ...linuxExecFloor({ nodePrefix, projectRoot }).flatMap((p) => ["--allow", p]), "--", "/bin/sh", "-c", cmd]
      : ["/bin/sh", "-c", cmd];

    const args = [
      ...generateBwrapArgs(opts.approved, {
        homeDir: opts.homeDir, cwd: opts.cwd, tmpDir: tmpdir(), pathExists: existsSync, realpath: safeRealpath,
        nodePrefix, projectRoot,
      }),
      ...inner,
    ];
```

And change the `computeDenySet` call to pass `landlockFloor`:

```ts
    const denySet = computeDenySet(opts.approved, {
      homeDir: opts.homeDir, platform: "linux",
      nodePrefix, projectRoot, cwd: opts.cwd, tmpDir: tmpdir(),
      landlockFloor: useLandlock,
    });
```

(The `spawnSync("bwrap", args, …)`, the error/NS_FAILURE handling, and the `classifyViolation` call are unchanged.)

- [ ] **Step 2: Build + hermetic suite (macOS: BubblewrapSandbox is Linux-gated, effect tests skip)**

Run: `npx tsc --build --force packages/sandbox && node --import tsx --test packages/sandbox/test/*.test.ts`
Expected: builds clean; all hermetic tests pass; the Linux effect tests skip on darwin.

- [ ] **Step 3: Write the Linux effect tests** (append inside the existing Linux-gated `describe("BubblewrapSandbox …", { skip: !linux … }, …)` block in `bubblewrap.test.ts`; benign probes only). These run in CI where `dist/landlock-exec` was built by `npm run build`.

These tests require the compiled helper. Add near the top of the file (once):

```ts
import { fileURLToPath } from "node:url";
// dist sibling of the compiled bubblewrap.js; in the source tree the helper lands in
// packages/sandbox/dist/landlock-exec after `npm run build`.
const HELPER_BUILT = existsSync(fileURLToPath(new URL("../dist/landlock-exec", import.meta.url)));
const skipNoHelper = HELPER_BUILT ? false : "requires the built landlock-exec helper (cc on Linux)";
```

```ts
  test("Landlock floor: a dropped /tmp binary is denied and surfaces a confirmed process violation", { skip: skipNoHelper }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-home-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const stash = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-stash-")));
    const marker = join(stash, "marker.txt");
    const cmd = `printf '#!/bin/sh\\necho PWNED > "${marker}"\\n' > "${stash}/payload" && chmod +x "${stash}/payload" && "${stash}/payload"`;
    const res = new BubblewrapSandbox().run(cmd, { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    assert.ok(existsSync(join(stash, "payload")), "payload write must succeed (writable location)");
    assert.ok(!existsSync(marker), "the dropped binary must NOT have executed (Landlock floor)");
    assert.notEqual(res.exitCode, 0);
    assert.equal(res.violation?.kind, "process");
    assert.equal(res.violation?.confidence, "confirmed");
  });

  test("Landlock floor: a floor binary (node) and a node_modules/.bin shim still run", { skip: skipNoHelper }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-pos-")));
    const proj = join(home, "proj"); mkdirSync(join(proj, "node_modules", ".bin"), { recursive: true });
    const shim = join(proj, "node_modules", ".bin", "hello");
    writeFileSync(shim, "#!/bin/sh\necho SHIM-OK\n", { mode: 0o755 });
    const res = new BubblewrapSandbox().run(`node -e "console.log('NODE-OK')" && "${shim}"`, { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    assert.equal(res.exitCode, 0, res.stderr);
    assert.match(res.stdout, /NODE-OK/);
    assert.match(res.stdout, /SHIM-OK/);
  });
```

- [ ] **Step 4: Commit, push, validate on Linux CI**

```bash
git add packages/sandbox/src/bubblewrap.ts packages/sandbox/test/bubblewrap.test.ts
git commit -m "feat(sandbox): wire Landlock floor into BubblewrapSandbox — fail-open --check detection + advisory fallback (Phase 2)"
git push -u origin phase2-landlock-floor
```

Open a PR (CI runs the main `ci.yml` on the branch, which `npm run build`s the helper, then `npm test` runs the effect tests):

```bash
gh pr create --repo git-agentic/pkg-registry --base main --head phase2-landlock-floor --title "Phase 2: Landlock Linux exec floor (closes #8)" --body "Enforced Linux exec floor via a from-source Landlock helper; fail-open to the Phase 29 advisory floor. See docs/superpowers/specs/2026-07-10-landlock-exec-floor-phase2-design.md. https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf"
gh pr checks <PR#> --repo git-agentic/pkg-registry --watch || true
```

- [ ] **Step 5: Confirm the effect tests actually ran (helper was built) on CI**

Read the build-test job log; confirm `[build-native] built …/landlock-exec` appears (not a skip), and the two new effect tests passed on both Node 22 and 24. If the log shows `[build-native] skip: no cc`, the runner lacked `cc` — GitHub `ubuntu-latest` ships gcc, so this shouldn't happen; if it does, report it (the effect tests would have exercised the fallback path, not the floor). Record the exact `npm test` count for Task 7.

```bash
gh run view <run-id> --repo git-agentic/pkg-registry --log | grep -E "build-native|PWNED|SHIM-OK|NODE-OK|Landlock floor|tests [0-9]|pass [0-9]"
```

---

### Task 7: ADR + docs + close #8 + finish

**Files:**
- Create: `docs/adr/0044-landlock-linux-exec-floor.md`
- Modify: `ARCHITECTURE.md` (§3.6), `sentinel-threat-model.md` (§3.9 + §4), `README.md` (sandbox section), `CLAUDE.md` (Phase 3 note + a Phase 2/Landlock paragraph + test count)

- [ ] **Step 1: Write ADR-0044** (match the house header style — `**Status:**`/`**Date:**` lines, extends/supersedes as body prose; check `docs/adr/0043-*.md`):

```markdown
# ADR-0044: Landlock Linux exec floor — enforced where available, advisory otherwise

**Status:** Accepted (Phase 2 / Landlock)
**Date:** 2026-07-10

Follows ADR-0042 (macOS exec floor) and ADR-0043 (Linux carve-out + advisory floor);
supersedes ADR-0043's advisory-floor default only where Landlock is available. Closes
issue #8 — a cross-platform exec floor now exists (macOS Seatbelt + Linux Landlock).

## Context

ADR-0043 shipped the Linux exfil-tool carve-out in pure TypeScript but left the exec
*floor* advisory because bwrap cannot `noexec`. A feasibility spike proved Landlock's
`LANDLOCK_ACCESS_FS_EXECUTE` enforces a path-based exec floor inside bwrap on
ubuntu-latest, unprivileged (`no_new_privs`, which bwrap sets), inherited across
`execve`. Node has no syscall API, so this requires a first-party compiled helper — a
deliberate, bounded exception to the repo's zero-native-dependency posture, chosen
because it is the only route to a real Linux floor.

## Decision

A ~90-line self-contained C helper (`packages/sandbox/native/landlock-exec.c`, inline
Landlock uapi, no kernel headers) applies an exec-allow ruleset for the floor and execs
the script, invoked inside bwrap: `bwrap … landlock-exec --allow <floor> -- /bin/sh -c
<script>`. It is **compiled from source by a `npm run build` step** (`build-native.mjs`)
— NOT a `postinstall` hook (install-time script execution is the very thing Sentinel
guards against) and NOT a lazy runtime compile (writing-then-exec'ing a binary on the
containment path). The step is a no-op (exit 0) on non-Linux / no-`cc`.

The Linux floor is `execAllowFloor` **plus** `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`
— `FS_EXECUTE` gates the dynamic linker + library `mmap`, unlike the macOS floor (the
spike's first CI run failed precisely on this).

**Fail-open, pre-checked detection:** the helper is used iff it exists AND
`landlock-exec --check` (ABI probe) exits 0; anything else falls back to the Phase 29
advisory floor with a one-time notice. `computeDenySet`/`classifyViolation` gain a
`linux-landlock` floor mode so a floor-outside exec denial (the dash `EACCES` shape
`/bin/sh: <n>: <path>: Permission denied`) attributes as a `confirmed` violation. The
Phase 29 `/dev/null` carve-out stays (Landlock is allow-list-only and can't deny a
literal under an allowed dir). macOS/Seatbelt is untouched.

## Consequences

- A dropped binary anywhere outside the floor is kernel-denied on Linux where Landlock
  + the helper are available — closing the gap ADR-0043 documented as advisory.
- Hosts without Landlock (old kernel / LSM disabled) or without `cc` at build run under
  the Phase 29 advisory floor — no availability regression, one honest notice.
- A first-party compiled helper enters the tree (built from source, auditable, not a
  package dependency). Recorded as a bounded, deliberate posture exception.
- `native` stays advisory on both platforms (unchanged).

## Rejected alternatives

- `postinstall` hook / lazy runtime compile — posture violations (see Decision).
- Prebuilt per-arch binaries — opaque binary in a supply-chain tool.
- Failure-triggered detection — would fail every lifecycle script on a Landlock-less
  host before falling back.
- Fail-closed refusal — an availability regression vs. Phase 29.
```

- [ ] **Step 2: Update ARCHITECTURE.md §3.6** — change the enforcement-scope so the exec **floor** is: macOS enforced (Seatbelt); Linux **enforced where Landlock + the from-source helper are available, advisory otherwise** (bwrap can't `noexec`; Landlock via `landlock-exec`, ADR-0044). The exfil-tool carve-out stays enforced on both. `native` advisory both. Note the Linux floor includes the library/linker dirs and the fail-open `--check` detection.

- [ ] **Step 3: Update the threat model** — in `sentinel-threat-model.md` §3.9 and the §4 bullet, state the Linux exec floor is now enforced (Landlock) where available, advisory otherwise; the dropped-binary gap is closed on Landlock-capable hosts; #8 is closed with the availability caveat documented.

- [ ] **Step 4: Update README sandbox section** — add/extend the Linux bullet: the exec floor is now enforced via a from-source Landlock helper where available (a dropped binary outside the floor is kernel-denied), falling back to the advisory floor otherwise; the carve-out is unchanged.

- [ ] **Step 5: Update CLAUDE.md** — (a) the Phase 3 note: `process` floor now enforced on macOS (Seatbelt) AND Linux-where-Landlock-available (from-source helper, ADR-0044), advisory otherwise; (b) a Phase 2/Landlock paragraph (the helper, the build step, the lib-dir floor, the fail-open detection, the classifier floor mode, the fallback); (c) update the `npm test` count to the exact total from Task 6 Step 5, and append the Phase 2 tests to the inventory comment (linuxExecFloor, computeDenySet Landlock-floor mode, classifier Landlock-floor mode, build-native no-op — hermetic; the two Landlock effect tests — Linux-CI-only).

- [ ] **Step 6: Build + full suite + commit**

```bash
npm run build && npm test
git add docs/adr/0044-landlock-linux-exec-floor.md ARCHITECTURE.md sentinel-threat-model.md README.md CLAUDE.md
git commit -m "docs: ADR-0044 Landlock Linux exec floor + architecture/threat-model/README/CLAUDE sweep (Phase 2, closes #8)"
git push
```

- [ ] **Step 7: Close #8 and finish the branch**

```bash
gh issue close 8 --repo git-agentic/pkg-registry --comment "Closed by Phase 2 (ADR-0044): the Linux exec FLOOR is now enforced via a from-source Landlock helper inside bwrap (\`landlock-exec --allow <floor> --\`) where Landlock is available — a dropped binary outside the floor is kernel-denied, matching the macOS Seatbelt floor (ADR-0042). Hosts without Landlock/\`cc\` fall back to the Phase 29 advisory floor (ADR-0043) with a one-time notice — documented, no availability regression. A cross-platform exec floor now exists; \`native\` remains advisory on both platforms by decision."
```

Then invoke `superpowers:finishing-a-development-branch` for `phase2-landlock-floor` (verify `npm run build && npm test` green and CI green on the PR first).

---

## Verification checklist (Definition of Done)

- [ ] `npm run build` clean on macOS (native step no-ops, exit 0) AND builds the helper on Linux CI
- [ ] `npm test` green; CLAUDE.md count updated
- [ ] Linux CI (Node 22 + 24) green: the helper compiled (`[build-native] built …`), the dropped-/tmp-binary effect test denied + confirmed, the floor-binary positive control ran
- [ ] Fail-open verified: with no helper (macOS / no cc), detection returns false and the Phase 29 advisory path runs (no lifecycle script breaks)
- [ ] macOS/Seatbelt path and the Phase 29 fallback path byte-behavior-unchanged
- [ ] Malicious fixtures still blocked (`npm run demo` ends in 403)
- [ ] ADR-0044 + docs agree: Linux floor enforced-where-available / advisory-otherwise; #8 closed with the caveat
- [ ] #8 closed
