# Phase 25 Slice 1 — Sandbox Write-Deny-by-Default (ADR-0038) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Invert the sandbox's write posture from allow-default-plus-deny-list to deny-by-default: a lifecycle script may write only inside a fixed floor (its Install directory, temp, `/dev`, the node build caches) plus operator-approved `filesystem:` Grants; everything else is denied at the kernel level.

**Architecture:** A new pure `write-floor.ts` computes the write-allow floor from `{cwd, tmpDir}`. Both backend generators (`profile.ts` Seatbelt, `bwrap.ts` Linux) gain a blanket write-deny + floor/grant re-allows, keeping their existing read-deny logic untouched (reads are Slice 2). `pathCovers` becomes directional so a Grant covers exactly its own subtree. The runners thread `cwd` + `tmpDir` into the generators. Phase 10 violation attribution is unchanged — `SENSITIVE_PATHS` still names confirmed write targets; other denied writes are contained but attribute as ambient (an accepted telemetry gap, ADR-0023).

**Tech Stack:** Node 24 / TypeScript, macOS Seatbelt (`sandbox-exec` / SBPL), Linux bubblewrap (`bwrap`), `node:test` + `tsx`.

**Spec:** `docs/superpowers/specs/2026-07-09-security-hardening-phases-design.md` (Phase 25 section, grilling-refined). Domain vocabulary in `CONTEXT.md`.

## Global Constraints

- ESM only, NodeNext: internal imports use `.js` specifiers even from `.ts` sources.
- **This is Slice 1 (writes) only.** Do NOT touch read-deny logic — the existing `SENSITIVE_PATHS` *read* denies and reads-are-allow-default stay exactly as they are. Home-read-deny is Slice 2, a separate plan.
- Profile/argv generation stays **pure**: same inputs ⇒ same output. No `os.tmpdir()`, `Date.now()`, or env reads *inside* a generator — `tmpDir` is passed in.
- `SENSITIVE_PATHS` (in `@sentinel/core`) is **not edited** — it stays the shared data table for detection + attribution.
- Enforcement is tested with **benign probes only**; synthetic malware fixtures are never executed. The "malicious fixture still blocked" definition-of-done extends to "a write outside the floor is denied."
- Seatbelt effect tests run on **darwin only** (skip elsewhere); bwrap effect tests run on **Linux CI only** (`describe`-level skip on darwin) — match the existing `const darwin = process.platform === "darwin"` gating in `packages/sandbox/test/seatbelt.test.ts` / `bubblewrap.test.ts`.
- Run one test file: `node --import tsx --test packages/sandbox/test/<file>.test.ts`. Full suite: `npm test`. Build: `npm run build` (if `rm` of `dist/` EPERMs, `npx tsc --build --force packages/sandbox`).
- Commit style: `feat(phase25): …` / `test(phase25): …` / `docs(phase25): …`.
- Current full-suite baseline on darwin (post-Phase-24): **613 tests, 611 pass, 2 skipped**.

---

### Task 1: Exploratory probe gate (throwaway, darwin) — confirm the write floor

**This task produces NO commit.** It is a design gate: run a real build under a prototype write-deny profile to confirm the floor hypothesis before locking the generators. If the probe reveals a needed floor path not in the hypothesis, **stop and report it** — the later tasks' floor list must be updated first.

**Files:**
- Create (scratchpad, not committed): `<scratchpad>/phase25-write-probe.sh`

**Hypothesis floor** (what Tasks 3–5 will encode): `cwd` subtree, `tmpDir`, `/tmp`, `/dev`, `~/.node-gyp`, `~/.cache/node-gyp`, `~/.npm/_logs`.

- [ ] **Step 1: Write the probe script**

Write to your scratchpad directory (NOT the repo):

```bash
#!/bin/bash
# Phase 25 write-floor probe (darwin). Builds a real native addon under a
# prototype write-deny SBPL profile and checks a persistence write is denied.
set -u
HOME_DIR=$(mktemp -d)
WORK=$(mktemp -d)
PROFILE=$(mktemp)
export HOME="$HOME_DIR"

# Prototype profile: allow-default reads, blanket write-deny, floor re-allow.
cat > "$PROFILE" <<EOF
(version 1)
(allow default)
(deny file-write*)
(allow file-write*
  (subpath "$WORK")
  (subpath "$(cd $TMPDIR && pwd -P)")
  (subpath "/private/tmp")
  (subpath "/dev")
  (subpath "$HOME_DIR/.node-gyp")
  (subpath "$HOME_DIR/.cache")
  (subpath "$HOME_DIR/.npm"))
EOF

# A minimal native addon (exercises node-gyp: writes build/ under cwd, headers under ~/.node-gyp).
cd "$WORK"
cat > binding.gyp <<EOF
{ "targets": [ { "target_name": "probe", "sources": ["probe.c"] } ] }
EOF
cat > probe.c <<EOF
#include <node_api.h>
napi_value Init(napi_env env, napi_value exports){ return exports; }
NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
EOF
echo '{"name":"probe","version":"1.0.0"}' > package.json

echo "=== gyp build under write-deny (expect success) ==="
sandbox-exec -f "$PROFILE" /bin/sh -c "npx node-gyp configure build 2>&1 | tail -20; echo GYP_EXIT=\$?"

echo "=== persistence write under write-deny (expect DENIED) ==="
printf 'ORIGINAL' > "$HOME_DIR/.zshrc"
sandbox-exec -f "$PROFILE" /bin/sh -c "echo PWNED >> '$HOME_DIR/.zshrc' 2>&1 || true"
echo "zshrc now: $(cat $HOME_DIR/.zshrc)"

echo "=== /dev/null redirect under write-deny (expect success) ==="
sandbox-exec -f "$PROFILE" /bin/sh -c "echo hi > /dev/null && echo DEVNULL_OK"

rm -rf "$HOME_DIR" "$WORK" "$PROFILE"
```

- [ ] **Step 2: Run the probe**

Run: `bash <scratchpad>/phase25-write-probe.sh`

Expected:
- `GYP_EXIT=0` and a compiled `build/Release/probe.node` — the floor lets a native build complete.
- `zshrc now: ORIGINAL` — the persistence write was denied (blocked at kernel).
- `DEVNULL_OK` — `/dev` writes work (proves `/dev` must be in the floor).

- [ ] **Step 3: Record findings and decide**

If all three expectations hold, the hypothesis floor is confirmed — proceed to Task 2 with the floor as written. **If the gyp build fails** with a write EPERM to a path *not* in the floor (likely suspects: `~/.cache/node/corepack`, a `~/.npm/_cacache` write, an npm lockfile written to `cwd`'s parent), record the exact path and **add it to the floor in Tasks 3/5 before implementing**. Report the confirmed floor in your task report; this is the input the rest of the plan depends on.

(No commit — this is exploratory. The committed regression guarantee is Task 6's effect-tests.)

---

### Task 2: Directional `pathCovers`

**Files:**
- Modify: `packages/sandbox/src/path-cover.ts`
- Test: `packages/sandbox/test/path-cover.test.ts`

**Interfaces:**
- Produces: `pathCovers(approvedTarget: string, target: string): boolean` — now true **only** when `approvedTarget` is an ancestor-or-equal of `target` (one direction). Consumed by `profile.ts`, `bwrap.ts`, `deny-set.ts`, `violation.ts`.

- [ ] **Step 1: Update the failing test**

Add these cases to `packages/sandbox/test/path-cover.test.ts` (read the file first; keep its existing passing cases that match the new directional rule, and replace any case that asserts the *reverse* direction):

```typescript
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { pathCovers } from "../src/path-cover.js";

describe("pathCovers (directional — approval covers at-or-below only)", () => {
  test("an ancestor approval covers a descendant deny", () => {
    assert.equal(pathCovers("~/.ssh", "~/.ssh/id_rsa"), true);
  });
  test("an equal path covers itself", () => {
    assert.equal(pathCovers("~/.npmrc", "~/.npmrc"), true);
  });
  test("a descendant approval does NOT cover an ancestor deny (the Phase 25 fix)", () => {
    assert.equal(pathCovers("~/.ssh/config", "~/.ssh"), false);
  });
  test("unrelated paths never cover", () => {
    assert.equal(pathCovers("~/.aws", "~/.ssh"), false);
    assert.equal(pathCovers("ssh", ".ssh"), false); // segment-anchored, not substring
  });
  test("the dynamic '*' target covers nothing", () => {
    assert.equal(pathCovers("*", "~/.ssh"), false);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/path-cover.test.ts`
Expected: FAIL — the descendant-does-not-cover-ancestor case fails (today's bidirectional `pathCovers` returns `true`).

- [ ] **Step 3: Make coverage directional**

In `packages/sandbox/src/path-cover.ts`, replace the body of `pathCovers` (keep `segments` unchanged). The current loop compares up to `Math.min(a.length, d.length)` and returns true for either direction; change it so the approved target must be an ancestor-or-equal (its segments are a prefix of the target's):

```typescript
/**
 * Directional segment-anchored coverage: true iff `approvedTarget` is an
 * ancestor-or-equal of `target` — i.e. an approval grants exactly its own
 * subtree and never widens up to an ancestor (Phase 25, ADR-0038). Segment-
 * anchored, so `ssh` does not cover `.ssh`; the dynamic `*` target covers
 * nothing.
 */
export function pathCovers(approvedTarget: string, target: string): boolean {
  const a = segments(approvedTarget);
  const d = segments(target);
  if (a.length === 0) return false;      // "*" / empty grants nothing
  if (a.length > d.length) return false; // a deeper approval can't cover a shallower path
  for (let i = 0; i < a.length; i++) if (a[i] !== d[i]) return false;
  return true;
}
```

Delete the old NOTE comment about the descendant-cancels-ancestor side effect (it's now fixed).

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/path-cover.test.ts`
Expected: PASS.

- [ ] **Step 5: Run the consumers' existing tests (regression)**

Run: `node --import tsx --test packages/sandbox/test/profile.test.ts packages/sandbox/test/bwrap.test.ts packages/sandbox/test/deny-set.test.ts packages/sandbox/test/violation.test.ts`
Expected: PASS. If a test asserted the old reverse-direction behavior (a descendant approval cancelling an ancestor deny), update it to the directional expectation and note it in your report.

- [ ] **Step 6: Commit**

```bash
git add packages/sandbox/src/path-cover.ts packages/sandbox/test/path-cover.test.ts
git commit -m "feat(phase25): directional pathCovers — an approval covers exactly its own subtree (ADR-0038)"
```

---

### Task 3: Write-allow floor helper

**Files:**
- Create: `packages/sandbox/src/write-floor.ts`
- Test: `packages/sandbox/test/write-floor.test.ts`

**Interfaces:**
- Produces: `writeAllowFloor(opts: { cwd: string; tmpDir: string }): string[]` — pure; returns the baseline writable paths as raw strings (absolute or `~`-relative). Callers (Tasks 4/5) expand `~` and canonicalize. **Use the floor confirmed by Task 1's probe** — the list below is the hypothesis.

- [ ] **Step 1: Write the failing test**

```typescript
// packages/sandbox/test/write-floor.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { writeAllowFloor } from "../src/write-floor.js";

describe("writeAllowFloor", () => {
  test("includes the install dir, temp, /tmp, /dev and the node build caches", () => {
    const floor = writeAllowFloor({ cwd: "/work/pkg", tmpDir: "/var/folders/x/T" });
    assert.deepEqual(floor, [
      "/work/pkg",
      "/var/folders/x/T",
      "/tmp",
      "/dev",
      "~/.node-gyp",
      "~/.cache/node-gyp",
      "~/.npm/_logs",
    ]);
  });
  test("is pure — same inputs give the same list", () => {
    const a = writeAllowFloor({ cwd: "/a", tmpDir: "/b" });
    const b = writeAllowFloor({ cwd: "/a", tmpDir: "/b" });
    assert.deepEqual(a, b);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/write-floor.test.ts`
Expected: FAIL — `Cannot find module '../src/write-floor.js'`.

- [ ] **Step 3: Write the implementation**

```typescript
// packages/sandbox/src/write-floor.ts
/**
 * The baseline set of writable locations every sandboxed lifecycle script gets
 * under write-deny-by-default (Phase 25, ADR-0038). Pure — the caller expands
 * `~` (via homeDir) and canonicalizes. A FIXED floor, deliberately not operator-
 * configurable: widening it silently reopens the persistence class. Per-package
 * needs are met by approved `filesystem:` Grants instead.
 *
 * `/dev` is here because a blanket `file-write*` deny otherwise blocks
 * `2>/dev/null` and other device writes that ordinary scripts rely on.
 */
export function writeAllowFloor(opts: { cwd: string; tmpDir: string }): string[] {
  return [
    opts.cwd,            // the Install directory — build output lands here
    opts.tmpDir,         // os.tmpdir() — build tools stage here
    "/tmp",              // firmlink → /private/tmp on macOS (caller canonicalizes)
    "/dev",              // /dev/null, /dev/stdout, ttys
    "~/.node-gyp",       // node-gyp downloaded headers
    "~/.cache/node-gyp", // node-gyp cache (XDG)
    "~/.npm/_logs",      // npm lifecycle logs
  ];
}
```

(If Task 1's probe added a path — e.g. `~/.cache/node/corepack` — add it here and to the test's expected list.)

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/write-floor.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/write-floor.ts packages/sandbox/test/write-floor.test.ts
git commit -m "feat(phase25): write-allow floor helper — fixed baseline writable paths (ADR-0038)"
```

---

### Task 4: Seatbelt generator — write-deny + floor + Grants

**Files:**
- Modify: `packages/sandbox/src/profile.ts`
- Modify: `packages/sandbox/src/seatbelt.ts` (thread `cwd` + `tmpDir` into `generateProfile`)
- Test: `packages/sandbox/test/profile.test.ts`

**Interfaces:**
- Consumes: `writeAllowFloor` (Task 3); directional `pathCovers` (Task 2); `expandHome`/`canonicalizeMacPath` (existing, `deny-set.ts`).
- Produces: `generateProfile(approved: Capability[], opts: { homeDir: string; cwd: string; tmpDir: string }): string` — the new `cwd`/`tmpDir` are required. Emits: `(allow default)`, the existing read-denies (unchanged), a blanket `(deny file-write*)`, then `(allow file-write* …)` for the floor + approved-`filesystem` Grants, then the network deny.

- [ ] **Step 1: Write the failing test**

Add to `packages/sandbox/test/profile.test.ts` (read it first; keep the existing read-deny assertions — they must still hold):

```typescript
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateProfile } from "../src/profile.js";
import type { Capability } from "@sentinel/core";

const OPTS = { homeDir: "/Users/x", cwd: "/work/pkg", tmpDir: "/var/folders/z/T" };

describe("generateProfile — write-deny (Phase 25)", () => {
  test("emits a blanket write-deny before the floor allows", () => {
    const p = generateProfile([], OPTS);
    const denyIdx = p.indexOf("(deny file-write*)");
    const allowIdx = p.indexOf("(allow file-write*");
    assert.ok(denyIdx !== -1, "blanket write-deny present");
    assert.ok(allowIdx > denyIdx, "floor allow comes AFTER the blanket deny (SBPL last-match-wins)");
  });
  test("the floor re-allows cwd, temp, /private/tmp, /dev and the node caches", () => {
    const p = generateProfile([], OPTS);
    for (const frag of [
      `(subpath "/work/pkg")`,
      `(subpath "/private/var/folders/z/T")`, // tmpDir canonicalized
      `(subpath "/private/tmp")`,             // /tmp canonicalized
      `(subpath "/dev")`,
      `(subpath "/Users/x/.node-gyp")`,
      `(subpath "/Users/x/.npm/_logs")`,
    ]) assert.ok(p.includes(frag), `floor must allow ${frag}`);
  });
  test("an approved filesystem capability becomes a positive write Grant", () => {
    const approved: Capability[] = [{ kind: "filesystem", target: ".config/app", evidence: [] }];
    const p = generateProfile(approved, OPTS);
    assert.ok(p.includes(`(allow file-write*`) && p.includes(`(subpath "/Users/x/.config/app")`),
      "approved fs target is write-allowed");
  });
  test("SENSITIVE write targets are carved back out AFTER the floor (persistence stays denied even under an allowed ancestor)", () => {
    const p = generateProfile([], OPTS);
    const floorAllow = p.indexOf("(allow file-write*");
    const carve = p.lastIndexOf("(deny file-write*");
    assert.ok(carve > floorAllow, "sensitive write carve-out must come after the floor allow (last-match-wins)");
    assert.ok(p.includes(`/Users/x/.zshrc`), "a persistence path is re-denied");
  });
  test("an approved Grant lifts the carve-out for its own path (approve ~/.zshrc → writable)", () => {
    const approved: Capability[] = [{ kind: "filesystem", target: ".zshrc", evidence: [] }];
    const p = generateProfile(approved, OPTS);
    // .zshrc is now covered by a Grant, so it is NOT in the trailing write carve-out.
    const carveTail = p.slice(p.indexOf("(allow file-write*"));
    assert.ok(!carveTail.includes(`(deny file-write* (literal "/Users/x/.zshrc")`), "granted path is not carved back out");
  });
  test("read-denies for credential paths are UNCHANGED (Slice 1 leaves reads alone)", () => {
    const p = generateProfile([], OPTS);
    assert.ok(p.includes("(deny file-read*"), "credential read-denies still emitted");
  });
  test("pure — same inputs, identical profile", () => {
    assert.equal(generateProfile([], OPTS), generateProfile([], OPTS));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/profile.test.ts`
Expected: FAIL — `generateProfile` doesn't accept `cwd`/`tmpDir`, emits no blanket write-deny or floor.

- [ ] **Step 3: Rewrite `generateProfile`**

Replace `packages/sandbox/src/profile.ts` with:

```typescript
import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";
import { canonicalizeMacPath, expandHome } from "./deny-set.js";
import { writeAllowFloor } from "./write-floor.js";

/**
 * Generate a macOS Seatbelt (SBPL) profile from a package's APPROVED capabilities.
 * Reads stay allow-default minus the SENSITIVE_PATHS read-denies (Slice 2 will
 * invert reads). Writes are DENY-BY-DEFAULT (Phase 25 Slice 1): a blanket
 * `(deny file-write*)` then re-allow the write floor + approved-filesystem Grants.
 * SBPL is last-match-wins, so the allow forms follow the blanket deny. Pure:
 * same inputs ⇒ same string.
 */
export function generateProfile(
  approved: Capability[],
  opts: { homeDir: string; cwd: string; tmpDir: string },
): string {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");
  const canon = (p: string) => canonicalizeMacPath(expandHome(p, opts.homeDir));

  const lines = ["(version 1)", "(allow default)"];

  // Reads: unchanged from before Phase 25 — deny each SENSITIVE read path not
  // covered by an approved (directional) Grant.
  for (const sp of sensitivePathsFor("darwin")) {
    if (!sp.modes.includes("read")) continue;
    const uncovered = sp.denyPaths.filter((dp) => !approvedFs.some((t) => pathCovers(t, dp)));
    if (uncovered.length === 0) continue;
    const items = uncovered.map((dp) => `(${sp.denyKind} "${canon(dp)}")`).join(" ");
    lines.push(`(deny file-read* ${items})`);
  }

  // Writes: deny by default, re-allow the floor + approved Grants, then carve
  // the SENSITIVE_PATHS write targets back OUT (SBPL last-match-wins) so a
  // persistence path is denied even if it sits under an allowed ancestor —
  // unless an approved Grant explicitly covers it. The carve-out is what makes
  // persistence protection robust (and hermetically testable, since a test's
  // fake $HOME lives under os.tmpdir(), which is in the floor).
  lines.push("(deny file-write*)");
  const floor = writeAllowFloor({ cwd: opts.cwd, tmpDir: opts.tmpDir }).map(canon);
  const grants = approvedFs.map(canon);
  const allowItems = [...floor, ...grants].map((p) => `(subpath "${p}")`).join(" ");
  lines.push(`(allow file-write* ${allowItems})`);
  for (const sp of sensitivePathsFor("darwin")) {
    if (!sp.modes.includes("write")) continue;
    const uncovered = sp.denyPaths.filter((dp) => !approvedFs.some((t) => pathCovers(t, dp)));
    if (uncovered.length === 0) continue;
    const items = uncovered.map((dp) => `(${sp.denyKind} "${canon(dp)}")`).join(" ");
    lines.push(`(deny file-write* ${items})`);
  }

  if (!hasNetwork) lines.push("(deny network*)");
  return lines.join("\n") + "\n";
}
```

Then thread `cwd`/`tmpDir` in `packages/sandbox/src/seatbelt.ts` — add the tmpdir import and change the `generateProfile` call:

```typescript
import { tmpdir } from "node:os";
// …
    const profile = generateProfile(opts.approved, { homeDir: opts.homeDir, cwd: opts.cwd, tmpDir: tmpdir() });
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/profile.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/profile.ts packages/sandbox/src/seatbelt.ts packages/sandbox/test/profile.test.ts
git commit -m "feat(phase25): Seatbelt write-deny-by-default + floor + approved-fs Grants (ADR-0038)"
```

---

### Task 5: bwrap generator — write-deny + floor + Grants

**Files:**
- Modify: `packages/sandbox/src/bwrap.ts`
- Modify: `packages/sandbox/src/bubblewrap.ts` (thread `cwd` + `tmpDir`)
- Test: `packages/sandbox/test/bwrap.test.ts`

**Interfaces:**
- Consumes: `writeAllowFloor` (Task 3); `expandHome` (existing).
- Produces: `generateBwrapArgs(approved: Capability[], opts: { homeDir: string; cwd: string; tmpDir: string }): string[]` — root becomes **read-only** (`--ro-bind / /`) so reads still work but writes are denied, with the floor + Grants re-bound read-write via `--bind-try` (tolerant of not-yet-existing cache dirs). Existing credential-read masks and `--unshare-net` unchanged.

- [ ] **Step 1: Write the failing test**

Add to `packages/sandbox/test/bwrap.test.ts` (read it first; keep the existing credential-mask + network assertions):

```typescript
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateBwrapArgs } from "../src/bwrap.js";
import type { Capability } from "@sentinel/core";

const OPTS = { homeDir: "/home/x", cwd: "/work/pkg", tmpDir: "/tmp/build" };

/** Find the source path of a --bind/--ro-bind/--bind-try pair in the flat argv. */
function binds(args: string[], flag: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) if (args[i] === flag) out.push(args[i + 1]!);
  return out;
}

describe("generateBwrapArgs — write-deny (Phase 25)", () => {
  test("root is mounted read-only (reads work, writes denied)", () => {
    const args = generateBwrapArgs([], OPTS);
    assert.deepEqual(binds(args, "--ro-bind").slice(0, 1), ["/"], "first mount is --ro-bind / /");
    assert.ok(!binds(args, "--bind").includes("/"), "root is NOT rw-bound");
  });
  test("the write floor is re-bound read-write (bind-try tolerates missing cache dirs)", () => {
    const args = generateBwrapArgs([], OPTS);
    const rw = [...binds(args, "--bind"), ...binds(args, "--bind-try")];
    for (const p of ["/work/pkg", "/tmp/build", "/dev", "/home/x/.node-gyp", "/home/x/.npm/_logs"]) {
      assert.ok(rw.includes(p), `floor path ${p} must be re-bound rw`);
    }
  });
  test("an approved filesystem capability is re-bound read-write", () => {
    const approved: Capability[] = [{ kind: "filesystem", target: ".config/app", evidence: [] }];
    const rw = [...binds(generateBwrapArgs(approved, OPTS), "--bind"),
                ...binds(generateBwrapArgs(approved, OPTS), "--bind-try")];
    assert.ok(rw.includes("/home/x/.config/app"), "approved fs target is rw-bound");
  });
  test("pure — same inputs, identical argv", () => {
    assert.deepEqual(generateBwrapArgs([], OPTS), generateBwrapArgs([], OPTS));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/bwrap.test.ts`
Expected: FAIL — `generateBwrapArgs` takes no `cwd`/`tmpDir`, still does `--bind / /`.

- [ ] **Step 3: Rewrite `generateBwrapArgs`**

Replace `packages/sandbox/src/bwrap.ts` with:

```typescript
import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";
import { expandHome } from "./deny-set.js";
import { writeAllowFloor } from "./write-floor.js";

/**
 * Generate `bwrap` argv from a package's APPROVED capabilities. Phase 25 Slice 1:
 * root is mounted READ-ONLY (`--ro-bind / /`) so reads still work while writes are
 * denied by default; the write floor + approved-filesystem Grants are re-bound
 * read-write on top (`--bind-try`, tolerant of a not-yet-created cache dir).
 * Credential-read masks (unchanged from before) and `--unshare-net` follow.
 * Pure: same inputs ⇒ same argv. No firmlink canonicalization (Linux).
 */
export function generateBwrapArgs(
  approved: Capability[],
  opts: { homeDir: string; cwd: string; tmpDir: string },
): string[] {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");

  // Read-only root + writable floor/grants on top.
  const args = ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"];
  const floor = writeAllowFloor({ cwd: opts.cwd, tmpDir: opts.tmpDir });
  const rw = [...floor, ...approvedFs].map((p) => expandHome(p, opts.homeDir));
  for (const p of rw) args.push("--bind-try", p, p);

  // SENSITIVE_PATHS masks, applied AFTER the floor binds so they win for any
  // overlapping path (a bwrap tmpfs/ro-bind-devnull mask denies both read and
  // write). This preserves credential-read protection (Slice 1 leaves reads
  // open otherwise) AND carves persistence write targets back out of the floor —
  // so `~/.zshrc` stays denied even when the test's fake $HOME sits under the
  // floor's temp dir. A Grant covering the path skips its mask.
  for (const sp of sensitivePathsFor("linux")) {
    for (const dp of sp.denyPaths) {
      if (approvedFs.some((t) => pathCovers(t, dp))) continue;
      const target = expandHome(dp, opts.homeDir);
      if (sp.denyKind === "subpath") args.push("--tmpfs", target);
      else args.push("--ro-bind", "/dev/null", target);
    }
  }

  if (!hasNetwork) args.push("--unshare-net");
  return args;
}
```

Note the ordering change from the old generator: the masks now come **after** the floor binds (bwrap applies mounts in order; the later mount wins for an overlapping path), so a sensitive path under a rw floor bind is re-masked. The mask loop itself is the same shape as before (it covers both read and write, since a tmpfs/`/dev/null` mask denies both).

Then thread `cwd`/`tmpDir` in `packages/sandbox/src/bubblewrap.ts`:

```typescript
import { tmpdir } from "node:os";
// …
    const args = [...generateBwrapArgs(opts.approved, { homeDir: opts.homeDir, cwd: opts.cwd, tmpDir: tmpdir() }), "/bin/sh", "-c", cmd];
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/sandbox/test/bwrap.test.ts`
Expected: PASS. (These are pure argv tests — they run on darwin too; only the *effect* tests are Linux-gated.)

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/bwrap.ts packages/sandbox/src/bubblewrap.ts packages/sandbox/test/bwrap.test.ts
git commit -m "feat(phase25): bwrap write-deny via read-only root + rw floor/Grants (ADR-0038)"
```

---

### Task 6: Effect-tests — write floor enforced end-to-end + deny-set non-drift

**Files:**
- Modify: `packages/sandbox/test/seatbelt.test.ts` (darwin effect tests)
- Modify: `packages/sandbox/test/bubblewrap.test.ts` (Linux CI effect tests)
- Modify: `packages/sandbox/test/deny-set.test.ts` if the directional change shifted any expectation

**Interfaces:**
- Consumes: the shipped `SeatbeltSandbox`/`BubblewrapSandbox` (`run(cmd, { cwd, approved, homeDir, env })`).

- [ ] **Step 1: Write the failing effect tests**

Add to the `describe("SeatbeltSandbox enforcement", …)` block in `packages/sandbox/test/seatbelt.test.ts` (it already imports `mkdtempSync`, `realpathSync`, `writeFileSync`, `readFileSync`, `tmpdir`, `join`):

```typescript
  test("a write to the Install directory (cwd, the floor) succeeds — positive control", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-floor-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "sb-work-")));
    const inside = join(work, "build-output.txt");
    const r = new SeatbeltSandbox().run(`echo OK > "${inside}"`, { cwd: work, approved: [], homeDir: home });
    assert.equal(r.exitCode, 0);
    assert.equal(readFileSync(inside, "utf8").trim(), "OK", "a write inside the floor (cwd) must succeed");
  });

  test("a persistence write is denied by the carve-out even though the fake $HOME is under the floor's temp dir", () => {
    // NOTE: os.tmpdir() is in the write floor, and this fake $HOME lives under it,
    // so ~/.zshrc sits inside an allowed ancestor. It is still denied — the
    // SENSITIVE_PATHS write carve-out (emitted after the floor allow) re-denies it.
    // This is why the carve-out is load-bearing, not just attribution.
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-carve-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "sb-cwork-")));
    const rc = join(home, ".zshrc");
    writeFileSync(rc, "ORIGINAL");
    new SeatbeltSandbox().run(`echo PWNED >> "${rc}" 2>/dev/null || true`, { cwd: work, approved: [], homeDir: home });
    assert.equal(readFileSync(rc, "utf8"), "ORIGINAL", "the persistence write must be denied by the carve-out");
  });

  test("a real /dev/null redirect still works under write-deny", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-dev-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "sb-devwork-")));
    const r = new SeatbeltSandbox().run(`echo hi > /dev/null && echo DEVOK`, { cwd: work, approved: [], homeDir: home });
    assert.equal(r.exitCode, 0);
    assert.ok(r.stdout.includes("DEVOK"), "device writes must still work");
  });
```

The existing tests — persistence write to `~/.zshrc` denied, filesystem approval relaxes the write, credential-read violation — must still pass unchanged; they now exercise the blanket write-deny + carve-out + Grant path.

**Testability note (put this in your report):** because `os.tmpdir()` is in the floor and every hermetic test path lives under it, "an arbitrary *non-sensitive* path outside the floor is denied" cannot be shown as an effect test — every temp path is inside the floor. That property is asserted at the *generator* level instead (Task 4's "blanket `(deny file-write*)` before the floor allow" test). The effect tests prove the two things that ARE hermetically observable: floor writes succeed, and the sensitive carve-out denies persistence even under an allowed ancestor.

Add the bwrap equivalents to `packages/sandbox/test/bubblewrap.test.ts` under its Linux-gated enforcement `describe` (mirror the two tests above using `new BubblewrapSandbox()`).

- [ ] **Step 2: Run to verify (darwin)**

Run: `node --import tsx --test packages/sandbox/test/seatbelt.test.ts`
Expected: the two new tests PASS; all pre-existing enforcement tests still PASS. (The bubblewrap effect tests skip on darwin — they run in Linux CI.)

- [ ] **Step 3: Verify deny-set non-drift**

Run: `node --import tsx --test packages/sandbox/test/deny-set.test.ts packages/sandbox/test/violation.test.ts`
Expected: PASS. `computeDenySet` still derives from `SENSITIVE_PATHS` (unchanged), so attribution of a `~/.zshrc` write is still `confirmed`. If the directional `pathCovers` shifted a `deny-set.test.ts` expectation (a descendant approval no longer cancelling an ancestor deny), update that assertion and note it.

- [ ] **Step 4: Commit**

```bash
git add packages/sandbox/test/seatbelt.test.ts packages/sandbox/test/bubblewrap.test.ts packages/sandbox/test/deny-set.test.ts
git commit -m "test(phase25): write-floor enforcement effect-tests + deny-set non-drift (ADR-0038)"
```

---

### Task 7: ADR-0038 + docs + full gate

**Files:**
- Create: `docs/adr/0038-sandbox-default-deny.md`
- Modify: `docs/adr/README.md`, `ARCHITECTURE.md`, `CLAUDE.md`, `AGENTS.md`, `CONTEXT.md` (if a term sharpened during implementation)

- [ ] **Step 1: Write ADR-0038**

```markdown
# ADR-0038: Sandbox default-deny (write slice)

Date: 2026-07-09
Status: Accepted
Supersedes: ADR-0016 (Seatbelt runner), ADR-0017 (write confinement), ADR-0018 (cross-platform backends) — the allow-default-plus-deny-list stance only.

## Context

The prior sandbox was allow-default (`(allow default)` / `--bind / /`) minus a
fixed `SENSITIVE_PATHS` deny list, so a lifecycle script could write anywhere
not explicitly enumerated — contradicting the "approved capability manifest"
model. An external audit flagged this. Phase 25 inverts the posture; it lands as
two slices (writes now, `$HOME` reads as a gated follow-up) because their risk
profiles differ sharply (see the design spec).

## Decision (Slice 1 — writes)

Writes are **deny-by-default**. A blanket deny, then re-allow a **fixed write
floor**: the Install directory (`cwd`), the OS temp dir, `/tmp`, `/dev` (device
writes like `2>/dev/null`), and the node build caches (`~/.node-gyp`,
`~/.cache/node-gyp`, `~/.npm/_logs`). The floor is not operator-configurable —
widening it silently reopens the persistence class; per-package needs are met by
approved `filesystem:` **Grants**, which now emit positive write allows instead
of cancelling a deny. `pathCovers` is **directional**: a Grant covers exactly
its own subtree, never widening to an ancestor.

- **Seatbelt:** `(deny file-write*)` + `(allow file-write* …floor…grants)`
  (last-match-wins). Reads unchanged.
- **bwrap:** `--ro-bind / /` (read-only root) + `--bind-try` the floor/grants
  read-write. Reads unchanged.

`SENSITIVE_PATHS` is unchanged as a data table. Its write entries are emitted as
a **carve-out** re-deny *after* the floor allow (SBPL last-match-wins; bwrap
mask-after-bind), so a persistence path is denied even when it sits under an
allowed ancestor — e.g. under the floor's temp dir. That makes them load-bearing
enforcement, not merely redundant, and they still drive Phase 10 attribution and
the `secret-exfil` detection rule. A Grant covering the path lifts its carve-out.

## Consequences

- Persistence/tamper writes (shell rc, LaunchAgents, systemd units, any
  non-floor path) are denied at the kernel — the whole class, not an enumerated
  list.
- **Telemetry gap (accepted, per ADR-0023):** Phase 10 `classifyViolation`
  attributes a *confirmed* write violation only for `SENSITIVE_PATHS` targets
  (the finite `deniedPaths` list). A denied write to a non-sensitive, non-floor
  path is *contained* but attributes as ambient (`null`) — containment ≥
  telemetry, same principle as a swallowed denial.
- `$HOME`-read-deny (Slice 2) is a separate follow-up; reads remain
  allow-default-minus-`SENSITIVE_PATHS` until then.

## Alternatives considered

- **Operator-configurable write floor** — rejected; a widenable floor is a
  footgun that reopens the persistence class. Grants are the per-package escape.
- **Keep enumerated write-deny list** — rejected; it's the exact gap the audit
  named (a novel persistence path stays writable).
```

- [ ] **Step 2: Update the doc set**

- `docs/adr/README.md`: append an ADR-0038 index entry (match the file's format).
- `ARCHITECTURE.md`: add the Phase 25 (Slice 1) section where §3.24 sits, same style.
- `CLAUDE.md` **and** `AGENTS.md`: add the Phase 25 Slice-1 paragraph after the Phase 24 one (both root files carry the phase log — update both); update the test-count comment in `CLAUDE.md` with the real number from Step 3.
- `CONTEXT.md`: already has Grant / Carve-out / Install directory / Deny-by-default from the grilling session — only touch it if implementation sharpened a term further.

- [ ] **Step 3: Full gate**

Run: `npm run build`
Expected: clean.

Run: `npm test`
Expected: green — the 613 baseline plus the new Phase 25 tests (path-cover updates, write-floor unit, profile/bwrap generator tests, and the darwin write-floor effect tests). Record the actual total for `CLAUDE.md`. The 2 skips remain (the bwrap enforcement suite stays a describe-level skip on darwin).

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0038-sandbox-default-deny.md docs/adr/README.md ARCHITECTURE.md CLAUDE.md AGENTS.md CONTEXT.md
git commit -m "docs(phase25): ADR-0038 sandbox default-deny (write slice); ARCHITECTURE/CLAUDE/AGENTS"
```

---

## Self-review notes

- **Spec coverage (Slice 1 scope):** two-slice framing honored — this plan is writes only, reads explicitly deferred (Task 7 ADR + constraints). Write-allow floor (Task 3, probe-confirmed in Task 1), fixed-not-configurable (Task 3 doc + ADR), approvals-as-Grants (Tasks 4/5), directional `pathCovers` (Task 2), Seatbelt + bwrap mechanics (Tasks 4/5), effect-tests + deny-set non-drift (Task 6), ADR-0038 superseding 0016/0017/0018 with the accepted attribution telemetry gap (Task 7). Slice-2 items (home-read-deny, `execPath` node-prefix, project-root input, `/etc/passwd` carve-out, bwrap tmpfs telemetry asymmetry) are intentionally absent — they belong to the Slice 2 plan.
- **Type consistency:** `generateProfile`/`generateBwrapArgs` both take `{ homeDir, cwd, tmpDir }` (Tasks 4/5), matching the runner call sites; `writeAllowFloor({ cwd, tmpDir })` matches Tasks 3→4→5; directional `pathCovers(approvedTarget, target)` matches Task 2 and its consumers.
- **Probe-first honored:** Task 1 is an explicit gate whose output (the confirmed floor) feeds Tasks 3/5; the plan's floor is the labelled hypothesis, and Task 1 says to adjust it before implementing if the probe disagrees.
- **Not in scope:** Slice 2 (home-read-deny) — its own plan after this lands.
