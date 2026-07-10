# Phase 10 — Runtime Violation Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn a silent sandbox denial into a structured, attributed runtime-violation event that the CLI reports to the proxy, which quarantines that exact build (integrity) fleet-wide.

**Architecture:** A pure `classifyViolation` in `@sentinel/sandbox` correlates a child's permission-error exit against the deny set the runner already compiles (`computeDenySet`), attaching a `SandboxViolation` to `SandboxResult`. `sentinel-script-shell` POSTs it to the proxy's new `/-/violations`. A `ViolationStore` persists it, revokes the approval, and the serve path overlays a critical `runtime-violation` finding forcing `block` — never mutating the deterministic static score.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; no new dependencies.

## Global Constraints

- **Invariant #1 (deterministic score):** violations NEVER mutate the cached 0–100 `score`; the block is a serve-time overlay, exactly like `deny`/approval. The `scoring is deterministic across runs` test stays green.
- **Invariant #6 (never crash / fail-open):** `classifyViolation` is pure and total (returns `null`, never throws); a reporting-POST failure is swallowed and never changes the install exit code.
- **Best-effort telemetry scope:** the sensor only detects violations that surface as process failure (non-zero exit + permission-error stderr). A swallowed denial (exit 0, clean stderr) is invisible to telemetry but STILL contained by the sandbox. Document this; do not claim to catch swallowed denials.
- **Confidence gate:** only `confirmed` violations (permission-error signature AND target ∈ deny set, or network-denied class) auto-quarantine; `suspected` (targetless class-denial) records + surfaces but does NOT auto-403.
- **Fixture safety:** synthetic, inert, `SYNTHETIC FIXTURE` header, RFC 5737 IPs (`198.51.100.0/24`); scored as text, never live malware. New telemetry probes PROPAGATE the error (unlike `enforce-probe` which swallows).
- **Permission-error signatures:** macOS Seatbelt → node `EPERM: operation not permitted, open '<path>'` and `connect EPERM <host>:<port>`; Linux bwrap → `EACCES`/`ENOENT` on the masked path. Extraction regexes: filesystem `/(?:EPERM|EACCES|ENOENT)[^\n]*?['"]([^'"\n]+)['"]/`, network `/connect (?:EPERM|EACCES) ([0-9.]+):(\d+)/`.
- ESM only, NodeNext: internal imports use `.js` specifiers even from `.ts`.
- Tests hermetic: `LocalFixtureUpstream` only; never hit live npm in `npm test`. Sandbox effect tests skip off-platform (darwin runs Seatbelt; Linux CI runs bwrap).
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/<pkg>`.
- After editing anything under `fixtures/`, re-run `npm run fixtures`.
- Run all commands from repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.
- CLI-child e2e tests use async `spawn`/`execFile`, never `spawnSync`/`execFileSync` against the in-process proxy (event-loop deadlock).

---

### Task 1: `computeDenySet` — shared deny-set derivation

**Files:**
- Create: `packages/sandbox/src/deny-set.ts`
- Modify: `packages/sandbox/src/profile.ts` (consume shared helpers)
- Modify: `packages/sandbox/src/bwrap.ts` (consume shared helper)
- Modify: `packages/sandbox/src/index.ts` (export)
- Test: `packages/sandbox/test/deny-set.test.ts`

**Interfaces:**
- Produces (used by Tasks 2–3):
  - `interface DenySet { deniedPaths: string[]; networkDenied: boolean }`
  - `computeDenySet(approved: Capability[], opts: { homeDir: string; platform: "darwin" | "linux" }): DenySet` — `deniedPaths` is the expanded, canonicalized (darwin) list of `SENSITIVE_PATHS.denyPaths` entries NOT covered by an approved filesystem capability; `networkDenied` is true when no `network` capability is approved.
  - `expandHome(p: string, homeDir: string): string` and `canonicalizeMacPath(p: string): string` (moved from profile.ts).

- [ ] **Step 1: Write the failing test** (`packages/sandbox/test/deny-set.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Capability } from "@sentinel/core";
import { computeDenySet } from "../src/deny-set.js";
import { generateProfile } from "../src/profile.js";

const HOME = "/Users/test";
const fsCap = (target: string): Capability => ({ kind: "filesystem", target, evidence: [] });
const netCap = (): Capability => ({ kind: "network", target: "*", evidence: [] });

describe("computeDenySet", () => {
  test("no approvals: denies sensitive paths and network", () => {
    const ds = computeDenySet([], { homeDir: HOME, platform: "darwin" });
    assert.ok(ds.networkDenied);
    assert.ok(ds.deniedPaths.some((p) => p.includes(".ssh")), "ssh must be denied");
    assert.ok(ds.deniedPaths.every((p) => !p.startsWith("~")), "paths must be home-expanded");
  });

  test("an approved network capability lifts networkDenied", () => {
    assert.equal(computeDenySet([netCap()], { homeDir: HOME, platform: "darwin" }).networkDenied, false);
  });

  test("an approved filesystem capability covering ~/.ssh removes it from deniedPaths", () => {
    const ds = computeDenySet([fsCap("~/.ssh")], { homeDir: HOME, platform: "darwin" });
    assert.ok(!ds.deniedPaths.some((p) => p.includes(".ssh")), "approved ssh must not be denied");
  });

  test("darwin canonicalizes /etc to /private/etc", () => {
    const ds = computeDenySet([], { homeDir: HOME, platform: "darwin" });
    assert.ok(ds.deniedPaths.includes("/private/etc/passwd"), "must canonicalize /etc → /private/etc");
  });

  test("non-drift: every deniedPath appears in the generated Seatbelt profile", () => {
    const approved: Capability[] = [fsCap("~/.aws")];
    const ds = computeDenySet(approved, { homeDir: HOME, platform: "darwin" });
    const profile = generateProfile(approved, { homeDir: HOME });
    for (const p of ds.deniedPaths) {
      assert.ok(profile.includes(p), `profile must deny ${p} (deny-set/profile drift)`);
    }
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/sandbox/test/deny-set.test.ts
```

Expected: FAIL — cannot find module `../src/deny-set.js`.

- [ ] **Step 3: Implement `packages/sandbox/src/deny-set.ts`**

```ts
import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";

/** The concrete resources the sandbox profile denies, for runtime-violation attribution. */
export interface DenySet {
  /** Expanded, canonicalized (darwin) absolute paths the profile denies. */
  deniedPaths: string[];
  /** True when the profile denies all network (no approved `network` capability). */
  networkDenied: boolean;
}

/** Expand a `~`-relative path against homeDir. */
export function expandHome(p: string, homeDir: string): string {
  return p.startsWith("~") ? homeDir + p.slice(1) : p;
}

/**
 * macOS firmlinks: sandbox-exec matches the canonical /private path, not the alias.
 * /etc, /var, /tmp are firmlinks to /private/etc, /private/var, /private/tmp.
 * Pure mapping (no fs calls) — these roots are stable macOS facts.
 */
export function canonicalizeMacPath(p: string): string {
  for (const root of ["/etc", "/var", "/tmp"]) {
    if (p === root || p.startsWith(root + "/")) return "/private" + p;
  }
  return p;
}

/**
 * The deny set the sandbox profile enforces, for classifying a runtime violation.
 * Mirrors `generateProfile`/`generateBwrapArgs`: a SENSITIVE_PATHS entry is denied
 * unless an approved filesystem capability covers it; network is denied unless an
 * approved `network` capability is present. Pure: same inputs ⇒ same DenySet.
 */
export function computeDenySet(
  approved: Capability[],
  opts: { homeDir: string; platform: "darwin" | "linux" },
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
  return { deniedPaths, networkDenied };
}
```

- [ ] **Step 4: Refactor `profile.ts` to share the helpers** — replace its local `canonicalizeMacPath` and inline `expand` with imports; behavior unchanged. New top of file:

```ts
import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";
import { canonicalizeMacPath, expandHome } from "./deny-set.js";
```

Delete the local `canonicalizeMacPath` function (lines 4–14 of the original). In `generateProfile`, replace `const expand = (p) => …` usage with `expandHome(p, opts.homeDir)`:

```ts
export function generateProfile(approved: Capability[], opts: { homeDir: string }): string {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");

  const lines = ["(version 1)", "(allow default)"];
  const denyFor = (mode: "read" | "write", op: "file-read*" | "file-write*") => {
    for (const sp of sensitivePathsFor("darwin")) {
      if (!sp.modes.includes(mode)) continue;
      const uncovered = sp.denyPaths.filter((dp) => !approvedFs.some((t) => pathCovers(t, dp)));
      if (uncovered.length === 0) continue;
      const items = uncovered.map((dp) => `(${sp.denyKind} "${canonicalizeMacPath(expandHome(dp, opts.homeDir))}")`).join(" ");
      lines.push(`(deny ${op} ${items})`);
    }
  };
  denyFor("read", "file-read*");
  denyFor("write", "file-write*");
  if (!hasNetwork) lines.push("(deny network*)");
  return lines.join("\n") + "\n";
}
```

- [ ] **Step 5: Refactor `bwrap.ts` to share `expandHome`** — replace its local `const expand` with the import:

```ts
import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";
import { expandHome } from "./deny-set.js";
```

In `generateBwrapArgs` replace `const expand = …;` and `const target = expand(dp);` with `const target = expandHome(dp, opts.homeDir);`.

- [ ] **Step 6: Export from `index.ts`** — add:

```ts
export { computeDenySet, expandHome, canonicalizeMacPath, type DenySet } from "./deny-set.js";
```

- [ ] **Step 7: Run deny-set + the existing profile/bwrap suites**

```bash
npx tsx --test packages/sandbox/test/deny-set.test.ts packages/sandbox/test/profile.test.ts packages/sandbox/test/bwrap.test.ts
npm run build
```

Expected: all PASS (the refactor is behavior-preserving; profile/bwrap tests prove it).

- [ ] **Step 8: Commit**

```bash
git add packages/sandbox/src/deny-set.ts packages/sandbox/src/profile.ts packages/sandbox/src/bwrap.ts packages/sandbox/src/index.ts packages/sandbox/test/deny-set.test.ts
git commit -m "feat(phase10): computeDenySet — shared deny-set derivation for violation attribution"
```

---

### Task 2: `classifyViolation` + `SandboxResult.violation`

**Files:**
- Create: `packages/sandbox/src/violation.ts`
- Modify: `packages/sandbox/src/types.ts`
- Modify: `packages/sandbox/src/index.ts` (exports)
- Test: `packages/sandbox/test/violation.test.ts`

**Interfaces:**
- Consumes: `DenySet` (Task 1).
- Produces (used by Tasks 3, 5):
  - `interface SandboxViolation { kind: "filesystem" | "network" | "process"; target: string | null; confidence: "confirmed" | "suspected"; deniedResource: string | null; evidence: { exitCode: number; stderrExcerpt: string } }`
  - `SandboxResult` gains `violation?: SandboxViolation`.
  - `classifyViolation(result: SandboxResult, denySet: DenySet): SandboxViolation | null`.

- [ ] **Step 1: Update `types.ts`** — add the import and fields:

```ts
import type { Capability } from "@sentinel/core";

export interface SandboxViolation {
  /** The denied resource class the child hit. */
  kind: "filesystem" | "network" | "process";
  /** Extracted path or host:port from the child's error, or null if not attributable. */
  target: string | null;
  /** confirmed: target matches the deny set. suspected: class-denied but no attributable target. */
  confidence: "confirmed" | "suspected";
  /** The deny-set entry matched (a denied path, or "network"); null when suspected without a match. */
  deniedResource: string | null;
  /** Redaction-safe evidence: the child's exit code and the single matched error line (≤200 chars). */
  evidence: { exitCode: number; stderrExcerpt: string };
}

export interface SandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  /** A runtime violation inferred from a permission-error exit, when one was detected (Phase 10). */
  violation?: SandboxViolation;
}
```

(Keep the existing `Sandbox` interface unchanged.)

- [ ] **Step 2: Write the failing test** (`packages/sandbox/test/violation.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { classifyViolation } from "../src/violation.js";
import type { DenySet } from "../src/deny-set.js";
import type { SandboxResult } from "../src/types.js";

const denySet: DenySet = { deniedPaths: ["/Users/test/.ssh", "/private/etc/passwd"], networkDenied: true };
const ok = (over: Partial<SandboxResult>): SandboxResult => ({ exitCode: 0, stdout: "", stderr: "", ...over });

describe("classifyViolation", () => {
  test("confirmed filesystem: EPERM on a denied path", () => {
    const r = ok({ exitCode: 1, stderr: "Error: EPERM: operation not permitted, open '/Users/test/.ssh/id_rsa'" });
    const v = classifyViolation(r, denySet);
    assert.equal(v?.kind, "filesystem");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.target, "/Users/test/.ssh/id_rsa");
    assert.equal(v?.deniedResource, "/Users/test/.ssh");
  });

  test("confirmed network: connect EPERM under network-denied", () => {
    const r = ok({ exitCode: 1, stderr: "Error: connect EPERM 198.51.100.7:443" });
    const v = classifyViolation(r, denySet);
    assert.equal(v?.kind, "network");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.target, "198.51.100.7:443");
    assert.equal(v?.deniedResource, "network");
  });

  test("none: ambient EPERM on a NON-denied path is not a violation (false-positive guard)", () => {
    const r = ok({ exitCode: 1, stderr: "EPERM: operation not permitted, open '/build/cache/x'" });
    assert.equal(classifyViolation(r, denySet), null);
  });

  test("suspected: network EPERM with no parseable host, under network-denied", () => {
    const r = ok({ exitCode: 1, stderr: "Error: connect EPERM (address hidden)" });
    const v = classifyViolation(r, denySet);
    assert.equal(v?.confidence, "suspected");
    assert.equal(v?.kind, "network");
    assert.equal(v?.target, null);
  });

  test("none: non-zero exit with no permission-error signature (ordinary build failure)", () => {
    assert.equal(classifyViolation(ok({ exitCode: 2, stderr: "SyntaxError: unexpected token" }), denySet), null);
  });

  test("none: exit 0 (a swallowed denial leaves no signal — documented limitation)", () => {
    assert.equal(classifyViolation(ok({ exitCode: 0, stderr: "EPERM: operation not permitted, open '/Users/test/.ssh/id_rsa'" }), denySet), null);
  });

  test("none: network EPERM but network was approved (not denied)", () => {
    const r = ok({ exitCode: 1, stderr: "connect EPERM 198.51.100.7:443" });
    assert.equal(classifyViolation(r, { deniedPaths: [], networkDenied: false }), null);
  });

  test("linux EACCES on a denied path is confirmed", () => {
    const r = ok({ exitCode: 1, stderr: "Error: EACCES: permission denied, open '/Users/test/.ssh/config'" });
    assert.equal(classifyViolation(r, denySet)?.confidence, "confirmed");
  });

  test("stderrExcerpt is truncated to <= 200 chars", () => {
    const long = "EPERM: operation not permitted, open '/Users/test/.ssh/id_rsa' " + "x".repeat(500);
    const v = classifyViolation(ok({ exitCode: 1, stderr: long }), denySet);
    assert.ok((v?.evidence.stderrExcerpt.length ?? 0) <= 200);
  });
});
```

- [ ] **Step 3: Run to verify it fails**

```bash
npx tsx --test packages/sandbox/test/violation.test.ts
```

Expected: FAIL — cannot find module `../src/violation.js`.

- [ ] **Step 4: Implement `packages/sandbox/src/violation.ts`**

```ts
import type { DenySet } from "./deny-set.js";
import { pathCovers } from "./path-cover.js";
import type { SandboxResult, SandboxViolation } from "./types.js";

const FS_ERROR = /(?:EPERM|EACCES|ENOENT)[^\n]*?['"]([^'"\n]+)['"]/;
const NET_ERROR = /connect (?:EPERM|EACCES) ([0-9.]+):(\d+)/;
const NET_CLASS = /connect (?:EPERM|EACCES)/;
const PERM_SIGNATURE = /EPERM|EACCES|operation not permitted|permission denied/i;

function firstMatchingLine(stderr: string, re: RegExp): string | null {
  for (const line of stderr.split(/\r?\n/)) if (re.test(line)) return line.trim();
  return null;
}

function excerpt(line: string): string {
  return line.length > 200 ? line.slice(0, 199) + "…" : line;
}

/**
 * Infer a runtime violation from a sandboxed child's failure. Pure and total:
 * returns null when there is no surfacing permission-error signal. The deny set is
 * ground truth — a permission error on a resource we did NOT deny is ambient, not a
 * violation (the false-positive filter). Only detects violations that SURFACE as
 * process failure; a swallowed denial (exit 0, clean stderr) is invisible here but
 * still contained by the sandbox.
 */
export function classifyViolation(result: SandboxResult, denySet: DenySet): SandboxViolation | null {
  if (result.exitCode === 0) return null;
  const stderr = result.stderr ?? "";
  if (!PERM_SIGNATURE.test(stderr)) return null;

  // Network: attributable host:port, or class-denied suspected.
  const netLine = firstMatchingLine(stderr, NET_CLASS);
  if (netLine && denySet.networkDenied) {
    const m = NET_ERROR.exec(stderr);
    const target = m ? `${m[1]}:${m[2]}` : null;
    return {
      kind: "network", target,
      confidence: target ? "confirmed" : "suspected",
      deniedResource: target ? "network" : null,
      evidence: { exitCode: result.exitCode, stderrExcerpt: excerpt(netLine) },
    };
  }

  // Filesystem: attributable path that falls inside a denied path.
  const fsLine = firstMatchingLine(stderr, FS_ERROR);
  if (fsLine) {
    const m = FS_ERROR.exec(fsLine);
    const target = m?.[1] ?? null;
    // pathCovers is segment-anchored: true iff denied path is an ancestor-or-equal of
    // the hit target. This IS the false-positive filter — an EPERM on a non-denied path
    // matches nothing and returns null (ambient, not our sandbox).
    const matched = target ? denySet.deniedPaths.find((dp) => pathCovers(dp, target)) : undefined;
    if (target && matched) {
      return {
        kind: "filesystem", target, confidence: "confirmed", deniedResource: matched,
        evidence: { exitCode: result.exitCode, stderrExcerpt: excerpt(fsLine) },
      };
    }
    // A permission error on a path we didn't deny → ambient, not our sandbox.
    return null;
  }

  return null;
}
```

- [ ] **Step 5: Export from `index.ts`** — add:

```ts
export { classifyViolation } from "./violation.js";
export type { SandboxViolation } from "./types.js";
```

- [ ] **Step 6: Run the test**

```bash
npx tsx --test packages/sandbox/test/violation.test.ts
npm run build
```

Expected: PASS (all violation.test.ts cases).

- [ ] **Step 7: Commit**

```bash
git add packages/sandbox/src/violation.ts packages/sandbox/src/types.ts packages/sandbox/src/index.ts packages/sandbox/test/violation.test.ts
git commit -m "feat(phase10): classifyViolation — infer + attribute a runtime violation from a sandboxed failure"
```

---

### Task 3: Wire the sensor into both runners

**Files:**
- Modify: `packages/sandbox/src/seatbelt.ts`
- Modify: `packages/sandbox/src/bubblewrap.ts`
- Test: `packages/sandbox/test/seatbelt.test.ts` (add a violation effect test; darwin-gated)

**Interfaces:**
- Consumes: `computeDenySet` (Task 1), `classifyViolation` (Task 2).
- Produces: both runners populate `SandboxResult.violation` when a violation is detected. Consumed by Task 6 (script-shell) and Task 7 (e2e).

- [ ] **Step 1: Add the violation effect test to `seatbelt.test.ts`** (inside the darwin-gated `describe("SeatbeltSandbox enforcement", …)`)

```ts
  test("a denied credential read surfaces a confirmed runtime violation", () => {
    const home = mkdtempSync(join(tmpdir(), "sentinel-home-"));
    // A propagating probe: let the EPERM print to stderr and exit non-zero.
    const cmd = `node -e "require('fs').readFileSync(require('path').join(process.env.HOME,'.ssh','id_rsa'))"`;
    const r = new SeatbeltSandbox().run(cmd, { cwd: tmpdir(), approved: [], homeDir: home, env: { ...process.env, HOME: home } });
    assert.notEqual(r.exitCode, 0, "positive control: the denied read must fail the process");
    assert.equal(r.violation?.kind, "filesystem");
    assert.equal(r.violation?.confidence, "confirmed");
    assert.ok(r.violation?.target?.includes(".ssh"), "target must name the ssh path");
  });
```

(Use whatever `mkdtempSync`/`join`/`tmpdir` imports the file already has; add any missing.)

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/sandbox/test/seatbelt.test.ts
```

Expected (on darwin): FAIL — `r.violation` is undefined (runner doesn't classify yet).

- [ ] **Step 3: Wire `seatbelt.ts`** — compute the deny set and classify. Replace the `return { … }` success branch:

```ts
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Capability } from "@sentinel/core";
import type { Sandbox, SandboxResult } from "./types.js";
import { generateProfile } from "./profile.js";
import { computeDenySet } from "./deny-set.js";
import { classifyViolation } from "./violation.js";
```

In `run`, after building `res`:

```ts
      if (res.error) {
        return { exitCode: 127, stdout: "", stderr: res.error.message };
      }
      const result: SandboxResult = {
        exitCode: res.status ?? (res.signal ? 1 : 0),
        stdout: res.stdout ?? "",
        stderr: res.stderr ?? "",
      };
      const denySet = computeDenySet(opts.approved, { homeDir: opts.homeDir, platform: "darwin" });
      const violation = classifyViolation(result, denySet);
      return violation ? { ...result, violation } : result;
```

- [ ] **Step 4: Wire `bubblewrap.ts` identically** (platform `"linux"`). Add the imports and, before the final `return`:

```ts
    const result: SandboxResult = {
      exitCode: res.status ?? (res.signal ? 1 : 0),
      stdout: res.stdout ?? "",
      stderr: res.stderr ?? "",
    };
    const denySet = computeDenySet(opts.approved, { homeDir: opts.homeDir, platform: "linux" });
    const violation = classifyViolation(result, denySet);
    return violation ? { ...result, violation } : result;
```

- [ ] **Step 5: Run the sandbox suite**

```bash
npm run build
npx tsx --test packages/sandbox/test/seatbelt.test.ts packages/sandbox/test/bwrap.test.ts packages/sandbox/test/violation.test.ts
```

Expected (darwin): PASS incl. the new violation effect test.

- [ ] **Step 6: Commit**

```bash
git add packages/sandbox/src/seatbelt.ts packages/sandbox/src/bubblewrap.ts packages/sandbox/test/seatbelt.test.ts
git commit -m "feat(phase10): runners attach a classified runtime violation to SandboxResult"
```

---

### Task 4: `ViolationStore` + core `runtime-violation` overlay helper

**Files:**
- Create: `packages/proxy/src/violations.ts`
- Modify: `packages/core/src/index.ts` (export a finding factory) OR keep in proxy — see step
- Test: `packages/proxy/test/violations-store.test.ts`

**Interfaces:**
- Produces (used by Task 5):
  - `interface ViolationRecord { name; version; integrity; kind; target: string|null; confidence: "confirmed"|"suspected"; deniedResource: string|null; evidence: { exitCode: number; stderrExcerpt: string }; quarantined: boolean; reportedAt: string }`
  - `class ViolationStore` with `record(v): ViolationRecord`, `get(integrity): ViolationRecord | undefined`, `isQuarantined(integrity): boolean`, `clear(integrity): boolean`, `recent(limit?): ViolationRecord[]`.

- [ ] **Step 1: Write the failing test** (`packages/proxy/test/violations-store.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { ViolationStore } from "../src/violations.js";

const base = {
  name: "evil", version: "1.0.0", integrity: "sha512-AAA",
  kind: "filesystem" as const, target: "/Users/x/.ssh/id_rsa",
  confidence: "confirmed" as const, deniedResource: "/Users/x/.ssh",
  evidence: { exitCode: 1, stderrExcerpt: "EPERM ..." },
};

describe("ViolationStore", () => {
  test("a confirmed violation is recorded and quarantines the integrity", () => {
    const s = new ViolationStore();
    const rec = s.record(base);
    assert.equal(rec.quarantined, true);
    assert.equal(s.isQuarantined("sha512-AAA"), true);
    assert.equal(s.get("sha512-AAA")?.target, "/Users/x/.ssh/id_rsa");
  });

  test("a suspected violation is recorded but does NOT quarantine", () => {
    const s = new ViolationStore();
    const rec = s.record({ ...base, confidence: "suspected", target: null, deniedResource: null });
    assert.equal(rec.quarantined, false);
    assert.equal(s.isQuarantined("sha512-AAA"), false);
  });

  test("idempotent on (integrity, kind, target): no duplicate records", () => {
    const s = new ViolationStore();
    s.record(base);
    s.record(base);
    assert.equal(s.recent().length, 1);
  });

  test("clear removes the quarantine", () => {
    const s = new ViolationStore();
    s.record(base);
    assert.equal(s.clear("sha512-AAA"), true);
    assert.equal(s.isQuarantined("sha512-AAA"), false);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/violations-store.test.ts
```

Expected: FAIL — cannot find module `../src/violations.js`.

- [ ] **Step 3: Implement `packages/proxy/src/violations.ts`** (mirror `ApprovalStore`'s in-memory + optional-file shape)

```ts
import { existsSync, readFileSync, writeFileSync } from "node:fs";

export interface ViolationInput {
  name: string;
  version: string;
  integrity: string;
  kind: "filesystem" | "network" | "process";
  target: string | null;
  confidence: "confirmed" | "suspected";
  deniedResource: string | null;
  evidence: { exitCode: number; stderrExcerpt: string };
}

export interface ViolationRecord extends ViolationInput {
  quarantined: boolean;
  reportedAt: string; // ISO-8601
}

/** Runtime-violation telemetry, integrity-keyed. Confirmed violations quarantine the build. */
export class ViolationStore {
  private byIntegrity = new Map<string, ViolationRecord>();
  private order: string[] = [];

  constructor(private readonly file?: string) {
    if (file && existsSync(file)) {
      try {
        for (const r of JSON.parse(readFileSync(file, "utf8")) as ViolationRecord[]) this.index(r);
      } catch {
        /* start empty on a corrupt log */
      }
    }
  }

  record(v: ViolationInput, now = new Date().toISOString()): ViolationRecord {
    const existing = this.byIntegrity.get(v.integrity);
    if (existing && existing.kind === v.kind && existing.target === v.target) return existing;
    const rec: ViolationRecord = { ...v, quarantined: v.confidence === "confirmed", reportedAt: now };
    this.index(rec);
    this.persist();
    return rec;
  }

  get(integrity: string | null | undefined): ViolationRecord | undefined {
    return integrity ? this.byIntegrity.get(integrity) : undefined;
  }

  isQuarantined(integrity: string | null | undefined): boolean {
    return Boolean(integrity && this.byIntegrity.get(integrity)?.quarantined);
  }

  clear(integrity: string): boolean {
    const had = this.byIntegrity.delete(integrity);
    if (had) {
      this.order = this.order.filter((k) => k !== integrity);
      this.persist();
    }
    return had;
  }

  recent(limit = 50): ViolationRecord[] {
    return this.order.slice(-limit).reverse()
      .map((k) => this.byIntegrity.get(k))
      .filter((x): x is ViolationRecord => Boolean(x));
  }

  private index(r: ViolationRecord): void {
    if (!this.byIntegrity.has(r.integrity)) this.order.push(r.integrity);
    this.byIntegrity.set(r.integrity, r);
  }

  private persist(): void {
    if (!this.file) return;
    try {
      writeFileSync(this.file, JSON.stringify([...this.byIntegrity.values()], null, 2));
    } catch {
      /* best-effort */
    }
  }
}
```

- [ ] **Step 4: Run the test**

```bash
npx tsx --test packages/proxy/test/violations-store.test.ts
npm run build
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/violations.ts packages/proxy/test/violations-store.test.ts
git commit -m "feat(phase10): ViolationStore — integrity-keyed runtime-violation records + quarantine flag"
```

---

### Task 5: Server — `/-/violations` endpoint, quarantine overlay, header, wiring

**Files:**
- Modify: `packages/proxy/src/server.ts` (ServerOptions, endpoints, gateAndSend overlay)
- Modify: `packages/proxy/src/index.ts` (construct + pass ViolationStore)
- Test: `packages/proxy/test/violations-e2e.test.ts`

**Interfaces:**
- Consumes: `ViolationStore` (Task 4), `SandboxViolation` shape (Task 2).
- Produces: `ServerOptions.violations: ViolationStore`; routes `POST /-/violations`, `GET /-/violations`, `DELETE /-/violations/:integrity`; `x-sentinel-violations` header; a quarantined integrity serves `block` with a `runtime-violation` finding.

- [ ] **Step 1: Write the failing e2e test** (`packages/proxy/test/violations-e2e.test.ts`)

```ts
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type AuditReport } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

describe("runtime violation reporting + quarantine (e2e)", () => {
  let server: Server; let base: string; let violations: ViolationStore; let approvals: ApprovalStore;
  before(async () => {
    ensureFixtures();
    violations = new ViolationStore();
    approvals = new ApprovalStore();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
      approvals, enterprisePolicy: DEFAULT_POLICY, policy: "block",
      privateStore: new PrivatePackageStore(), violations,
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  async function integrityOf(pkg: string, version: string): Promise<string> {
    const rep = await (await fetch(`${base}/-/audit/${pkg}/${version}`)).json() as AuditReport;
    return rep.meta.integrity!;
  }

  test("a confirmed violation quarantines the integrity → next serve 403s with runtime-violation", async () => {
    const integrity = await integrityOf("leftpad-lite", "1.0.0");
    // Serve succeeds before any violation.
    assert.equal((await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`)).status, 200);

    const post = await fetch(`${base}/-/violations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "leftpad-lite", version: "1.0.0", integrity,
        kind: "filesystem", target: "/home/x/.ssh/id_rsa", confidence: "confirmed",
        deniedResource: "/home/x/.ssh", evidence: { exitCode: 1, stderrExcerpt: "EPERM ..." },
      }),
    });
    assert.equal(post.status, 200);

    const res = await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`);
    assert.equal(res.status, 403);
    const body = await res.json() as { findings: { ruleId: string }[] };
    assert.ok(body.findings.some((f) => f.ruleId === "runtime-violation"));
  });

  test("a suspected violation is recorded but does NOT quarantine", async () => {
    const integrity = await integrityOf("net-fetch-lite", "1.0.0");
    await fetch(`${base}/-/violations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "net-fetch-lite", version: "1.0.0", integrity,
        kind: "network", target: null, confidence: "suspected",
        deniedResource: null, evidence: { exitCode: 1, stderrExcerpt: "connect EPERM" },
      }),
    });
    assert.equal((await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.0.tgz`)).status, 200);
  });

  test("DELETE clears the quarantine", async () => {
    const integrity = await integrityOf("leftpad-lite", "1.0.0");
    await fetch(`${base}/-/violations/${encodeURIComponent(integrity)}`, { method: "DELETE" });
    assert.equal((await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`)).status, 200);
  });

  test("POST for an un-audited integrity is rejected 400", async () => {
    const res = await fetch(`${base}/-/violations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "x", version: "1.0.0", integrity: "sha512-UNKNOWN", kind: "filesystem", target: "/a", confidence: "confirmed", deniedResource: "/a", evidence: { exitCode: 1, stderrExcerpt: "" } }),
    });
    assert.equal(res.status, 400);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/violations-e2e.test.ts
```

Expected: FAIL — `ServerOptions` has no `violations`; routes 404.

- [ ] **Step 3: Implement `server.ts`**

Add to imports:

```ts
import { ViolationStore, type ViolationInput } from "./violations.js";
```

Add to `ServerOptions`:

```ts
  /** Runtime-violation telemetry store (Phase 10). */
  violations: ViolationStore;
```

Bind it in `createServer`: `const violations = opts.violations;`

A quarantine-overlay helper (near `reconcile`):

```ts
  /** Overlay a quarantine on a served report: inject a critical runtime-violation finding + force block. */
  function applyQuarantine(report: AuditReport): AuditReport {
    const rec = violations.get(report.meta.integrity);
    if (!rec?.quarantined) return report;
    const finding = {
      ruleId: "runtime-violation", category: "install-script" as const, severity: "critical" as const,
      message: `runtime violation: ${rec.kind} access to ${rec.target ?? rec.deniedResource ?? "a denied resource"} blocked at install time — build quarantined`,
      onChangedFile: false, evidence: [], weight: 0, waived: false,
    };
    return { ...report, verdict: "block", findings: [finding, ...report.findings] };
  }
```

In `gateAndSend`, compute the effective report at the top and set the header:

```ts
  function gateAndSend(res: Response, pkg: string, version: string, report: AuditReport, tarball: Buffer, isPrivate: boolean): Response | void {
    report = applyQuarantine(report);
    const rec = reconcile(report);
    res.setHeader("x-sentinel-score", String(report.score));
    res.setHeader("x-sentinel-verdict", report.verdict);
    res.setHeader("x-sentinel-violations", String(violations.get(report.meta.integrity) ? 1 : 0));
    // … existing headers …
```

(The existing `if (policy === "block") { if (report.verdict === "block") …` block then 403s with the runtime-violation finding automatically, since `applyQuarantine` forced `block` and prepended the finding.)

Endpoints (near the `/-/approvals` routes):

```ts
  app.post("/-/violations", (req, res) => {
    const v = req.body as Partial<ViolationInput>;
    if (!v || typeof v.integrity !== "string" || typeof v.name !== "string" || typeof v.version !== "string" ||
        (v.confidence !== "confirmed" && v.confidence !== "suspected") ||
        (v.kind !== "filesystem" && v.kind !== "network" && v.kind !== "process")) {
      return res.status(400).json({ error: "invalid violation: need name, version, integrity, kind, confidence" });
    }
    if (!store.get(v.integrity)) {
      return res.status(400).json({ error: `no audited report for integrity ${v.integrity} — audit before reporting` });
    }
    const rec = violations.record({
      name: v.name, version: v.version, integrity: v.integrity, kind: v.kind,
      target: v.target ?? null, confidence: v.confidence, deniedResource: v.deniedResource ?? null,
      evidence: { exitCode: v.evidence?.exitCode ?? 0, stderrExcerpt: String(v.evidence?.stderrExcerpt ?? "").slice(0, 200) },
    });
    if (rec.quarantined) {
      approvals.remove(v.integrity); // revoke any standing approval for a quarantined build
      console.log(`[violation] quarantined ${v.name}@${v.version} (${rec.kind} → ${rec.target ?? rec.deniedResource})`);
    }
    res.json({ recorded: rec });
  });

  app.get("/-/violations", (_req, res) => {
    res.json({ violations: violations.recent(50) });
  });

  app.delete(/^\/-\/violations\/(.+)$/, (req, res) => {
    const integrity = decodeURIComponent(req.params[0] ?? "");
    res.json({ cleared: violations.clear(integrity) });
  });
```

- [ ] **Step 4: Wire `packages/proxy/src/index.ts`** — construct and pass the store:

```ts
import { ViolationStore } from "./violations.js";
```

Add `export { ViolationStore } from "./violations.js";` beside the other store exports. In `main()`:

```ts
  const violations = new ViolationStore(process.env.SENTINEL_VIOLATIONS);
```

Add `violations` to the `createServer({ … })` options. Add a boot log line: `` console.log(`  violations: ${process.env.SENTINEL_VIOLATIONS ? "persisted" : "in-memory"}`); ``

- [ ] **Step 5: Fix any other `createServer` call sites** — every test that calls `createServer` now needs a `violations: new ViolationStore()`. The compiler/test run will flag them; add it to each (grep `createServer({` under `packages/proxy/test`). This is a required, mechanical addition.

- [ ] **Step 6: Run the new e2e + neighbors**

```bash
npm run build
npx tsx --test packages/proxy/test/violations-e2e.test.ts packages/proxy/test/violations-store.test.ts packages/proxy/test/proxy.test.ts packages/proxy/test/approvals.test.ts
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/src/index.ts packages/proxy/test/violations-e2e.test.ts
git commit -m "feat(phase10): /-/violations endpoint + serve-time quarantine overlay + x-sentinel-violations header"
```

---

### Task 6: `sentinel-script-shell` reports the violation

**Files:**
- Modify: `packages/cli/src/script-shell.ts`
- Test: `packages/cli/test/script-shell-report.test.ts` (unit: the report POST, with a stub fetch)

**Interfaces:**
- Consumes: `SandboxResult.violation` (Task 3), `POST /-/violations` (Task 5).
- Produces: when `result.violation` is present and `SENTINEL_PROXY`/name/version are set, `script-shell` POSTs the violation before exiting; a POST failure never changes the exit code.

- [ ] **Step 1: Add a reportViolation helper + call it in `script-shell.ts`**

After `const r = sandbox.run(...)` and before writing stdout/stderr, add:

```ts
  if (r.violation && process.env.SENTINEL_PROXY && name && version) {
    await reportViolation(process.env.SENTINEL_PROXY, name, version, r.violation);
  }
```

Add the helper (module scope). Since the shell doesn't have the served integrity, resolve it from the manifest already fetched for dependencies; for the root script (which has no proxy manifest) skip integrity-less reporting. To keep it simple and correct, fetch the manifest to get integrity when not already known:

```ts
import type { SandboxViolation } from "@sentinel/sandbox";

async function reportViolation(proxy: string, name: string, version: string, violation: SandboxViolation): Promise<void> {
  try {
    const man = await fetch(`${proxy}/-/manifest/${encodeURIComponent(name)}/${encodeURIComponent(version)}`);
    if (!man.ok) return;
    const integrity = ((await man.json()) as { meta?: { integrity?: string } }).meta?.integrity;
    if (!integrity) return;
    await fetch(`${proxy}/-/violations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name, version, integrity, ...violation }),
    });
  } catch {
    /* telemetry is best-effort: a reporting failure never changes the install outcome */
  }
}
```

(Confirm `@sentinel/sandbox` exports `SandboxViolation` — Task 2 added it. `manifest` returns `{ meta, … }` per server.ts's `/-/manifest` route.)

- [ ] **Step 2: Write a unit test** (`packages/cli/test/script-shell-report.test.ts`) that exercises `reportViolation` against a stub server. Export `reportViolation` from script-shell.ts for testability (add `export`):

```ts
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import { createServer, type Server } from "node:http";
import { reportViolation } from "../src/script-shell.js";

describe("reportViolation", () => {
  let server: Server; let base: string; const posts: any[] = [];
  before(async () => {
    server = createServer((req, res) => {
      if (req.url?.startsWith("/-/manifest/")) { res.setHeader("content-type", "application/json"); return res.end(JSON.stringify({ meta: { integrity: "sha512-XYZ" } })); }
      if (req.url === "/-/violations" && req.method === "POST") {
        let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { posts.push(JSON.parse(b)); res.end("{}"); }); return;
      }
      res.statusCode = 404; res.end();
    });
    await new Promise<void>((r) => server.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }));
  });
  after(() => server.close());

  test("posts the violation with the manifest integrity", async () => {
    await reportViolation(base, "evil", "1.0.0", { kind: "filesystem", target: "/x/.ssh/id_rsa", confidence: "confirmed", deniedResource: "/x/.ssh", evidence: { exitCode: 1, stderrExcerpt: "EPERM" } });
    assert.equal(posts.length, 1);
    assert.equal(posts[0].integrity, "sha512-XYZ");
    assert.equal(posts[0].confidence, "confirmed");
  });

  test("a proxy error is swallowed (no throw)", async () => {
    await assert.doesNotReject(reportViolation("http://127.0.0.1:1", "x", "1.0.0", { kind: "network", target: null, confidence: "suspected", deniedResource: null, evidence: { exitCode: 1, stderrExcerpt: "" } }));
  });
});
```

- [ ] **Step 3: Run to verify RED then implement** — run the test (fails: `reportViolation` not exported), add `export` to the helper, re-run.

```bash
npx tsx --test packages/cli/test/script-shell-report.test.ts
```

Expected after export: PASS.

- [ ] **Step 4: Build + run the enforce e2e to confirm no regression**

```bash
npm run build
npx tsx --test packages/proxy/test/enforce-e2e.test.ts packages/cli/test/script-shell-report.test.ts
```

Expected: PASS (enforce-e2e still green; the swallowing enforce-probe produces no violation, exit 0 — unchanged).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/script-shell.ts packages/cli/test/script-shell-report.test.ts
git commit -m "feat(phase10): sentinel-script-shell reports a detected runtime violation to the proxy (best-effort)"
```

---

### Task 7: Propagating violation fixtures + full enforce→report→quarantine e2e

**Files:**
- Create: `fixtures/benign/violation-fs-probe/1.0.0/package/{package.json,index.js,probe.js}`
- Create: `fixtures/benign/violation-net-probe/1.0.0/package/{package.json,index.js,probe.js}`
- Modify: `fixtures/index.json`
- Test: `packages/proxy/test/violation-enforce-e2e.test.ts` (darwin-gated, mirrors enforce-e2e)

**Interfaces:**
- Consumes: the full chain (Tasks 3, 5, 6).
- Produces: fixtures that PROPAGATE a denied action; an e2e proving install-under-enforce → violation reported → integrity quarantined → re-serve 403s.

- [ ] **Step 1: Create `violation-fs-probe`** package files.

`package.json`:

```json
{
  "name": "violation-fs-probe",
  "version": "1.0.0",
  "description": "SYNTHETIC BENIGN FIXTURE — postinstall attempts an undeclared ssh read and lets the EPERM propagate (exit non-zero) so the telemetry sensor detects it. Reads nothing it isn't denied; no exfiltration.",
  "scripts": { "postinstall": "node probe.js" }
}
```

`index.js`: `module.exports = {};`

`probe.js`:

```js
// SYNTHETIC BENIGN FIXTURE. Unlike enforce-probe (which swallows), this PROPAGATES the
// denial so the runtime-violation sensor has a surfacing signal. Path built from string
// fragments so static analysis emits only a generic filesystem target (covers nothing →
// denied even when approved). No network, no exfiltration.
const fs = require("fs");
const os = require("os");
const p = require("path");
const key = p.join(os.homedir(), "." + "ssh", "id_" + "rsa");
fs.readFileSync(key); // denied → EPERM propagates → non-zero exit + stderr signature
```

- [ ] **Step 2: Create `violation-net-probe`** package files.

`package.json`:

```json
{
  "name": "violation-net-probe",
  "version": "1.0.0",
  "description": "SYNTHETIC BENIGN FIXTURE — postinstall attempts an undeclared connect to an RFC 5737 documentation IP and lets the EPERM propagate. No data sent; connection is denied by the sandbox.",
  "scripts": { "postinstall": "node probe.js" }
}
```

`index.js`: `module.exports = {};`

`probe.js`:

```js
// SYNTHETIC BENIGN FIXTURE. Attempts a connect to a documentation IP (RFC 5737,
// 198.51.100.0/24) and lets the sandbox's network denial surface as a non-zero exit.
// No data is sent; the connection never establishes.
const net = require("net");
const s = net.connect(443, "198.51.100.7");
s.on("error", (e) => { console.error(e.message); process.exit(1); });
s.on("connect", () => { s.destroy(); process.exit(0); });
```

- [ ] **Step 3: Register both in `fixtures/index.json`** (benign class, no signature/provenance needed — add minimal entries mirroring `enforce-probe`'s):

```json
    "violation-fs-probe": {
      "class": "benign",
      "versions": { "1.0.0": { "signature": "valid", "provenance": false } }
    },
    "violation-net-probe": {
      "class": "benign",
      "versions": { "1.0.0": { "signature": "valid", "provenance": false } }
    }
```

- [ ] **Step 4: Rebuild fixtures + confirm both pack and score `allow`**

```bash
npm run fixtures
node -e "const r=require('./fixtures/registry.json'); for (const n of ['violation-fs-probe','violation-net-probe']) if(!r.packages[n]) throw new Error('missing '+n); console.log('fixtures OK')"
```

Expected: `fixtures OK`. (Both must score `allow` so they install under `block` policy — the postinstall command is `node probe.js`, a script-file invocation scoring low, like enforce-probe.)

- [ ] **Step 5: Write the darwin-gated enforce→quarantine e2e** (`packages/proxy/test/violation-enforce-e2e.test.ts`) — model it on `enforce-e2e.test.ts` (same boot, same `spawn`-based enforced install into a temp HOME with `npm_config_script_shell` shim + `SENTINEL_ENFORCE=1` + `SENTINEL_PROXY=base`). After approving and installing `violation-fs-probe@1.0.0` under enforce:

```ts
  test("ENFORCED: the propagating ssh read is reported and quarantines the build", async () => {
    await enforcedInstall("violation-fs-probe", true); // approves + installs under enforce
    // The script-shell reported the violation during install; the integrity is now quarantined.
    const rep = await (await fetch(`${base}/-/audit/violation-fs-probe/1.0.0`)).json() as AuditReport;
    const integrity = rep.meta.integrity!;
    const listed = await (await fetch(`${base}/-/violations`)).json() as { violations: { integrity: string; kind: string; quarantined: boolean }[] };
    assert.ok(listed.violations.some((v) => v.integrity === integrity && v.kind === "filesystem" && v.quarantined), "a confirmed fs violation must be recorded + quarantined");
    // Re-serving the same build now 403s.
    assert.equal((await fetch(`${base}/violation-fs-probe/-/violation-fs-probe-1.0.0.tgz`)).status, 403);
  });
```

(Reuse enforce-e2e's helper structure verbatim; the key difference is asserting the violation record + the 403 after install, rather than file effects. Include the positive control that the install ran — the fixture's package installs even though its postinstall exits non-zero; note npm may report the postinstall failure, so assert on the violation record, not npm's exit code. If npm aborts on the postinstall non-zero exit, the violation is still reported by the shell before the non-zero propagates — assert the record exists regardless of npm's final status.)

- [ ] **Step 6: Run the e2e (darwin) + full suite**

```bash
npm run build
npx tsx --test packages/proxy/test/violation-enforce-e2e.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS; record the full-suite counts.

- [ ] **Step 7: Commit**

```bash
git add fixtures/benign/violation-fs-probe fixtures/benign/violation-net-probe fixtures/index.json packages/proxy/test/violation-enforce-e2e.test.ts
git commit -m "feat(phase10): propagating violation-probe fixtures + enforce→report→quarantine e2e"
```

---

### Task 8: Surfacing — CLI `violations` command, dashboard panel, audit-tree count

**Files:**
- Modify: `packages/cli/src/index.ts` (add `violations` command)
- Modify: `packages/cli/src/format.ts` (a `formatViolations` renderer)
- Modify: `packages/proxy/public/index.html` (violations panel)
- Modify: `packages/core/src/tree.ts` + `packages/proxy/src/server.ts` (audit-tree violations count) — OPTIONAL, see step
- Test: `packages/cli/test/format-violations.test.ts`

**Interfaces:**
- Consumes: `GET /-/violations` (Task 5).

- [ ] **Step 1: `formatViolations` in `format.ts`** — a renderer for the list:

```ts
export interface ViolationRow {
  name: string; version: string; kind: string; target: string | null;
  confidence: string; quarantined: boolean; evidence: { exitCode: number; stderrExcerpt: string };
}

export function formatViolations(rows: ViolationRow[]): string {
  const L: string[] = ["", c(C.bold, `  runtime violations (${rows.length})`), c(C.gray, `  ${"─".repeat(56)}`)];
  if (rows.length === 0) L.push(c(C.gray, "  none recorded"));
  for (const v of rows) {
    const tag = v.quarantined ? c(C.red, "QUARANTINED") : c(C.yellow, v.confidence.toUpperCase());
    L.push(`  ${tag} ${v.name}@${v.version} ${c(C.gray, `${v.kind} → ${v.target ?? "?"}`)}`);
  }
  L.push("");
  return L.join("\n");
}
```

- [ ] **Step 2: unit test** (`packages/cli/test/format-violations.test.ts`) — assert a quarantined row renders "QUARANTINED" and includes the target; empty list renders "none recorded". (Model on the existing format tests; strip ANSI or set `NO_COLOR`.)

- [ ] **Step 3: `sentinel violations` command in `index.ts`** (near the other `.command(...)`):

```ts
program
  .command("violations")
  .description("List runtime violations recorded by the proxy (quarantined builds).")
  .option("--proxy <url>", "proxy base URL", DEFAULT_PROXY)
  .option("--json", "output raw JSON", false)
  .action(async (opts: { proxy: string; json: boolean }) => {
    const res = await fetch(`${opts.proxy}/-/violations`);
    if (!res.ok) { console.error(`failed: ${res.status}`); process.exit(1); }
    const { violations } = (await res.json()) as { violations: ViolationRow[] };
    if (opts.json) console.log(JSON.stringify(violations, null, 2));
    else console.log(formatViolations(violations));
  });
```

Import `formatViolations, type ViolationRow` from `./format.js`.

- [ ] **Step 4: Dashboard panel in `index.html`** — add a "Runtime violations" section mirroring the Approvals panel: a `<table>` with `id="violation-rows"`, a `loadViolations()` fetching `/-/violations`, a `violationRow(v)` builder (esc all fields; red badge when `quarantined`), and add `loadViolations()` to the initial load + the `setInterval`. Add a `.badge.quarantined { background: rgba(248,81,73,.15); }` style. (Keep it consistent with the existing `approvalRow`/`loadApprovals` code.)

- [ ] **Step 5: audit-tree violations count (small)** — in `server.ts`'s `/-/audit-tree` row mapping, a row whose integrity is quarantined reports `status: "block"` with `topFinding: "runtime violation (quarantined)"`. Since audit-tree audits by name/version (not necessarily the served integrity), keep this minimal: after computing each row's report, call `applyQuarantine(report)` before deriving the row's status/verdict, so a quarantined build shows as blocked in the tree too. No new aggregate field required (YAGNI — the block already flows into counts).

- [ ] **Step 6: Build + run**

```bash
npm run build
npx tsx --test packages/cli/test/format-violations.test.ts
SENTINEL_UPSTREAM=fixtures SENTINEL_BOOT_EXIT=1 node packages/proxy/dist/index.js
npm test 2>&1 | tail -6
```

Expected: format test PASS; proxy boots+exits clean; full suite green (record counts).

- [ ] **Step 7: Commit**

```bash
git add packages/cli/src/index.ts packages/cli/src/format.ts packages/cli/test/format-violations.test.ts packages/proxy/public/index.html packages/proxy/src/server.ts
git commit -m "feat(phase10): sentinel violations command, dashboard panel, audit-tree quarantine surfacing"
```

---

### Task 9: Docs, ADR-0023, final verification

**Files:**
- Create: `docs/adr/0023-runtime-violation-telemetry.md`
- Modify: `ARCHITECTURE.md` (§3.11 + the enforce-flow section; §5 if a store list exists)
- Modify: `CLAUDE.md` (What-this-is phase list; test-count line)
- Modify: `README.md` (feature bullet; `sentinel violations`; `/-/violations` endpoint; `SENTINEL_VIOLATIONS` env var)

- [ ] **Step 1: Write ADR-0023** — follow the house style of `docs/adr/0022-provenance-deep-verify.md`. Required content: **Context** (the sandbox contains but is silent — a blocked exfil looks like a build hiccup; Phase 10 makes it a sensor). **Decision** (inference from the known deny set via `computeDenySet` + `classifyViolation`; sensor in the runners, reporter in `script-shell`, `ViolationStore` + `/-/violations` in the proxy; confirmed⇒quarantine (revoke approval + serve-time `block` overlay), suspected⇒record-only; integrity-scoped; the block is a serve-time overlay that NEVER touches the deterministic score — invariant #1). **Best-effort limitation** (the sensor only sees violations that surface as process failure; a swallowed denial evades telemetry but NOT containment — containment is unchanged from Phase 6; the probe fixtures propagate to demonstrate the detectable path). **Auth posture** (`/-/violations` unauthenticated this phase, consistent with `/-/approvals`; a spoofed violation can only quarantine — a fail-closed DoS, not a bypass; authenticating it is deferred multi-tenant work). **Consequences** (fleet quarantine on the noisy majority; the deny-set must not drift from the profile — locked by the non-drift test; false-positive filter = target ∈ deny set). **Deferred** (tracer/shim for swallowed denials; authenticating `/-/violations`; suspected auto-quarantine; cross-version propagation; central telemetry service). **Rejected** (OS-log scraping — unavailable unprivileged, probed; feeding the static score — breaks invariant #1). Extends ADR-0016/0017/0018/0019, ADR-0013, ADR-0002.

- [ ] **Step 2: ARCHITECTURE.md §3.11** — describe the flow: sandbox denies → `classifyViolation` attributes from stderr + `computeDenySet` → `SandboxResult.violation` → `script-shell` POSTs `/-/violations` → `ViolationStore` records + (confirmed) quarantines → serve overlay forces `block` fleet-wide. State the best-effort limitation and the invariant-#1 preservation (serve-time overlay, not a score change). If §5 lists proxy stores, add `ViolationStore`.

- [ ] **Step 3: CLAUDE.md** — add the Phase 10 sentence to "What this is" (mirror Phase 9's density: sandbox-as-sensor, `classifyViolation`, `/-/violations`, confirmed-quarantine, best-effort/containment-unchanged). Update the `npm test` count line with the ACTUAL number from Step 5 (preserve the darwin-skip caveat structure; note the new darwin-gated violation effect + enforce e2e among the platform-gated tests).

- [ ] **Step 4: README.md** — feature bullet on runtime violation telemetry + quarantine; document `sentinel violations`; the `POST/GET/DELETE /-/violations` endpoints; the `SENTINEL_VIOLATIONS` persistence env var.

- [ ] **Step 5: Full Definition-of-Done run**

```bash
npm run build
npm run fixtures
npm test 2>&1 | tail -8
npm run demo 2>&1 | tail -3
```

Expected: build clean; ALL tests pass (record exact count for CLAUDE.md); demo still blocks the malicious fixture. If the count differs from CLAUDE.md, update the doc to reality — never force the number.

- [ ] **Step 6: Commit**

```bash
git add docs ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs(phase10): ADR-0023 runtime violation telemetry; ARCHITECTURE §3.11; CLAUDE/README updates"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 sensor/reporter/store → Tasks 1–6; §2 classification + confidence + false-positive filter + best-effort limitation → Tasks 2 (unit), 3 (effect), and the `exit 0` swallowed-denial test → Task 2; §3 endpoint + store + quarantine overlay + auth posture → Tasks 4–5; §4 fixtures (propagating) + effect/e2e/invariant tests → Tasks 3, 7; surfacing (header/dashboard/audit-tree/CLI) → Tasks 5, 8; docs/DoD → Task 9. Invariant-#1 guard = the existing determinism test (unchanged; the overlay is at serve time) + the `weight: 0` finding.
- **Type consistency:** `SandboxViolation` (Task 2) → `ViolationInput`/`ViolationRecord` (Task 4) share `kind`/`target`/`confidence`/`deniedResource`/`evidence`; `DenySet` (Task 1) consumed by name in Tasks 2–3; `runtime-violation` ruleId consistent between the Task 5 overlay and the Task 5/7 e2e assertions; `computeDenySet(approved, {homeDir, platform})` signature identical across Tasks 1/3.
- **Known judgment calls:** the `runtime-violation` finding uses category `install-script` (an existing `Category`; no new category added — YAGNI); the quarantine overlay forces `block` + prepends a `weight: 0` finding so the numeric score is untouched (invariant #1); `script-shell` resolves integrity via the `/-/manifest` fetch it already does for dependency approval; `enforce-probe` is left swallowing (demonstrates containment) while the new probes propagate (demonstrate telemetry).
