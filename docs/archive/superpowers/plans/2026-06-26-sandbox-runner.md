# Sandboxed Install Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate a macOS Seatbelt sandbox profile from a package's *approved* capabilities and run its lifecycle scripts under it, so an un-approved credential read or network egress is kernel-denied (ADR-0011 Option A, enforcement).

**Architecture:** A new `@sentinel/sandbox` workspace package with a pure `generateProfile(approved, {homeDir})` (capabilities → SBPL), a `SeatbeltSandbox` that shells out to `sandbox-exec` (fails closed off-darwin), and a lifecycle-script runner. `@sentinel/core` gains a shared `SENSITIVE_PATHS` consumed by both the profile generator and the existing `secret-exfil` rule. A `sentinel run-scripts <dir>` command ties it together.

**Tech Stack:** Node 24 (≥22), TypeScript (NodeNext, ESM, `.js` specifiers, project references), `node:child_process` + `/usr/bin/sandbox-exec`, `commander` 15, tests on `node:test` + `tsx`.

## Global Constraints

- ESM only; internal imports use `.js` specifiers even from `.ts`. **No new runtime dependencies** (sandbox-exec is an OS binary; spawn via `node:child_process`).
- **Fail closed off-darwin:** `SeatbeltSandbox` and `run-scripts` MUST refuse with a clear error on `process.platform !== 'darwin'` — never run a script unsandboxed believing it is sandboxed. Enforcement tests are gated on `process.platform === 'darwin'` (skipped elsewhere) so the suite stays green cross-platform.
- **The profile model is allow-default + targeted-deny** (deny-by-default SIGABRTs on dyld). `(version 1)(allow default)` then `(deny file-read* …)` for sensitive paths and `(deny network*)`.
- **Enforced surface = filesystem reads + network egress**, each relaxed by an approved capability. Per-host network is NOT enforced (Seatbelt is all-or-nothing); process/native are covered transitively (children inherit the sandbox).
- **DRY:** the sandbox credential deny-list and `secret-exfil`'s file-path detections share one `SENSITIVE_PATHS` source in core. The refactor MUST keep the existing `secret-exfil` tests green (behavior unchanged).
- **Report is honest:** the violation report is *inferred from static analysis* (detected − approved), not kernel-observed, and only fires on a *loud* script failure. Enforcement is the guarantee; the report is best-effort.
- **Tests assert the protected-resource EFFECT** (secret bytes never obtained / connection never landed), NOT the script exit code (a competent exfil script swallows EPERM and exits 0). Network tests use a **loopback listener**, never a doc IP.
- The malicious public fixtures stay **scored-as-text and never executed**; enforcement is tested with benign in-test probe packages.
- Build with `npx tsc --build --force <pkg>` if `rm` of `dist/` fails with EPERM.

**Commands:** Build `npm run build` · Full suite `npm test` (a `pretest` hook rebuilds fixtures) · Single file `node --import tsx --test <file>` · Single test `--test-name-pattern "<name>"`.

---

## File structure

**Create:**
- `packages/core/src/sensitive-paths.ts` — `SensitivePath` type + `SENSITIVE_PATHS`.
- `packages/sandbox/package.json`, `packages/sandbox/tsconfig.json` — new workspace package.
- `packages/sandbox/src/types.ts` — `Sandbox` interface, `SandboxResult`.
- `packages/sandbox/src/profile.ts` — `generateProfile`.
- `packages/sandbox/src/seatbelt.ts` — `SeatbeltSandbox`.
- `packages/sandbox/src/runner.ts` — `runLifecycleScripts`.
- `packages/sandbox/src/index.ts` — package exports.
- `packages/sandbox/test/profile.test.ts`, `packages/sandbox/test/seatbelt.test.ts`.
- `packages/cli/test/run-scripts.test.ts`.
- `docs/adr/0016-macos-seatbelt-sandbox-runner.md`.

**Modify:**
- `packages/core/src/rules/secret-exfil.ts` — source file-path detections from `SENSITIVE_PATHS`.
- `packages/core/src/index.ts` — export `SENSITIVE_PATHS` + `SensitivePath`.
- `packages/core/test/audit.test.ts` (only if a secret-exfil assertion needs confirming — it should not).
- `tsconfig.json` (root) — add the sandbox project reference.
- `package.json` (root) — add `packages/sandbox` to `workspaces`.
- `packages/cli/package.json` — add `@sentinel/sandbox` dependency.
- `packages/cli/tsconfig.json` — add the sandbox reference.
- `packages/cli/src/index.ts` — the `run-scripts` command.
- `ARCHITECTURE.md`, `CLAUDE.md`, `README.md`, `docs/adr/0011-install-time-permission-manifest.md`.

---

## Task 1: Core — `SENSITIVE_PATHS` + `secret-exfil` DRY refactor

**Files:**
- Create: `packages/core/src/sensitive-paths.ts`
- Modify: `packages/core/src/rules/secret-exfil.ts`, `packages/core/src/index.ts`
- Test: `packages/core/test/sensitive-paths.test.ts` (create)

**Interfaces:**
- Produces: `interface SensitivePath { label: string; denyPaths: string[]; denyKind: "literal" | "subpath"; detectRe?: RegExp }` and `SENSITIVE_PATHS: SensitivePath[]`. Entries with a `detectRe` are the ones `secret-exfil` detects; ALL entries' `denyPaths` are denied by the sandbox (later task). `~`-prefixed `denyPaths` are home-relative (expanded by the profile generator).

- [ ] **Step 1: Write the failing test**

Create `packages/core/test/sensitive-paths.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { SENSITIVE_PATHS } from "../src/index.js";

describe("SENSITIVE_PATHS", () => {
  test("covers the key credential locations with valid shapes", () => {
    const denyPaths = SENSITIVE_PATHS.flatMap((p) => p.denyPaths);
    for (const expected of ["~/.ssh", "~/.aws", "~/.npmrc", "/etc/passwd"]) {
      assert.ok(denyPaths.includes(expected), `expected a denyPath ${expected}`);
    }
    for (const p of SENSITIVE_PATHS) {
      assert.ok(p.label && p.denyPaths.length > 0, "each entry has a label + denyPaths");
      assert.ok(p.denyKind === "literal" || p.denyKind === "subpath", "denyKind is literal|subpath");
    }
  });

  test("the four detectRe entries match the historical secret-exfil patterns", () => {
    const withRe = SENSITIVE_PATHS.filter((p) => p.detectRe);
    const hits = (s: string) => withRe.some((p) => p.detectRe!.test(s));
    assert.ok(hits("os.homedir()+'/.npmrc'"));
    assert.ok(hits(".aws/credentials"));
    assert.ok(hits(".ssh/id_rsa"));
    assert.ok(hits("/etc/passwd"));
    assert.ok(!hits("just some normal code"));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/core/test/sensitive-paths.test.ts`
Expected: FAIL — `SENSITIVE_PATHS` is not exported.

- [ ] **Step 3: Create `sensitive-paths.ts`**

Create `packages/core/src/sensitive-paths.ts`:

```ts
/**
 * Canonical credential/secret filesystem locations. The single source shared by
 * the `secret-exfil` rule (which detects reads of them in code via `detectRe`) and
 * the sandbox profile generator (which denies `denyPaths`), so detection and
 * enforcement can never drift. `~`-prefixed paths are home-relative.
 */
export interface SensitivePath {
  label: string;
  /** Absolute or `~`-relative paths the sandbox denies reading. */
  denyPaths: string[];
  /** Seatbelt path filter kind for these denyPaths. */
  denyKind: "literal" | "subpath";
  /** Code-detection regex for `secret-exfil`; omit for deny-only (broader sandbox) paths. */
  detectRe?: RegExp;
}

export const SENSITIVE_PATHS: SensitivePath[] = [
  // The four with detectRe reproduce secret-exfil's historical file-path patterns:
  { label: "npm auth token (~/.npmrc)", denyPaths: ["~/.npmrc"], denyKind: "literal", detectRe: /\.npmrc|_authToken/ },
  { label: "AWS credentials file", denyPaths: ["~/.aws"], denyKind: "subpath", detectRe: /\.aws\/credentials|\.aws\\credentials/ },
  { label: "SSH private keys", denyPaths: ["~/.ssh"], denyKind: "subpath", detectRe: /\.ssh\/id_|id_rsa|id_ed25519/ },
  { label: "system account files", denyPaths: ["/etc/passwd", "/etc/shadow"], denyKind: "literal", detectRe: /\/etc\/passwd|\/etc\/shadow/ },
  // Deny-only entries (sandbox blocks; secret-exfil does not separately detect them):
  { label: "GnuPG keyring", denyPaths: ["~/.gnupg"], denyKind: "subpath" },
  { label: "netrc credentials", denyPaths: ["~/.netrc"], denyKind: "literal" },
  { label: "git credentials", denyPaths: ["~/.git-credentials"], denyKind: "literal" },
  { label: "Docker config", denyPaths: ["~/.docker/config.json"], denyKind: "literal" },
  { label: "Kubernetes config", denyPaths: ["~/.kube"], denyKind: "subpath" },
];
```

- [ ] **Step 4: Refactor `secret-exfil.ts` to source paths from `SENSITIVE_PATHS`**

In `packages/core/src/rules/secret-exfil.ts`, add the import and replace the `SECRET_READS` array. Add at the top:

```ts
import { SENSITIVE_PATHS } from "../sensitive-paths.js";
```

Replace the `SECRET_READS` constant (lines 4-14) with:

```ts
/** Reads of sensitive material: env-var detections here + file-path detections from SENSITIVE_PATHS. */
const SECRET_READS: { re: RegExp; what: string }[] = [
  { re: /process\.env\s*\[/, what: "dynamic environment-variable enumeration" },
  { re: /\b(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN)\b/, what: "AWS credentials" },
  { re: /\b(NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN)\b/, what: "CI/registry tokens" },
  { re: /process\.env\.(\w*?(SECRET|TOKEN|KEY|PASS|CREDENTIAL)\w*)/i, what: "secret-named env var" },
  // file-path detections shared with the sandbox deny-list (no drift):
  ...SENSITIVE_PATHS.filter((p) => p.detectRe).map((p) => ({ re: p.detectRe!, what: p.label })),
];
```

(This preserves the exact same set of patterns: the 4 env-var entries plus the 4 file-path entries, now sourced from `SENSITIVE_PATHS`. The `what` strings for the path entries change to the `SENSITIVE_PATHS` labels — that only affects a finding's message text, which no test pins verbatim.)

- [ ] **Step 5: Export from core**

In `packages/core/src/index.ts`, add after the existing exports:

```ts
export { SENSITIVE_PATHS, type SensitivePath } from "./sensitive-paths.js";
```

- [ ] **Step 6: Run all core tests — secret-exfil must stay green**

Run: `npx tsc --build --force packages/core && node --import tsx --test packages/core/test/*.test.ts`
Expected: PASS — `sensitive-paths.test.ts` passes AND `audit.test.ts` (the `secret-exfil` critical/evidence assertions on `color-stream@1.4.1`) is unchanged-green. If a secret-exfil test fails, a `detectRe` diverged from the original — fix the regex to match the historical pattern exactly.

- [ ] **Step 7: Commit**

```bash
git add packages/core/src/sensitive-paths.ts packages/core/src/rules/secret-exfil.ts packages/core/src/index.ts packages/core/test/sensitive-paths.test.ts
git commit -m "refactor(core): shared SENSITIVE_PATHS source for secret-exfil + sandbox deny-list"
```

---

## Task 2: `@sentinel/sandbox` package scaffold + pure profile generation

**Files:**
- Create: `packages/sandbox/package.json`, `packages/sandbox/tsconfig.json`, `packages/sandbox/src/types.ts`, `packages/sandbox/src/profile.ts`, `packages/sandbox/src/index.ts`
- Modify: `tsconfig.json` (root), `package.json` (root)
- Test: `packages/sandbox/test/profile.test.ts`

**Interfaces:**
- Consumes: `type Capability`, `SENSITIVE_PATHS` from `@sentinel/core`.
- Produces:
  - `interface SandboxResult { exitCode: number; stdout: string; stderr: string }`
  - `interface Sandbox { run(cmd: string, opts: { cwd: string; profile: string; env?: NodeJS.ProcessEnv }): SandboxResult }`
  - `generateProfile(approved: Capability[], opts: { homeDir: string }): string`

- [ ] **Step 1: Scaffold the package**

Create `packages/sandbox/package.json`:

```json
{
  "name": "@sentinel/sandbox",
  "version": "0.1.0",
  "description": "Sentinel sandbox: generate an OS sandbox profile from approved capabilities and run lifecycle scripts under it (macOS Seatbelt).",
  "license": "Apache-2.0",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": { ".": { "types": "./dist/index.d.ts", "default": "./dist/index.js" } },
  "dependencies": { "@sentinel/core": "0.1.0" },
  "devDependencies": { "@types/node": "^24.13.2" }
}
```

Create `packages/sandbox/tsconfig.json`:

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "rootDir": "src", "outDir": "dist" },
  "include": ["src/**/*.ts"],
  "references": [{ "path": "../core" }]
}
```

In the root `tsconfig.json`, add the reference (after `packages/proxy`):

```json
    { "path": "packages/proxy" },
    { "path": "packages/sandbox" },
    { "path": "packages/cli" }
```

In the root `package.json`, add `packages/sandbox` to `workspaces` (after `packages/proxy`):

```json
  "workspaces": [
    "packages/core",
    "packages/proxy",
    "packages/sandbox",
    "packages/cli"
  ],
```

Then link the new workspace:

Run: `npm install`
Expected: completes; `node_modules/@sentinel/sandbox` symlink created (verify: `ls -l node_modules/@sentinel/sandbox`).

- [ ] **Step 2: Write the failing profile test**

Create `packages/sandbox/test/profile.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateProfile } from "../src/profile.js";
import type { Capability } from "@sentinel/core";

const fs = (target: string): Capability => ({ kind: "filesystem", target, evidence: [] });
const net = (target: string): Capability => ({ kind: "network", target, evidence: [] });
const HOME = "/Users/test";

describe("generateProfile", () => {
  test("with no approvals: denies sensitive reads and all network", () => {
    const p = generateProfile([], { homeDir: HOME });
    assert.match(p, /^\(version 1\)/);
    assert.match(p, /\(allow default\)/);
    assert.match(p, /deny file-read\* \(subpath "\/Users\/test\/\.ssh"\)/);
    assert.match(p, /deny file-read\* \(literal "\/Users\/test\/\.npmrc"\)/);
    assert.match(p, /deny file-read\* \(literal "\/etc\/passwd"\) \(literal "\/etc\/shadow"\)/);
    assert.match(p, /\(deny network\*\)/);
  });

  test("an approved network capability omits the network deny", () => {
    const p = generateProfile([net("api.example.com")], { homeDir: HOME });
    assert.doesNotMatch(p, /\(deny network\*\)/);
  });

  test("an approved filesystem capability omits its sensitive-path deny", () => {
    const p = generateProfile([fs(".npmrc")], { homeDir: HOME });
    assert.doesNotMatch(p, /\.npmrc"/);          // the ~/.npmrc deny is gone
    assert.match(p, /\.ssh"/);                   // unrelated denies remain
  });

  test("deterministic for the same inputs", () => {
    assert.equal(generateProfile([net("x")], { homeDir: HOME }), generateProfile([net("x")], { homeDir: HOME }));
  });
});
```

- [ ] **Step 3: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/profile.test.ts`
Expected: FAIL — cannot find module `../src/profile.js`.

- [ ] **Step 4: Write `types.ts` and `profile.ts`**

Create `packages/sandbox/src/types.ts`:

```ts
export interface SandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface Sandbox {
  /** Run `cmd` (via `sh -c`) under the given SBPL `profile`, in `cwd`. */
  run(cmd: string, opts: { cwd: string; profile: string; env?: NodeJS.ProcessEnv }): SandboxResult;
}
```

Create `packages/sandbox/src/profile.ts`:

```ts
import { SENSITIVE_PATHS, type Capability } from "@sentinel/core";

/**
 * Generate a macOS Seatbelt (SBPL) profile from a package's APPROVED capabilities.
 * Allow-default + targeted-deny (deny-by-default SIGABRTs on dyld). Pure: same
 * inputs ⇒ same string. `homeDir` expands `~`-relative SENSITIVE_PATHS.
 */
export function generateProfile(approved: Capability[], opts: { homeDir: string }): string {
  const expand = (p: string) => (p.startsWith("~") ? opts.homeDir + p.slice(1) : p);
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target.replace(/^~?\/?/, ""));
  const hasNetwork = approved.some((c) => c.kind === "network");

  const lines = ["(version 1)", "(allow default)"];
  for (const sp of SENSITIVE_PATHS) {
    // Omit this deny if an approved filesystem target matches one of its denyPaths (coarse, MVP).
    const covered = approvedFs.some((t) =>
      t.length > 0 && sp.denyPaths.some((dp) => dp.replace(/^~?\/?/, "").includes(t) || t.includes(dp.replace(/^~?\/?/, ""))),
    );
    if (covered) continue;
    const items = sp.denyPaths.map((dp) => `(${sp.denyKind} "${expand(dp)}")`).join(" ");
    lines.push(`(deny file-read* ${items})`);
  }
  if (!hasNetwork) lines.push("(deny network*)");
  return lines.join("\n") + "\n";
}
```

Create `packages/sandbox/src/index.ts`:

```ts
export { generateProfile } from "./profile.js";
export type { Sandbox, SandboxResult } from "./types.js";
```

- [ ] **Step 5: Run to verify it passes**

Run: `npx tsc --build --force packages/sandbox && node --import tsx --test packages/sandbox/test/profile.test.ts`
Expected: PASS (all four cases).

- [ ] **Step 6: Commit**

```bash
git add packages/sandbox tsconfig.json package.json package-lock.json
git commit -m "feat(sandbox): @sentinel/sandbox package + pure generateProfile (capabilities → SBPL)"
```

---

## Task 3: `SeatbeltSandbox` + lifecycle runner (darwin-gated enforcement)

**Files:**
- Create: `packages/sandbox/src/seatbelt.ts`, `packages/sandbox/src/runner.ts`
- Modify: `packages/sandbox/src/index.ts`
- Test: `packages/sandbox/test/seatbelt.test.ts`

**Interfaces:**
- Consumes: `Sandbox`, `SandboxResult` (Task 2).
- Produces:
  - `class SeatbeltSandbox implements Sandbox` — `run(cmd, { cwd, profile, env? })`; throws `Error("sandbox enforcement unavailable on <platform>")` when `process.platform !== 'darwin'`.
  - `interface ScriptResult { hook: string; command: string; exitCode: number }`
  - `runLifecycleScripts(opts: { packageDir: string; profile: string; sandbox: Sandbox }): { results: ScriptResult[]; failed: boolean }`

- [ ] **Step 1: Write the failing tests**

Create `packages/sandbox/test/seatbelt.test.ts`:

```ts
import assert from "node:assert/strict";
import net from "node:net";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { SeatbeltSandbox } from "../src/seatbelt.js";
import { runLifecycleScripts } from "../src/runner.js";
import { generateProfile } from "../src/profile.js";

const darwin = process.platform === "darwin";

describe("SeatbeltSandbox (fail-closed)", () => {
  test("non-darwin throws (we never run unsandboxed)", { skip: darwin ? "darwin: covered by enforcement tests" : false }, () => {
    assert.throws(() => new SeatbeltSandbox().run("echo hi", { cwd: tmpdir(), profile: "(version 1)(allow default)" }), /unavailable/i);
  });
});

describe("SeatbeltSandbox enforcement", { skip: darwin ? false : "requires macOS sandbox-exec" }, () => {
  test("a denied file-read leaves the secret unobtained (assert on EFFECT, not exit)", () => {
    const dir = mkdtempSync(join(tmpdir(), "sb-enf-"));
    const secret = join(dir, "secret.txt");
    writeFileSync(secret, "TOPSECRET-XYZ");
    const out = join(dir, "out.txt");
    // deny-default profile that denies this exact file
    const profile = `(version 1)\n(allow default)\n(deny file-read* (literal "${secret}"))\n`;
    // script swallows the error (like real exfil) and writes what it managed to read
    const sb = new SeatbeltSandbox();
    sb.run(`cat ${secret} > ${out} 2>/dev/null || true`, { cwd: dir, profile });
    const got = existsSync(out) ? readFileSync(out, "utf8") : "";
    assert.ok(!got.includes("TOPSECRET-XYZ"), "the secret bytes must NOT have been obtained");
  });

  test("a denied network connection never lands (loopback listener)", async () => {
    const got: boolean[] = [];
    const server = net.createServer((s) => { got.push(true); s.destroy(); });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as net.AddressInfo).port;
    const dir = mkdtempSync(join(tmpdir(), "sb-net-"));
    const profile = `(version 1)\n(allow default)\n(deny network*)\n`;
    new SeatbeltSandbox().run(`nc -z -G 2 127.0.0.1 ${port} || true`, { cwd: dir, profile });
    await new Promise((r) => setTimeout(r, 200));
    server.close();
    assert.equal(got.length, 0, "the sandboxed connection must not have reached the listener");
  });
});

describe("runLifecycleScripts", { skip: darwin ? false : "requires macOS sandbox-exec" }, () => {
  test("runs present hooks under the profile and a benign script succeeds", () => {
    const dir = mkdtempSync(join(tmpdir(), "sb-run-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: "echo built > built.txt" } }));
    const profile = generateProfile([], { homeDir: process.env.HOME ?? "/tmp" });
    const r = runLifecycleScripts({ packageDir: dir, profile, sandbox: new SeatbeltSandbox() });
    assert.equal(r.failed, false);
    assert.equal(r.results.length, 1);
    assert.equal(r.results[0]?.hook, "postinstall");
    assert.equal(readFileSync(join(dir, "built.txt"), "utf8").trim(), "built");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/sandbox/test/seatbelt.test.ts`
Expected: FAIL — cannot find module `../src/seatbelt.js`.

- [ ] **Step 3: Write `seatbelt.ts`**

Create `packages/sandbox/src/seatbelt.ts`:

```ts
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Sandbox, SandboxResult } from "./types.js";

/** Enforces an SBPL profile via macOS `sandbox-exec`. Fails closed on non-darwin. */
export class SeatbeltSandbox implements Sandbox {
  run(cmd: string, opts: { cwd: string; profile: string; env?: NodeJS.ProcessEnv }): SandboxResult {
    if (process.platform !== "darwin") {
      throw new Error(`sandbox enforcement unavailable on ${process.platform} (macOS Seatbelt required)`);
    }
    const dir = mkdtempSync(join(tmpdir(), "sentinel-sb-"));
    const profileFile = join(dir, "profile.sb");
    writeFileSync(profileFile, opts.profile);
    const res = spawnSync("/usr/bin/sandbox-exec", ["-f", profileFile, "/bin/sh", "-c", cmd], {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      encoding: "utf8",
    });
    return {
      exitCode: res.status ?? (res.signal ? 1 : 0),
      stdout: res.stdout ?? "",
      stderr: res.stderr ?? "",
    };
  }
}
```

- [ ] **Step 4: Write `runner.ts`**

Create `packages/sandbox/src/runner.ts`:

```ts
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Sandbox } from "./types.js";

export interface ScriptResult {
  hook: string;
  command: string;
  exitCode: number;
}

const LIFECYCLE = ["preinstall", "install", "postinstall"] as const;

/** Run a package's present lifecycle scripts under the sandbox profile (cwd = packageDir). */
export function runLifecycleScripts(opts: {
  packageDir: string;
  profile: string;
  sandbox: Sandbox;
}): { results: ScriptResult[]; failed: boolean } {
  let scripts: Record<string, string> = {};
  try {
    scripts = JSON.parse(readFileSync(join(opts.packageDir, "package.json"), "utf8"))?.scripts ?? {};
  } catch {
    scripts = {};
  }
  const results: ScriptResult[] = [];
  for (const hook of LIFECYCLE) {
    const command = scripts[hook];
    if (!command) continue;
    const r = opts.sandbox.run(command, { cwd: opts.packageDir, profile: opts.profile });
    results.push({ hook, command, exitCode: r.exitCode });
  }
  return { results, failed: results.some((r) => r.exitCode !== 0) };
}
```

Update `packages/sandbox/src/index.ts` to add:

```ts
export { SeatbeltSandbox } from "./seatbelt.js";
export { runLifecycleScripts, type ScriptResult } from "./runner.js";
```

- [ ] **Step 5: Run to verify it passes**

Run: `npx tsc --build --force packages/sandbox && node --import tsx --test packages/sandbox/test/seatbelt.test.ts`
Expected (on macOS): PASS — the secret stays unobtained, the connection never lands, the benign script runs. (On non-darwin the enforcement describes are skipped and the fail-closed test runs.)

- [ ] **Step 6: Commit**

```bash
git add packages/sandbox/src/seatbelt.ts packages/sandbox/src/runner.ts packages/sandbox/src/index.ts packages/sandbox/test/seatbelt.test.ts
git commit -m "feat(sandbox): SeatbeltSandbox (fail-closed off-darwin) + lifecycle runner"
```

---

## Task 4: CLI — `sentinel run-scripts`

**Files:**
- Modify: `packages/cli/package.json`, `packages/cli/tsconfig.json`, `packages/cli/src/index.ts`
- Test: `packages/cli/test/run-scripts.test.ts`

**Interfaces:**
- Consumes: `generateProfile`, `SeatbeltSandbox`, `runLifecycleScripts` from `@sentinel/sandbox`; `extractCapabilities`, `capabilityAtom`, `type Capability` from `@sentinel/core`.
- Produces: a `run-scripts` command + an exported pure helper `parseApprovals(flags: string[]): Capability[]` and `unapprovedAtoms(detected: Capability[], approved: Capability[]): string[]`.

- [ ] **Step 1: Wire the dependency**

In `packages/cli/package.json`, add to `dependencies`:

```json
    "@sentinel/core": "0.1.0",
    "@sentinel/sandbox": "0.1.0",
    "commander": "^15.0.0"
```

In `packages/cli/tsconfig.json`, add the reference:

```json
  "references": [{ "path": "../core" }, { "path": "../sandbox" }]
```

Run: `npm install`
Expected: `node_modules/@sentinel/sandbox` resolves for the CLI (verify the symlink exists).

- [ ] **Step 2: Write the failing test**

Create `packages/cli/test/run-scripts.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Capability } from "@sentinel/core";
import { parseApprovals, unapprovedAtoms } from "../src/index.js";

const cap = (kind: string, target: string): Capability => ({ kind: kind as Capability["kind"], target, evidence: [] });

describe("parseApprovals", () => {
  test("parses kind:target flags", () => {
    const a = parseApprovals(["network:api.example.com", "filesystem:.npmrc"]);
    assert.deepEqual(a.map((c) => `${c.kind}:${c.target}`), ["network:api.example.com", "filesystem:.npmrc"]);
  });
  test("ignores malformed flags", () => {
    assert.deepEqual(parseApprovals(["garbage"]), []);
  });
});

describe("unapprovedAtoms", () => {
  test("returns detected minus approved by atom", () => {
    const detected = [cap("network", "evil.example.com"), cap("filesystem", ".aws/credentials")];
    const approved = [cap("filesystem", ".aws/credentials")];
    assert.deepEqual(unapprovedAtoms(detected, approved), ["network:evil.example.com"]);
  });
});
```

- [ ] **Step 3: Run to verify it fails**

Run: `node --import tsx --test packages/cli/test/run-scripts.test.ts`
Expected: FAIL — `parseApprovals`/`unapprovedAtoms` not exported.

- [ ] **Step 4: Implement the command + helpers**

In `packages/cli/src/index.ts`:

Add imports near the top (after the existing `@sentinel/core` import):

```ts
import { readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative } from "node:path";
import { extractCapabilities, capabilityAtom, type Capability, type PackageFile } from "@sentinel/core";
import { generateProfile, SeatbeltSandbox, runLifecycleScripts } from "@sentinel/sandbox";
```

(If `readFileSync` is already imported from `node:fs`, merge — do not duplicate the import.)

Add the exported helpers near `planApprovals`:

```ts
export function parseApprovals(flags: string[]): Capability[] {
  const out: Capability[] = [];
  for (const f of flags) {
    const i = f.indexOf(":");
    if (i <= 0) continue;
    const kind = f.slice(0, i);
    const target = f.slice(i + 1);
    if (!["network", "filesystem", "process", "native"].includes(kind) || !target) continue;
    out.push({ kind: kind as Capability["kind"], target, evidence: [] });
  }
  return out;
}

export function unapprovedAtoms(detected: Capability[], approved: Capability[]): string[] {
  const approvedSet = new Set(approved.map(capabilityAtom));
  return detected.map(capabilityAtom).filter((a) => !approvedSet.has(a));
}

/** Read a package dir into PackageFile[] using the npm `package/<path>` convention. */
function readPackageFiles(dir: string): PackageFile[] {
  const walk = (d: string): string[] =>
    readdirSync(d).flatMap((n) => {
      const p = join(d, n);
      return statSync(p).isDirectory() ? walk(p) : [p];
    });
  return walk(dir).map((p) => ({
    path: "package/" + relative(dir, p),
    content: safeRead(p),
    size: 0,
    changed: false,
  }));
}

function safeRead(p: string): string {
  try { return readFileSync(p, "utf8"); } catch { return ""; }
}
```

Add the command before the `parseAsync` guard line:

```ts
program
  .command("run-scripts")
  .description("Run a package's lifecycle scripts under a sandbox derived from its approved capabilities (macOS).")
  .argument("<package-dir>", "path to an unpacked package directory")
  .option("--approve <cap...>", "approved capabilities as kind:target (e.g. network:api.example.com)", [])
  .action((dir: string, opts: { approve: string[] }) => {
    if (process.platform !== "darwin") {
      console.error("\x1b[31msentinel: sandbox enforcement is only available on macOS\x1b[0m");
      process.exit(2);
    }
    let scripts: Record<string, string> = {};
    try {
      scripts = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"))?.scripts ?? {};
    } catch {
      console.error(`\x1b[31msentinel: cannot read ${join(dir, "package.json")}\x1b[0m`);
      process.exit(2);
    }
    const hooks = ["preinstall", "install", "postinstall"].filter((h) => scripts[h]);
    if (hooks.length === 0) {
      console.log("No lifecycle scripts — nothing to enforce.");
      return;
    }
    const detected = extractCapabilities({ meta: {} as never, files: readPackageFiles(dir), mode: "full" });
    const approved = parseApprovals(opts.approve);
    const profile = generateProfile(approved, { homeDir: homedir() });
    const { results, failed } = runLifecycleScripts({ packageDir: dir, profile, sandbox: new SeatbeltSandbox() });

    for (const r of results) {
      console.log(`  ${r.hook}: \`${r.command}\` -> exit ${r.exitCode}`);
    }
    if (failed) {
      const unapproved = unapprovedAtoms(detected, approved);
      console.error("\x1b[33mA lifecycle script failed under sandbox enforcement.\x1b[0m");
      if (unapproved.length) {
        console.error("Detected, un-approved capabilities (likely cause — inferred from static analysis):");
        for (const a of unapproved) console.error(`  › ${a}`);
        console.error("Approve them (--approve <kind:target>) and retry, or treat the package as malicious.");
      }
      process.exit(1);
    }
    console.log(`Ran ${results.length} lifecycle script(s) under enforcement; no denied capability needed.`);
  });
```

- [ ] **Step 5: Run to verify it passes**

Run: `node --import tsx --test packages/cli/test/run-scripts.test.ts`
Expected: PASS (parseApprovals + unapprovedAtoms).

- [ ] **Step 6: Manual end-to-end (macOS — single command, in-test probe)**

Run (creates a benign probe package whose postinstall *attempts* a credential read + connect, then verifies enforcement via `run-scripts`):

```bash
cd /Users/tonibergholm/Developer/claude/pkg-registry
D=$(mktemp -d); printf 'TOPSECRET\n' > "$HOME/.sentinel-probe-secret" 2>/dev/null || true
cat > "$D/package.json" <<'JSON'
{ "name": "probe", "version": "1.0.0", "scripts": { "postinstall": "node build.js" } }
JSON
cat > "$D/build.js" <<'JS'
const fs=require("fs");try{const s=fs.readFileSync(process.env.HOME+"/.sentinel-probe-secret","utf8");fs.writeFileSync("leaked.txt",s)}catch(e){}
JS
node --import tsx packages/cli/src/index.ts run-scripts "$D"; echo "exit=$?"
echo "leaked the secret? ->"; cat "$D/leaked.txt" 2>/dev/null || echo "(no leak — enforcement worked)"
rm -f "$HOME/.sentinel-probe-secret"
```

Expected: the postinstall runs under enforcement; `leaked.txt` does NOT contain `TOPSECRET` (the read of a `~`-dotfile... note: this probe reads `~/.sentinel-probe-secret`, which is NOT in `SENSITIVE_PATHS`, so it would NOT be denied — use it only to confirm the command runs end-to-end). For a real denial demo, the script must target a path in `SENSITIVE_PATHS` (e.g. `~/.npmrc`); the automated enforcement guarantee is covered by `seatbelt.test.ts` (which denies an exact planted path). Treat this step as a smoke test of the command wiring, not the enforcement assertion.

- [ ] **Step 7: Build + commit**

```bash
npx tsc --build --force packages/cli
git add packages/cli/package.json packages/cli/tsconfig.json packages/cli/src/index.ts packages/cli/test/run-scripts.test.ts package-lock.json
git commit -m "feat(cli): sentinel run-scripts — enforce lifecycle scripts under a capability-derived sandbox"
```

---

## Task 5: Documentation

**Files:**
- Create: `docs/adr/0016-macos-seatbelt-sandbox-runner.md`
- Modify: `docs/adr/0011-install-time-permission-manifest.md`, `ARCHITECTURE.md`, `CLAUDE.md`, `README.md`

- [ ] **Step 1: Write ADR-0016**

Create `docs/adr/0016-macos-seatbelt-sandbox-runner.md`:

```md
# ADR-0016: macOS Seatbelt sandbox runner (ADR-0011 stage A, partial)

**Status:** Accepted
**Date:** 2026-06-26
**Phase:** 3 (implements ADR-0011 Option A for macOS)

## Context
ADR-0011 stage B made capability an approved, recorded decision but did not constrain
execution. Stage A is runtime least-privilege: run lifecycle scripts in a sandbox whose
profile is generated from the package's approved capabilities.

## Decision
1. **macOS Seatbelt (`sandbox-exec`)** behind a `Sandbox` interface (Linux landlock/
   bubblewrap is a future impl). Verified empirically: file-read and network denies are
   enforced here.
2. **Allow-default + targeted-deny** profile (deny-by-default SIGABRTs on dyld).
3. **Enforced surface = filesystem reads + network egress**, each relaxed by an approved
   capability; children/native inherit the sandbox. Network is **all-or-nothing**
   (Seatbelt can't host-filter); per-host fidelity lives on the proxy.
4. **Fail closed off-darwin** — the runner refuses, never runs unsandboxed.
5. **DRY** the credential deny-list with `secret-exfil` via a shared `SENSITIVE_PATHS`.
6. **The violation report is inferred** (detected − approved), not kernel-observed (the
   unified log isn't reliably available), and best-effort (a swallowed EPERM produces no
   report). Enforcement is the guarantee; the report is opportunistic.

## Consequences
- The MVP is the enforcement primitive + `sentinel run-scripts` on one resolved package.
  Deferred: full `npm install --enforce` tree orchestration + npm-env replication; Linux;
  per-host script network / force-`HTTP_PROXY`; observe/dry-run; kernel-observed reports;
  write-confinement; proxy-approval fetch in `run-scripts`.
- The synthetic-malware fixtures remain scored-as-text and unexecuted; enforcement is
  tested with benign in-test probe packages asserting the protected-resource effect.
```

- [ ] **Step 2: Annotate ADR-0011**

In `docs/adr/0011-install-time-permission-manifest.md`, under its `**Status:**` line add:

```md
> **Stage A (partial, 2026-06-26, ADR-0016):** a macOS Seatbelt runner now ENFORCES the
> approved capability set at install time (`sentinel run-scripts`). Linux + full
> `npm install --enforce` orchestration remain deferred.
```

- [ ] **Step 3: Update ARCHITECTURE.md**

Add a subsection after the private-namespace section (§3.5):

```md
### 3.6 Sandbox enforcement (Phase 3, ADR-0011/0016)

`@sentinel/sandbox` turns an *approved* capability set into *enforced* runtime
least-privilege on macOS: `generateProfile(approved, {homeDir})` emits an allow-default +
deny-sensitive Seatbelt (SBPL) profile (deny credential reads from the shared
`SENSITIVE_PATHS`, deny network egress), each relaxed by an approved capability; the
`SeatbeltSandbox` runs each lifecycle script under it via `sandbox-exec` (failing closed
off-darwin). `sentinel run-scripts <dir>` ties it together and, on a loud failure, reports
the detected-but-unapproved capabilities (inferred, best-effort). Network is all-or-nothing
at the sandbox layer; per-host fidelity lives on the proxy. Children/native inherit the
sandbox. Full `npm install --enforce` orchestration is deferred.
```

- [ ] **Step 4: Update CLAUDE.md**

Add `@sentinel/sandbox` to the stack/packages description and reaffirm the never-execute
rule still holds (the enforcement probe is benign). Then run `npm test 2>&1 | tail -4`,
note the count `N`, and update the two `102/102` references to `N/N`.

In the "What this is" / packages area, add a line:

```md
Phase 3 adds **`@sentinel/sandbox`** — a macOS Seatbelt runner that enforces a package's
approved capability manifest at install time (`sentinel run-scripts`). Synthetic malware
fixtures are still scored-as-text and **never executed**; enforcement is tested with
benign probe packages.
```

- [ ] **Step 5: Update README.md**

Add a `sentinel run-scripts` usage note under the CLI section (one short paragraph + the
example): "On macOS, `sentinel run-scripts <package-dir> [--approve network:host …]` runs
the package's lifecycle scripts under a Seatbelt sandbox generated from its approved
capabilities; un-approved credential reads / network egress are denied by the kernel."

- [ ] **Step 6: Commit**

```bash
git add docs/adr ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs: ADR-0016 Seatbelt runner; annotate ADR-0011; ARCHITECTURE + CLAUDE + README"
```

---

## Task 6: Full-suite verification

**Files:** none.

- [ ] **Step 1: Clean build**

Run: `npm run build`
Expected: no TypeScript errors (the new package builds via project references).

- [ ] **Step 2: Full test suite**

Run: `npm test`
Expected: all pass — core (incl. `sensitive-paths`), proxy, sandbox (`profile` everywhere; `seatbelt` enforcement on macOS / fail-closed elsewhere), cli (`run-scripts` helpers). Update CLAUDE.md (Task 5 Step 4) if the count differs.

- [ ] **Step 3: Confirm the enforcement guarantee (macOS)**

Run: `node --import tsx --test --test-name-pattern "never have been obtained" packages/sandbox/test/seatbelt.test.ts`
Expected (macOS): PASS — the sandboxed `cat` of a denied path leaves the secret unobtained. (Non-darwin: the test is skipped; note that in the report.)

- [ ] **Step 4: Confirm `secret-exfil` + malware invariant unchanged**

Run: `node --import tsx --test --test-name-pattern "secret-exfil|MALICIOUS" packages/core/test/audit.test.ts`
Expected: PASS — `color-stream@1.4.1` still fires the critical `secret-exfil` finding (DRY refactor didn't regress detection) and stays blocked.

- [ ] **Step 5: Demo still runs**

Run: `npm run demo 2>&1 | grep -iE "HTTP 403|verdict: block"`
Expected: malicious tarball blocked (unaffected by the sandbox work).

---

## Self-review notes

- **Spec coverage:** Seatbelt behind `Sandbox` interface (T2/T3); per-package lifecycle scripts (T3 runner + T4 command); enforce + actionable report (T4); fs+network surface (T2 profile); `@sentinel/sandbox` + `run-scripts` (T2-T4); `SENSITIVE_PATHS` DRY (T1); allow-default model (T2); fail-closed off-darwin (T3 SeatbeltSandbox + T4 command); inferred best-effort report (T4); assert-on-effect + loopback network (T3 tests); malware-never-executed (probe packages, T3/T4); deferred scope (docs T5); ADR-0016 + annotate 0011 (T5).
- **Probe-fixture nuance:** the spec's "dedicated probe fixture" is implemented as in-test temp packages (`mkdtemp`) — equivalent, hermetic, and avoids the committed-fixture rebuild pipeline.
- **Type consistency:** `SensitivePath`{label,denyPaths,denyKind,detectRe?}, `SENSITIVE_PATHS`, `generateProfile(approved, {homeDir})`, `Sandbox`/`SandboxResult`, `SeatbeltSandbox`, `runLifecycleScripts`/`ScriptResult`, `parseApprovals`, `unapprovedAtoms` — consistent across tasks.
- **Workspace wiring:** new package added to root `workspaces` + `tsconfig` references (T2); CLI dependency + reference (T4); `npm install` after each to create the symlink.
