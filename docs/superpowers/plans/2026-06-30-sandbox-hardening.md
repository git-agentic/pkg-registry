# Sandbox Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two exfil/persistence holes Phase 3's sandbox left open — credentials readable via `process.env`, and unrestricted writes to persistence targets.

**Architecture:** Two halves sharing one capability/path model. (a) Env-scrub: a new `env` capability kind, a fail-closed `ENV_ALLOWLIST`, and a pure `scrubEnv` that the runner applies before spawning. (b) Write-confinement: `SensitivePath` gains per-mode flags so `generateProfile` emits `file-write*` denies (incl. new persistence paths) alongside the existing `file-read*` denies. Both are pure/unit-testable; kernel enforcement is darwin-gated.

**Tech Stack:** Node 24 / TypeScript (ESM, NodeNext, `.js` import specifiers), npm workspaces, `node:test` + `tsx`, macOS Seatbelt (`sandbox-exec`).

## Global Constraints

- ESM only (`"type": "module"`); internal imports use `.js` specifiers even from `.ts`.
- Deterministic scoring is **untouched** — Phase 4 adds capability *data* + detections only; no scoring weight changes.
- Profile generation and `scrubEnv` MUST be **pure** (same inputs ⇒ same output, no kernel/fs).
- Fail-closed: env scrubbing is allowlist-based (unmatched var dropped); off-darwin enforcement still refuses loudly.
- Synthetic malware fixtures stay scored-as-text and **never executed**; enforcement is tested with inline benign probe scripts (the `seatbelt.test.ts` pattern).
- Darwin-gated tests use `{ skip: darwin ? false : "requires macOS sandbox-exec" }` and assert on the **EFFECT** (secret absent / file unchanged), never the exit code.
- Seatbelt matches the **canonical `/private/...`** path — every system path deny (read OR write) must go through `canonicalizeMacPath`. (Re-verified for writes: a `/tmp` deny does NOT match; `/private/tmp` does.)
- `npm test` must end green; bump the count in CLAUDE.md from **118** to the final number in the last task.
- Build with `npx tsc --build` (the mount may EPERM on `rm` of `dist/`; use `--force` if needed).

---

### Task 1: `env` capability kind + credential-shaped detection (core)

**Files:**
- Modify: `packages/core/src/types.ts:47` (the `CapabilityKind` union)
- Modify: `packages/core/src/detect/patterns.ts:17-43` (add `env` matchers to `CAPABILITY_MATCHERS`)
- Test: `packages/core/test/capabilities.test.ts`

**Interfaces:**
- Produces: `CapabilityKind` now includes `"env"`; `extractCapabilities` emits `{ kind: "env", target: "<VARNAME>", evidence }` for credential-shaped `process.env` reads. `target` is the uppercase env-var name. Consumed by Tasks 3 (scrubEnv), 6 (CLI `--approve env:`).

- [ ] **Step 1: Write the failing test**

Add to `packages/core/test/capabilities.test.ts`:

```ts
test("detects credential-shaped env reads as env capabilities, ignores benign env", () => {
  const files = [{
    path: "package/exfil.js",
    content: [
      "const t = process.env.NPM_TOKEN;",
      'const a = process.env["AWS_SECRET_ACCESS_KEY"];',
      "const mode = process.env.NODE_ENV;",   // benign — must NOT be captured
      "const p = process.env.PATH;",          // benign — must NOT be captured
    ].join("\n"),
  }];
  const caps = extractCapabilities({ meta: {} as never, files, mode: "full" });
  const envTargets = caps.filter((c) => c.kind === "env").map((c) => c.target).sort();
  assert.deepEqual(envTargets, ["AWS_SECRET_ACCESS_KEY", "NPM_TOKEN"]);
});
```

(If `extractCapabilities`/`assert` aren't already imported in this file, add `import assert from "node:assert/strict";` and the existing `extractCapabilities` import.)

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/core/test/capabilities.test.ts`
Expected: FAIL — `envTargets` is `[]` (no env matchers yet).

- [ ] **Step 3: Implement**

In `packages/core/src/types.ts`, extend the union:

```ts
export type CapabilityKind = "network" | "filesystem" | "process" | "native" | "env";
```

In `packages/core/src/detect/patterns.ts`, add this block to `CAPABILITY_MATCHERS` (after the `native` entry). The shared name fragment matches any env var whose name contains a credential token — this mirrors `secret-exfil`'s env detections; the **allowlist** in Task 3 is what enforces, so this only needs to feed the report:

```ts
  // env — credential-shaped env-var reads; the NAME is the target. Detection feeds the
  // report; enforcement is the fail-closed ENV_ALLOWLIST (sandbox), not this list.
  { kind: "env", re: /process\.env\.([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|AUTH|CREDENTIALS?)[A-Z0-9_]*)\b/g, group: 1 },
  { kind: "env", re: /process\.env\[\s*['"]([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|AUTH|CREDENTIALS?)[A-Z0-9_]*)['"]\s*\]/g, group: 1 },
```

(No `normalizeTarget` change needed: `env` falls to the default branch, which leaves the uppercase name intact.)

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx --test packages/core/test/capabilities.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/types.ts packages/core/src/detect/patterns.ts packages/core/test/capabilities.test.ts
git commit -m "feat(core): env capability kind + credential-shaped process.env detection"
```

---

### Task 2: per-mode `SensitivePath` + persistence entries (core)

**Files:**
- Modify: `packages/core/src/sensitive-paths.ts` (add `modes` field; annotate existing entries; add persistence entries)
- Test: `packages/core/test/sensitive-paths.test.ts`

**Interfaces:**
- Produces: `SensitivePath` gains `modes: ("read" | "write")[]`. Every entry declares which access is dangerous. Consumed by Task 4 (`generateProfile`). `secret-exfil` is unaffected (it filters on `detectRe`, not `modes`).

- [ ] **Step 1: Write the failing test**

Add to `packages/core/test/sensitive-paths.test.ts`:

```ts
test("every entry declares non-empty access modes", () => {
  for (const p of SENSITIVE_PATHS) {
    assert.ok(Array.isArray(p.modes) && p.modes.length > 0, `${p.label} missing modes`);
    for (const m of p.modes) assert.ok(m === "read" || m === "write", `${p.label} bad mode ${m}`);
  }
});

test("credential entries are read+write; persistence targets are write-only", () => {
  const npmrc = SENSITIVE_PATHS.find((p) => p.denyPaths.includes("~/.npmrc"));
  assert.deepEqual(npmrc?.modes.slice().sort(), ["read", "write"]);
  const launch = SENSITIVE_PATHS.find((p) => p.denyPaths.includes("~/Library/LaunchAgents"));
  assert.ok(launch, "LaunchAgents persistence entry must exist");
  assert.deepEqual(launch?.modes, ["write"]);
  assert.equal(launch?.denyKind, "subpath"); // a dir we block creation WITHIN
  const zsh = SENSITIVE_PATHS.find((p) => p.denyPaths.includes("~/.zshrc"));
  assert.deepEqual(zsh?.modes, ["write"]);
  assert.equal(zsh?.denyKind, "literal");
});
```

(Ensure `SENSITIVE_PATHS` and `assert` are imported at the top of the file.)

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/core/test/sensitive-paths.test.ts`
Expected: FAIL — `modes` is undefined; LaunchAgents/`.zshrc` entries don't exist.

- [ ] **Step 3: Implement**

Replace `packages/core/src/sensitive-paths.ts` body with (add the `modes` field to the interface and to every entry; append the persistence block):

```ts
export interface SensitivePath {
  label: string;
  /** Absolute or `~`-relative paths the sandbox denies. */
  denyPaths: string[];
  /** Seatbelt path filter kind for these denyPaths. */
  denyKind: "literal" | "subpath";
  /** Which access is dangerous: "read" → file-read* deny, "write" → file-write* deny. */
  modes: ("read" | "write")[];
  /** Code-detection regex for `secret-exfil`; omit for deny-only paths. */
  detectRe?: RegExp;
}

export const SENSITIVE_PATHS: SensitivePath[] = [
  // Credential reads (also worth blocking writes — overwrite/inject is tamper):
  { label: "npm auth token (~/.npmrc)", denyPaths: ["~/.npmrc"], denyKind: "literal", modes: ["read", "write"], detectRe: /\.npmrc|_authToken/ },
  { label: "AWS credentials file", denyPaths: ["~/.aws"], denyKind: "subpath", modes: ["read", "write"], detectRe: /\.aws\/credentials|\.aws\\credentials/ },
  { label: "SSH private keys", denyPaths: ["~/.ssh"], denyKind: "subpath", modes: ["read", "write"], detectRe: /\.ssh\/id_|id_rsa|id_ed25519/ },
  { label: "system account files", denyPaths: ["/etc/passwd", "/etc/shadow"], denyKind: "literal", modes: ["read", "write"], detectRe: /\/etc\/passwd|\/etc\/shadow/ },
  { label: "GnuPG keyring", denyPaths: ["~/.gnupg"], denyKind: "subpath", modes: ["read", "write"] },
  { label: "netrc credentials", denyPaths: ["~/.netrc"], denyKind: "literal", modes: ["read", "write"] },
  { label: "git credentials", denyPaths: ["~/.git-credentials"], denyKind: "literal", modes: ["read", "write"] },
  { label: "Docker config", denyPaths: ["~/.docker/config.json"], denyKind: "literal", modes: ["read", "write"] },
  { label: "Kubernetes config", denyPaths: ["~/.kube"], denyKind: "subpath", modes: ["read", "write"] },

  // Persistence / tamper targets — write-only (no secret to read; the threat is dropping
  // an autostart payload or appending to a startup file):
  { label: "shell rc (~/.zshrc)", denyPaths: ["~/.zshrc"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.zshenv)", denyPaths: ["~/.zshenv"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.bashrc)", denyPaths: ["~/.bashrc"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.bash_profile)", denyPaths: ["~/.bash_profile"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.profile)", denyPaths: ["~/.profile"], denyKind: "literal", modes: ["write"] },
  { label: "user LaunchAgents", denyPaths: ["~/Library/LaunchAgents"], denyKind: "subpath", modes: ["write"] },
  { label: "user LaunchDaemons", denyPaths: ["~/Library/LaunchDaemons"], denyKind: "subpath", modes: ["write"] },
  { label: "system LaunchAgents", denyPaths: ["/Library/LaunchAgents"], denyKind: "subpath", modes: ["write"] },
  { label: "system LaunchDaemons", denyPaths: ["/Library/LaunchDaemons"], denyKind: "subpath", modes: ["write"] },
  { label: "XDG autostart", denyPaths: ["~/.config/autostart"], denyKind: "subpath", modes: ["write"] },
  { label: "crontab spool", denyPaths: ["/var/at/tabs"], denyKind: "subpath", modes: ["write"] },
];
```

Update the top-of-file doc comment to say the list is shared by `secret-exfil` (reads, via `detectRe`) **and** the sandbox profile generator (reads + writes, via `modes`).

- [ ] **Step 4: Run tests to verify they pass (incl. secret-exfil regression)**

Run: `npx tsx --test packages/core/test/sensitive-paths.test.ts packages/core/test/audit.test.ts`
Expected: PASS (the new mode tests, and `secret-exfil` behavior unchanged — it filters on `detectRe`).

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/sensitive-paths.ts packages/core/test/sensitive-paths.test.ts
git commit -m "feat(core): per-mode SensitivePath + write-only persistence targets"
```

---

### Task 3: `ENV_ALLOWLIST` + `scrubEnv` (sandbox, pure)

**Files:**
- Create: `packages/sandbox/src/env.ts`
- Modify: `packages/sandbox/src/index.ts` (export `scrubEnv`, `ENV_ALLOWLIST`)
- Test: `packages/sandbox/test/env.test.ts`

**Interfaces:**
- Consumes: `Capability` from `@sentinel/core` (the `env`-kind approvals).
- Produces: `scrubEnv(sourceEnv: NodeJS.ProcessEnv, approvedEnv: Capability[]): NodeJS.ProcessEnv` — returns a new env containing only allowlisted names plus names granted by an approved `env` capability. Pure. Consumed by Task 5 (runner).

- [ ] **Step 1: Write the failing test**

Create `packages/sandbox/test/env.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { scrubEnv, ENV_ALLOWLIST } from "../src/env.js";
import type { Capability } from "@sentinel/core";

const envCap = (target: string): Capability => ({ kind: "env", target, evidence: [] });

describe("scrubEnv (fail-closed allowlist)", () => {
  const src = {
    PATH: "/usr/bin", HOME: "/Users/x", npm_config_cache: "/c", npm_package_name: "p",
    LC_ALL: "en_US", NODE_OPTIONS: "--x",
    NPM_TOKEN: "SEKRET", AWS_SECRET_ACCESS_KEY: "SEKRET2", SSH_AUTH_SOCK: "/tmp/agent.sock",
    NODE_AUTH_TOKEN: "SEKRET3", HONCHO_API_KEY: "SEKRET4", MY_PROD_CREDENTIAL: "SEKRET5",
  };

  test("passes allowlisted vars and prefixes", () => {
    const out = scrubEnv(src, []);
    assert.equal(out.PATH, "/usr/bin");
    assert.equal(out.HOME, "/Users/x");
    assert.equal(out.npm_config_cache, "/c");      // npm_ prefix
    assert.equal(out.npm_package_name, "p");
    assert.equal(out.LC_ALL, "en_US");             // LC_ prefix
    assert.equal(out.NODE_OPTIONS, "--x");         // exact
  });

  test("drops every credential — incl. novel-named and NODE_AUTH_TOKEN", () => {
    const out = scrubEnv(src, []);
    for (const k of ["NPM_TOKEN", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "NODE_AUTH_TOKEN", "HONCHO_API_KEY", "MY_PROD_CREDENTIAL"]) {
      assert.equal(out[k], undefined, `${k} must be dropped (fail-closed)`);
    }
  });

  test("an approved env capability lets exactly that var through", () => {
    const out = scrubEnv(src, [envCap("NPM_TOKEN")]);
    assert.equal(out.NPM_TOKEN, "SEKRET");
    assert.equal(out.AWS_SECRET_ACCESS_KEY, undefined); // unrelated secret still dropped
  });

  test("deterministic for the same inputs", () => {
    assert.deepEqual(scrubEnv(src, [envCap("NPM_TOKEN")]), scrubEnv(src, [envCap("NPM_TOKEN")]));
  });

  test("NODE allowlist is exact, not a prefix (guards NODE_AUTH_TOKEN)", () => {
    assert.ok(!ENV_ALLOWLIST.exact.has("NODE_AUTH_TOKEN"));
    assert.ok(!ENV_ALLOWLIST.prefixes.some((p) => "NODE_AUTH_TOKEN".startsWith(p)));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/sandbox/test/env.test.ts`
Expected: FAIL — `../src/env.js` doesn't exist.

- [ ] **Step 3: Implement**

Create `packages/sandbox/src/env.ts`. The allowlist is validated against a real `npm install` env dump (see ADR-0017): `npm_` and `LC_` are safe prefixes (npm does NOT leak registry auth into the `npm_config_` namespace — probed); `NODE` vars are enumerated **exactly** so the `NODE*` prefix can't pass `NODE_AUTH_TOKEN`; build-toolchain vars carry no secrets.

```ts
import type { Capability } from "@sentinel/core";

/**
 * Fail-closed env allowlist for sandboxed lifecycle scripts. Pass ONLY these; any other
 * var — including a novel-named credential — is dropped. Validated against a real `npm
 * install` lifecycle env (ADR-0017). The load-bearing behavior is the DROP of operator-shell
 * secrets (SSH_AUTH_SOCK, AWS_*, *_TOKEN); the npm_* entries are forward-looking for the
 * deferred `install --enforce` path (run-scripts itself isn't invoked by npm).
 */
export const ENV_ALLOWLIST = {
  prefixes: ["npm_", "LC_"],
  exact: new Set([
    "PATH", "HOME", "SHELL", "PWD", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP",
    "LANG", "TERM", "INIT_CWD",
    "NODE", "NODE_OPTIONS", "NODE_PATH", "NODE_ENV",     // exact, NOT a NODE* prefix
    "CPPFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS", "PKG_CONFIG_PATH", "PYTHON", "MAKEFLAGS",
  ]),
};

function allowed(name: string): boolean {
  return ENV_ALLOWLIST.exact.has(name) || ENV_ALLOWLIST.prefixes.some((p) => name.startsWith(p));
}

/** Return a new env containing only allowlisted vars plus those granted by an `env` approval. */
export function scrubEnv(sourceEnv: NodeJS.ProcessEnv, approvedEnv: Capability[]): NodeJS.ProcessEnv {
  const granted = new Set(approvedEnv.filter((c) => c.kind === "env").map((c) => c.target));
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(sourceEnv)) {
    if (v === undefined) continue;
    if (allowed(k) || granted.has(k)) out[k] = v;
  }
  return out;
}
```

Add to `packages/sandbox/src/index.ts`:

```ts
export { scrubEnv, ENV_ALLOWLIST } from "./env.js";
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx --test packages/sandbox/test/env.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/env.ts packages/sandbox/src/index.ts packages/sandbox/test/env.test.ts
git commit -m "feat(sandbox): fail-closed ENV_ALLOWLIST + pure scrubEnv"
```

---

### Task 4: write-confinement in `generateProfile` (sandbox, pure)

**Files:**
- Modify: `packages/sandbox/src/profile.ts:41-57` (`generateProfile`)
- Test: `packages/sandbox/test/profile.test.ts`

**Interfaces:**
- Consumes: `SENSITIVE_PATHS` (now with `modes`), `Capability` from core.
- Produces: `generateProfile` unchanged signature; output now also contains `(deny file-write* …)` lines for write-mode entries not covered by an approved `filesystem` capability. A `filesystem` approval relaxes BOTH the read and write deny for its target.

- [ ] **Step 1: Write the failing test**

Add to `packages/sandbox/test/profile.test.ts`:

```ts
test("emits file-write* denies for write-mode entries (persistence + credentials)", () => {
  const p = generateProfile([], { homeDir: HOME });
  assert.match(p, /deny file-write\* \(subpath "\/Users\/test\/Library\/LaunchAgents"\)/);
  assert.match(p, /deny file-write\* \(literal "\/Users\/test\/\.zshrc"\)/);
  assert.match(p, /deny file-write\* \(literal "\/Users\/test\/\.npmrc"\)/); // credential: read AND write
});

test("write denies are firmlink-canonicalized", () => {
  const p = generateProfile([], { homeDir: HOME });
  assert.match(p, /deny file-write\* \(subpath "\/private\/var\/at\/tabs"\)/);
  assert.doesNotMatch(p, /file-write\* \(subpath "\/var\/at\/tabs"\)/); // un-canonical alias not used
});

test("a filesystem approval omits BOTH the read and write deny for that path", () => {
  const p = generateProfile([fs(".npmrc")], { homeDir: HOME });
  assert.doesNotMatch(p, /file-read\* \(literal "\/Users\/test\/\.npmrc"\)/);
  assert.doesNotMatch(p, /file-write\* \(literal "\/Users\/test\/\.npmrc"\)/);
});

test("read-only behavior unchanged: write-only entries emit NO read deny", () => {
  const p = generateProfile([], { homeDir: HOME });
  assert.doesNotMatch(p, /file-read\* \(literal "\/Users\/test\/\.zshrc"\)/); // .zshrc is write-only
});
```

(`fs`, `HOME`, `generateProfile`, `assert` already exist in this file.)

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/sandbox/test/profile.test.ts`
Expected: FAIL — no `file-write*` lines emitted yet.

- [ ] **Step 3: Implement**

Rewrite the loop in `packages/sandbox/src/profile.ts` `generateProfile` (replace the single read-deny loop). Factor the per-mode emission so read and write share `pathCovers`/`canonicalizeMacPath`:

```ts
export function generateProfile(approved: Capability[], opts: { homeDir: string }): string {
  const expand = (p: string) => (p.startsWith("~") ? opts.homeDir + p.slice(1) : p);
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");

  const lines = ["(version 1)", "(allow default)"];
  const denyFor = (mode: "read" | "write", op: "file-read*" | "file-write*") => {
    for (const sp of SENSITIVE_PATHS) {
      if (!sp.modes.includes(mode)) continue;
      const uncovered = sp.denyPaths.filter((dp) => !approvedFs.some((t) => pathCovers(t, dp)));
      if (uncovered.length === 0) continue;
      const items = uncovered.map((dp) => `(${sp.denyKind} "${canonicalizeMacPath(expand(dp))}")`).join(" ");
      lines.push(`(deny ${op} ${items})`);
    }
  };
  denyFor("read", "file-read*");
  denyFor("write", "file-write*");
  if (!hasNetwork) lines.push("(deny network*)");
  return lines.join("\n") + "\n";
}
```

(All read denies emit first, then all write denies — keeps output ordering deterministic and the existing read-deny tests' line shapes intact.)

- [ ] **Step 4: Run test to verify it passes (incl. existing profile tests)**

Run: `npx tsx --test packages/sandbox/test/profile.test.ts`
Expected: PASS — new write tests pass and all existing read/network/firmlink/coverage tests stay green.

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/profile.ts packages/sandbox/test/profile.test.ts
git commit -m "feat(sandbox): file-write* denies for write-mode SensitivePaths (persistence + tamper)"
```

---

### Task 5: wire `scrubEnv` into the runner (sandbox)

**Files:**
- Modify: `packages/sandbox/src/runner.ts` (`runLifecycleScripts` gains `approved`, computes scrubbed env, passes it as `opts.env`)
- Test: `packages/sandbox/test/runner.test.ts` (create — pure, fake Sandbox, no kernel)

**Interfaces:**
- Consumes: `scrubEnv` (Task 3), `Capability` (core).
- Produces: `runLifecycleScripts({ packageDir, profile, sandbox, approved })` — `approved: Capability[]` (default `[]`). Each `sandbox.run` now receives `env: scrubEnv(process.env, approved)`. Consumed by Task 6 (CLI).

- [ ] **Step 1: Write the failing test**

Create `packages/sandbox/test/runner.test.ts` (a fake `Sandbox` captures the env it was handed — pure, runs everywhere):

```ts
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { runLifecycleScripts } from "../src/runner.js";
import type { Sandbox, SandboxResult } from "../src/types.js";
import type { Capability } from "@sentinel/core";

function fakeSandbox(captured: NodeJS.ProcessEnv[]): Sandbox {
  return { run(_cmd, opts: { cwd: string; profile: string; env?: NodeJS.ProcessEnv }): SandboxResult {
    captured.push(opts.env ?? {});
    return { exitCode: 0, stdout: "", stderr: "" };
  } };
}

describe("runLifecycleScripts env scrubbing", () => {
  test("passes a scrubbed env to the sandbox (secret dropped, allowlisted kept, approval honored)", () => {
    const dir = mkdtempSync(join(tmpdir(), "run-env-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: "echo hi" } }));
    process.env.SENTINEL_TEST_SECRET_TOKEN = "LEAK";  // a credential-shaped var
    const captured: NodeJS.ProcessEnv[] = [];
    const approved: Capability[] = [{ kind: "env", target: "SENTINEL_TEST_SECRET_TOKEN", evidence: [] }];
    try {
      runLifecycleScripts({ packageDir: dir, profile: "(version 1)\n(allow default)\n", sandbox: fakeSandbox(captured), approved });
      const env = captured[0]!;
      assert.equal(env.SENTINEL_TEST_SECRET_TOKEN, "LEAK", "approved env var passes through");
      assert.ok(env.PATH !== undefined, "allowlisted PATH kept");
      // and without the approval it is dropped:
      const captured2: NodeJS.ProcessEnv[] = [];
      runLifecycleScripts({ packageDir: dir, profile: "(version 1)\n(allow default)\n", sandbox: fakeSandbox(captured2), approved: [] });
      assert.equal(captured2[0]!.SENTINEL_TEST_SECRET_TOKEN, undefined, "unapproved secret dropped");
    } finally {
      delete process.env.SENTINEL_TEST_SECRET_TOKEN;
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/sandbox/test/runner.test.ts`
Expected: FAIL — `runLifecycleScripts` doesn't accept `approved` / doesn't pass `env`.

- [ ] **Step 3: Implement**

Edit `packages/sandbox/src/runner.ts`:

```ts
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Sandbox } from "./types.js";
import { scrubEnv } from "./env.js";
import type { Capability } from "@sentinel/core";

export interface ScriptResult {
  hook: string;
  command: string;
  exitCode: number;
}

const LIFECYCLE = ["preinstall", "install", "postinstall"] as const;

/** Run a package's present lifecycle scripts under the sandbox profile + scrubbed env. */
export function runLifecycleScripts(opts: {
  packageDir: string;
  profile: string;
  sandbox: Sandbox;
  approved?: Capability[];
}): { results: ScriptResult[]; failed: boolean } {
  let scripts: Record<string, string> = {};
  try {
    scripts = JSON.parse(readFileSync(join(opts.packageDir, "package.json"), "utf8"))?.scripts ?? {};
  } catch {
    scripts = {};
  }
  const env = scrubEnv(process.env, opts.approved ?? []);
  const results: ScriptResult[] = [];
  for (const hook of LIFECYCLE) {
    const command = scripts[hook];
    if (!command) continue;
    const r = opts.sandbox.run(command, { cwd: opts.packageDir, profile: opts.profile, env });
    results.push({ hook, command, exitCode: r.exitCode });
  }
  return { results, failed: results.some((r) => r.exitCode !== 0) };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx --test packages/sandbox/test/runner.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/runner.ts packages/sandbox/test/runner.test.ts
git commit -m "feat(sandbox): runner applies scrubEnv before spawning lifecycle scripts"
```

---

### Task 6: CLI integration — `env` approvals + threading (cli)

**Files:**
- Modify: `packages/cli/src/index.ts` (`parseApprovals` kind whitelist; `run-scripts` threads `approved`; operator note)
- Test: `packages/cli/test/run-scripts.test.ts`

**Interfaces:**
- Consumes: `runLifecycleScripts({ …, approved })` (Task 5).
- Produces: `parseApprovals` accepts `env:<NAME>`; `run-scripts` passes the parsed `approved` set into the runner and prints a one-line note that credential env-vars are scrubbed by default.

- [ ] **Step 1: Write the failing test**

Add to `packages/cli/test/run-scripts.test.ts`:

```ts
test("parseApprovals accepts env:<NAME>", () => {
  const caps = parseApprovals(["env:NPM_TOKEN", "network:x", "bogus:y"]);
  assert.ok(caps.some((c) => c.kind === "env" && c.target === "NPM_TOKEN"));
  assert.ok(!caps.some((c) => c.kind === ("bogus" as never)));
});
```

(Ensure `parseApprovals` and `assert` are imported in this test file.)

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/cli/test/run-scripts.test.ts`
Expected: FAIL — `env` is rejected by `parseApprovals`'s kind whitelist.

- [ ] **Step 3: Implement**

In `packages/cli/src/index.ts`, extend the kind whitelist in `parseApprovals` (line ~262):

```ts
    if (!["network", "filesystem", "process", "native", "env"].includes(kind) || !target) continue;
```

In the `run-scripts` `.action(...)`, pass `approved` to the runner and add the operator note. Replace the `runLifecycleScripts(...)` call and add the note near the existing network warning:

```ts
    if (approved.some((c) => c.kind === "env")) {
      console.error("\x1b[33mNote: credential-shaped env-vars are scrubbed; approved env capabilities are passed through.\x1b[0m");
    } else {
      console.error("\x1b[33mNote: credential-shaped env-vars are scrubbed by default (fail-closed). Grant one with --approve env:NAME.\x1b[0m");
    }
    const profile = generateProfile(approved, { homeDir: homedir() });
    const { results, failed } = runLifecycleScripts({ packageDir: dir, profile, sandbox: new SeatbeltSandbox(), approved });
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx --test packages/cli/test/run-scripts.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/index.ts packages/cli/test/run-scripts.test.ts
git commit -m "feat(cli): accept --approve env:NAME and thread approvals into the runner"
```

---

### Task 7: darwin-gated enforcement proof (sandbox)

**Files:**
- Modify: `packages/sandbox/test/seatbelt.test.ts` (add two enforcement tests to the existing `{ skip: darwin ? … }` describe block)

**Interfaces:**
- Consumes: `SeatbeltSandbox`, `runLifecycleScripts`, `generateProfile`, `scrubEnv` — all already exported.

- [ ] **Step 1: Write the failing test**

Add inside the existing `describe("SeatbeltSandbox enforcement", { skip: … })` block in `packages/sandbox/test/seatbelt.test.ts` (add `import { scrubEnv } from "../src/env.js";` and `generateProfile` is already imported):

```ts
  test("an unapproved credential env-var never reaches the script (assert on EFFECT)", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "sb-env-")));
    const out = join(dir, "leak.txt");
    // The probe script writes whatever it sees in the credential var.
    const cmd = `node -e "require('fs').writeFileSync('${out}', String(process.env.SECRET_API_KEY||''))"`;
    const env = scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, []); // no approval
    const profile = `(version 1)\n(allow default)\n`;
    new SeatbeltSandbox().run(cmd, { cwd: dir, profile, env });
    const got = existsSync(out) ? readFileSync(out, "utf8") : "";
    assert.ok(!got.includes("TOPSECRET-ENV"), "the credential env-var must not have reached the script");

    // With the approval, the same var IS available:
    const env2 = scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, [{ kind: "env", target: "SECRET_API_KEY", evidence: [] }]);
    new SeatbeltSandbox().run(cmd, { cwd: dir, profile, env: env2 });
    assert.ok(readFileSync(out, "utf8").includes("TOPSECRET-ENV"), "an approved env var is passed through");
  });

  test("an unapproved write to a sensitive path is denied (planted file unchanged)", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "sb-write-")));
    const planted = join(dir, "rc");      // stand-in for a shell rc / persistence file
    writeFileSync(planted, "ORIGINAL");
    // deny writes to this exact file; script swallows the EPERM like real malware
    const profile = `(version 1)\n(allow default)\n(deny file-write* (literal "${planted}"))\n`;
    new SeatbeltSandbox().run(`echo PWNED >> "${planted}" 2>/dev/null || true`, { cwd: dir, profile });
    assert.equal(readFileSync(planted, "utf8"), "ORIGINAL", "the planted file must be unchanged");
  });
```

- [ ] **Step 2: Run test to verify it fails (or skips off-darwin)**

Run: `npx tsx --test packages/sandbox/test/seatbelt.test.ts`
Expected (darwin): the new tests run. They should PASS once Tasks 3–5 are in — but run now to confirm they're wired (if scrubEnv import resolves and assertions hold). Off-darwin: the whole block SKIPS (suite stays green).

- [ ] **Step 3: (no new src — this task is the integration proof)**

These tests exercise code already implemented in Tasks 3–5. If a test fails on darwin, the bug is in that task's code — fix there, not by weakening the assertion.

- [ ] **Step 4: Run to verify they pass on darwin**

Run: `npx tsx --test packages/sandbox/test/seatbelt.test.ts`
Expected (darwin): PASS. Off-darwin: SKIP.

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/test/seatbelt.test.ts
git commit -m "test(sandbox): darwin-gated proof — env scrub + write-confinement enforce on effect"
```

---

### Task 8: docs — ADR-0017, annotate ADR-0016, ARCHITECTURE, CLAUDE.md

**Files:**
- Create: `docs/adr/0017-sandbox-env-scrub-and-write-confinement.md`
- Modify: `docs/adr/0016-macos-seatbelt-sandbox-runner.md` (annotate the two gaps as closed)
- Modify: `ARCHITECTURE.md` (sandbox section: env-scrub + write-confinement surfaces)
- Modify: `CLAUDE.md` (Phase 4 line; `env` kind; final test count)

- [ ] **Step 1: Write ADR-0017**

Create `docs/adr/0017-sandbox-env-scrub-and-write-confinement.md` following the existing ADR format (Status: Accepted; Context; Decision; Consequences). It MUST state:
- Env scrubbing is **allowlist-based / fail-closed** (D2); the `env` **capability kind** is the escape hatch (D3); `--approve env:NAME`.
- The `ENV_ALLOWLIST` was validated against a real `npm install` env; the **load-bearing** behavior is dropping operator-shell secrets (`SSH_AUTH_SOCK`, `AWS_*`, `*_TOKEN`) — `run-scripts` is not invoked by npm, so `npm_*` entries are forward-looking for the deferred `install --enforce` path.
- `NODE` vars are enumerated **exactly** (not a `NODE*` prefix) to avoid passing `NODE_AUTH_TOKEN`; modern npm does **not** leak registry auth into the `npm_config_` namespace (probed).
- Write-confinement: **per-mode `SensitivePath`** (D4); `file-write*` denies on credential paths + new persistence targets (LaunchAgents/Daemons, shell rc, autostart, crontab spool); firmlink canonicalization is **required for writes too** (probed: a `/tmp` deny does not match; `/private/tmp` does); directory targets use `denyKind: "subpath"` to block creation-within.
- A `filesystem` approval relaxes **both** read and write for its target (D5); read/write sub-kinds deferred (YAGNI).
- The honesty caveat is unchanged: the failure report is static-inferred/best-effort; the hard guarantee is kernel enforcement.

- [ ] **Step 2: Annotate ADR-0016**

In `docs/adr/0016-macos-seatbelt-sandbox-runner.md`, add a note to the deferred-items list that env-var scrubbing and write-confinement are now closed by **ADR-0017** (do not edit the original Accepted decision — append an annotation).

- [ ] **Step 3: Update ARCHITECTURE.md + CLAUDE.md**

- ARCHITECTURE.md sandbox section: add the env-scrub (fail-closed allowlist + `env` capability) and write-confinement (per-mode `SensitivePath`, persistence denies) surfaces.
- CLAUDE.md: add a Phase 4 line ("Phase 4 hardened the sandbox: fail-closed env-var scrubbing via an `env` capability + `file-write*` denies on credential/persistence paths"); add `env` to any capability-kind enumeration; update the test count from 118 to the new total (see Step 4).

- [ ] **Step 4: Full build + test, then pin the count**

Run: `npm run build && npm test`
Expected: build clean; suite green. Count the total, set CLAUDE.md's "must be N/N" to that number, and confirm the malicious fixture is still **blocked** (the audit/score tests are untouched, but verify the run printed no scoring regressions).

- [ ] **Step 5: Commit**

```bash
git add docs/adr/0017-sandbox-env-scrub-and-write-confinement.md docs/adr/0016-macos-seatbelt-sandbox-runner.md ARCHITECTURE.md CLAUDE.md
git commit -m "docs: ADR-0017 sandbox hardening; annotate ADR-0016; ARCHITECTURE + CLAUDE updates"
```

---

## Self-Review

**Spec coverage:** §4.1 env kind+detection → Task 1; §4.2 scrubEnv+ENV_ALLOWLIST → Task 3; §4.3 seam → Task 5; §5.1 per-mode SensitivePath+persistence → Task 2; §5.2 write denies → Task 4; §6 CLI/report → Task 6 (`unapprovedAtoms` already covers `env` via kind-generic atoms — no code needed); §7 testing → Tasks 1–7 (pure every-platform + darwin-gated enforcement + secret-exfil regression in Task 2 Step 4); §8 docs → Task 8. All covered.

**Placeholder scan:** every code step shows complete code; commands have expected output. The only deliberately-prose step is ADR-0017 prose (Task 8 Step 1), specified as a content checklist — acceptable for a doc.

**Type consistency:** `scrubEnv(sourceEnv, approvedEnv)` signature identical across Tasks 3/5/7; `runLifecycleScripts({…, approved})` identical across Tasks 5/6; `CapabilityKind` extended once (Task 1) and consumed everywhere; `ENV_ALLOWLIST.{prefixes,exact}` shape consistent between Task 3 impl and its test.
