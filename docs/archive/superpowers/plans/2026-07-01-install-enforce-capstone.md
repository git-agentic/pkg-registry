# `sentinel install --enforce` Capstone Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `sentinel install --enforce`, which runs a real `npm install` where every lifecycle script in the dependency tree executes under `createSandbox()` via a `sentinel-script-shell` wrapper, with npm's env replicated but credential-screened, failing closed if containment is unavailable.

**Architecture:** Script-shell interposition (probe-confirmed): `--enforce` sets `npm_config_script_shell` to a Sentinel wrapper bin and runs a normal `npm install --registry <proxy>`. npm invokes `<wrapper> -c "<cmd>"` for each lifecycle script, in dependency order, with full env/cwd/`.bin` PATH already set; the wrapper scrubs the env, resolves the package's approved capabilities, and runs the command under the sandbox. npm owns ordering/env/workspaces; the wrapper only interposes containment.

**Tech Stack:** Node 24 (also 22), TypeScript (NodeNext ESM, `.js` specifiers), npm workspaces, `node:test` + `tsx`, Express 5 proxy, macOS `sandbox-exec` / Linux `bwrap` via `@sentinel/sandbox`.

## Global Constraints

- **ESM only** (`"type": "module"`); internal imports use `.js` specifiers even from `.ts` sources (NodeNext). No top-level `require` in shipped `.ts`. (Fixture/probe *scripts-as-text* may use `require` — they are package payloads, not our source.)
- **Fail closed:** `--enforce` must NEVER run a lifecycle script unsandboxed. Any inability to guarantee kernel containment (sandbox unavailable, unapproved dependency, unbuildable safe env) → the wrapper exits non-zero → npm aborts. Never `exec` the command outside the sandbox.
- **`scrubEnv` stays pure & deterministic** (same `(sourceEnv, approvedEnv)` ⇒ same output). The credential-screen is a pure predicate.
- **Approval states** (`Manifest.approvalState`): safe-to-run = `"approved"`, `"inherited"`, `"n-a"` (no caps); fail-closed = `"required"`, `"denied"`.
- **Tests assert on the protected-resource EFFECT** (secret bytes never obtained, planted file unchanged), never on exit codes. Enforcement effect-tests are platform-gated: run where a sandbox enforces (Seatbelt on darwin, bwrap on Linux-with-userns), skip elsewhere.
- **Fixtures:** benign probe packages live in `fixtures/benign/<name>/<version>/package/`; re-run `npm run fixtures` after editing. RFC 5737 IPs only (`198.51.100.0/24`, `203.0.113.0/24`). Tests stay hermetic (`LocalFixtureUpstream`, never live npm registry).
- **Build:** `npm run build` = `tsc --build`. The mount may EPERM on `rm` of `dist/` — use `npx tsc --build --force <pkg>`, never `rm -rf dist`.
- **Test baseline before this work:** darwin `npm test` = 157 tests, 155 pass, 2 skip. Test glob: `packages/**/test/*.test.ts`. Keep the CLAUDE.md count line honest (final task).
- Scoring, rules, proxy audit path, policy, and approval store are UNCHANGED by this phase.

---

### Task 1: `scrubEnv` — narrow the `npm_` prefix + credential-screen `npm_config_*`

Turn the inert blanket `npm_` allowlist prefix (Phase 4, ADR-0017) into the narrowed, credential-screened form this path requires.

**Files:**
- Modify: `packages/sandbox/src/env.ts`
- Test: `packages/sandbox/test/env.test.ts`

**Interfaces:**
- Produces: `scrubEnv(sourceEnv, approvedEnv)` (signature unchanged) with new internal behavior; `ENV_ALLOWLIST` gains narrowed npm prefixes; new exported `CREDENTIAL_ENV_RE`.

- [ ] **Step 1: Write the failing tests**

Add to `packages/sandbox/test/env.test.ts` (keep existing tests):

```ts
import { scrubEnv, ENV_ALLOWLIST, CREDENTIAL_ENV_RE } from "../src/env.js";
// ... (existing imports/tests remain)

describe("scrubEnv npm narrowing + credential-screen", () => {
  const scrub = (e: Record<string, string>) => scrubEnv(e, []);
  test("keeps benign npm-injected vars a lifecycle script needs", () => {
    const out = scrub({
      npm_package_name: "p", npm_package_version: "1.0.0", npm_lifecycle_event: "postinstall",
      npm_node_execpath: "/n/bin/node", npm_command: "install", npm_execpath: "/n/npm-cli.js",
      npm_config_cache: "/c", npm_config_user_agent: "npm/11", npm_config_node_gyp: "/g",
      INIT_CWD: "/proj", PATH: "/proj/node_modules/.bin:/usr/bin",
    });
    for (const k of ["npm_package_name","npm_lifecycle_event","npm_node_execpath","npm_command","npm_execpath","npm_config_cache","npm_config_user_agent","INIT_CWD","PATH"])
      assert.ok(out[k] !== undefined, `${k} must be kept`);
  });
  test("drops credential-shaped npm_config_* keys (any npm version)", () => {
    const out = scrub({
      "npm_config__auth": "BASIC", "npm_config__authToken": "T", "npm_config__password": "P",
      "npm_config_//registry.npmjs.org/:_authToken": "SCOPED", "npm_config_registry_secret": "S",
      npm_config_cache: "/c",
    });
    assert.equal(out["npm_config__auth"], undefined);
    assert.equal(out["npm_config__authToken"], undefined);
    assert.equal(out["npm_config__password"], undefined);
    assert.equal(out["npm_config_//registry.npmjs.org/:_authToken"], undefined);
    assert.equal(out["npm_config_registry_secret"], undefined);
    assert.equal(out["npm_config_cache"], "/c", "benign config still kept");
  });
  test("drops unknown npm_ vars outside the narrowed sub-groups (fail-closed narrowing)", () => {
    assert.equal(scrub({ npm_mystery: "x" })["npm_mystery"], undefined);
  });
  test("an approved env: capability still passes its exact var through", () => {
    const out = scrubEnv({ MY_TOKEN: "v" }, [{ kind: "env", target: "MY_TOKEN", evidence: [] }]);
    assert.equal(out["MY_TOKEN"], "v");
  });
  test("CREDENTIAL_ENV_RE matches auth/token/password/secret shapes, not benign", () => {
    for (const k of ["npm_config__authToken","FOO_SECRET","x_password","AUTH_KEY","registry_token"]) assert.ok(CREDENTIAL_ENV_RE.test(k), k);
    for (const k of ["npm_config_cache","PATH","npm_package_name"]) assert.ok(!CREDENTIAL_ENV_RE.test(k), k);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx tsx --test packages/sandbox/test/env.test.ts`
Expected: FAIL — `CREDENTIAL_ENV_RE` not exported; `npm_mystery` currently kept (blanket prefix), credential keys currently kept.

- [ ] **Step 3: Edit `packages/sandbox/src/env.ts`**

Replace the `ENV_ALLOWLIST` prefixes and `allowed` with the narrowed + screened form (keep the existing `exact` set, ADD `npm_command`/`npm_execpath` to it):

```ts
/** Env-var names that look credential-bearing — dropped regardless of allowlist match. */
export const CREDENTIAL_ENV_RE = /_auth|authtoken|_password|passwd|token|secret|credential/i;

export const ENV_ALLOWLIST = {
  // Narrowed npm sub-groups a lifecycle script legitimately needs (was a blanket "npm_" — ADR-0017).
  prefixes: ["npm_package_", "npm_lifecycle_", "npm_node_", "npm_config_", "LC_"],
  exact: new Set([
    "PATH", "HOME", "SHELL", "PWD", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP",
    "LANG", "TERM", "INIT_CWD",
    "NODE", "NODE_OPTIONS", "NODE_PATH", "NODE_ENV",     // exact, NOT a NODE* prefix
    "CPPFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS", "PKG_CONFIG_PATH", "PYTHON", "MAKEFLAGS",
    "npm_command", "npm_execpath",
  ]),
};

function allowed(name: string): boolean {
  if (CREDENTIAL_ENV_RE.test(name)) return false;   // credential-screen wins over any allowlist match
  return ENV_ALLOWLIST.exact.has(name) || ENV_ALLOWLIST.prefixes.some((p) => name.startsWith(p));
}
```

Leave `scrubEnv` itself unchanged (it calls `allowed` and honors `env:` approvals; note the `env:` approval must still bypass — see Step 4).

- [ ] **Step 4: Preserve the `env:` approval bypass (verify, adjust if needed)**

`scrubEnv` keeps a var if `allowed(k) || granted.has(k)`. An approved `env:NAME` must pass even though the operator explicitly approved it. Confirm the existing `scrubEnv` body is:

```ts
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
(An operator-approved `env:MY_TOKEN` passes via `granted` even though `CREDENTIAL_ENV_RE` would screen it — approvals are an explicit operator override. This matches Phase 4 semantics.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx tsx --test packages/sandbox/test/env.test.ts`
Expected: PASS (new + existing). If an existing test asserted the old blanket `npm_` behavior kept a bare `npm_foo`, update it to the narrowed expectation.

- [ ] **Step 6: Commit**

```bash
git add packages/sandbox/src/env.ts packages/sandbox/test/env.test.ts
git commit -m "feat(sandbox): narrow npm_ allowlist to safe sub-groups + credential-screen (ADR-0017)"
```

---

### Task 2: enforce helpers — approval resolution, root detection, command parse (cli)

Pure, testable logic the wrapper needs, split out so it can be unit-tested without spawning npm.

**Files:**
- Create: `packages/cli/src/enforce.ts`
- Test: `packages/cli/test/enforce.test.ts`

**Interfaces:**
- Consumes: `Manifest` from `./format.js`; `Capability` from `@sentinel/core`.
- Produces:
  - `class EnforceError extends Error` (fail-closed marker)
  - `approvedCapsForManifest(m: Manifest): Capability[]` — returns `m.capabilities` for `approved`/`inherited`, `[]` for `n-a`; throws `EnforceError` for `required`/`denied`.
  - `isRootScript(cwd: string, initCwd: string | undefined): boolean` — true when the script is the install root's own (not a dependency under `node_modules`).
  - `commandFromArgv(argv: string[]): string` — extract `<cmd>` from `["-c", "<cmd>"]`; throws `EnforceError` if not that shape.

- [ ] **Step 1: Write the failing tests**

```ts
// packages/cli/test/enforce.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { approvedCapsForManifest, isRootScript, commandFromArgv, EnforceError } from "../src/enforce.js";
import type { Manifest } from "../src/format.js";

const mk = (state: string, caps: any[] = []): Manifest => ({
  meta: { name: "p", version: "1.0.0", integrity: "sha512-x" },
  verdict: "allow", approvalState: state, capabilities: caps, approvalRequired: [], inheritedFrom: null,
});

describe("approvedCapsForManifest", () => {
  test("approved/inherited return the manifest capabilities", () => {
    const caps = [{ kind: "network", target: "198.51.100.5", evidence: [] }];
    assert.deepEqual(approvedCapsForManifest(mk("approved", caps)), caps);
    assert.deepEqual(approvedCapsForManifest(mk("inherited", caps)), caps);
  });
  test("n-a returns empty (no capabilities, strict sandbox)", () => {
    assert.deepEqual(approvedCapsForManifest(mk("n-a")), []);
  });
  test("required and denied FAIL CLOSED (throw)", () => {
    assert.throws(() => approvedCapsForManifest(mk("required")), EnforceError);
    assert.throws(() => approvedCapsForManifest(mk("denied")), EnforceError);
  });
});

describe("isRootScript", () => {
  test("cwd equal to INIT_CWD is the root project", () => {
    assert.equal(isRootScript("/proj", "/proj"), true);
  });
  test("cwd under node_modules is a dependency", () => {
    assert.equal(isRootScript("/proj/node_modules/dep", "/proj"), false);
  });
  test("missing INIT_CWD falls back to the node_modules check", () => {
    assert.equal(isRootScript("/proj/node_modules/dep", undefined), false);
    assert.equal(isRootScript("/proj", undefined), true);
  });
});

describe("commandFromArgv", () => {
  test("extracts the command after -c", () => {
    assert.equal(commandFromArgv(["-c", "node -e \"x\""]), "node -e \"x\"");
  });
  test("throws when the shape is not -c <cmd>", () => {
    assert.throws(() => commandFromArgv(["node", "x"]), EnforceError);
    assert.throws(() => commandFromArgv(["-c"]), EnforceError);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx tsx --test packages/cli/test/enforce.test.ts`
Expected: FAIL — `Cannot find module '../src/enforce.js'`.

- [ ] **Step 3: Implement `packages/cli/src/enforce.ts`**

```ts
import type { Capability } from "@sentinel/core";
import type { Manifest } from "./format.js";

/** Raised when enforcement cannot be guaranteed — the wrapper must fail closed (never run unsandboxed). */
export class EnforceError extends Error {}

/**
 * Approved capabilities for a dependency's lifecycle scripts, from its proxy manifest.
 * "approved"/"inherited" ⇒ its detected capabilities; "n-a" ⇒ none (strict sandbox);
 * "required"/"denied" ⇒ fail closed (the package is not cleared to run).
 */
export function approvedCapsForManifest(m: Manifest): Capability[] {
  switch (m.approvalState) {
    case "approved":
    case "inherited":
      return m.capabilities;
    case "n-a":
      return [];
    default: // "required" | "denied" | anything unexpected
      throw new EnforceError(`package ${m.meta.name}@${m.meta.version} is not approved (state: ${m.approvalState})`);
  }
}

/** True when the lifecycle script belongs to the install root itself, not a dependency under node_modules. */
export function isRootScript(cwd: string, initCwd: string | undefined): boolean {
  if (cwd.includes("/node_modules/")) return false;
  if (initCwd) return cwd === initCwd;
  return true;
}

/** Extract the lifecycle command from npm's `<shell> -c "<cmd>"` invocation. */
export function commandFromArgv(argv: string[]): string {
  if (argv.length >= 2 && argv[0] === "-c" && typeof argv[1] === "string") return argv[1];
  throw new EnforceError(`sentinel-script-shell expects \`-c <command>\`, got: ${JSON.stringify(argv)}`);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx tsx --test packages/cli/test/enforce.test.ts`
Expected: PASS (10 assertions across 3 describes).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/enforce.ts packages/cli/test/enforce.test.ts
git commit -m "feat(cli): enforce helpers — approval resolution, root detection, -c command parse"
```

---

### Task 3: `sentinel-script-shell` wrapper bin (cli)

The executable npm invokes as the script-shell. Wires Task 1 + Task 2 + `createSandbox`, fail-closed.

**Files:**
- Create: `packages/cli/src/script-shell.ts`
- Modify: `packages/cli/package.json` (add the `sentinel-script-shell` bin)
- Test: `packages/cli/test/script-shell.test.ts`

**Interfaces:**
- Consumes: `scrubEnv`, `createSandbox` from `@sentinel/sandbox`; `approvedCapsForManifest`, `isRootScript`, `commandFromArgv`, `EnforceError` from `./enforce.js`; `parseApprovals` from `./index.js`; `Manifest` from `./format.js`.
- Produces: a runnable bin at `dist/script-shell.js` named `sentinel-script-shell`.

- [ ] **Step 1: Write the failing test (the portable guard — the rest is the e2e test in Task 6)**

```ts
// packages/cli/test/script-shell.test.ts
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHELL = join(HERE, "..", "src", "script-shell.ts");
const runShell = (args: string[], env: NodeJS.ProcessEnv) => {
  try {
    const out = execFileSync("node", ["--import", "tsx", SHELL, ...args], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { code: 0, out };
  } catch (e: any) { return { code: e.status ?? 1, out: (e.stdout ?? "") + (e.stderr ?? "") }; }
};

describe("sentinel-script-shell guard", () => {
  test("refuses to run when SENTINEL_ENFORCE is not set (fail closed)", () => {
    const r = runShell(["-c", "echo SHOULD_NOT_RUN"], { ...process.env, SENTINEL_ENFORCE: "" });
    assert.notEqual(r.code, 0, "must exit non-zero without SENTINEL_ENFORCE");
    assert.ok(!r.out.includes("SHOULD_NOT_RUN"), "the command must not have executed");
  });
  test("refuses a malformed invocation (not -c <cmd>)", () => {
    const r = runShell(["oops"], { ...process.env, SENTINEL_ENFORCE: "1" });
    assert.notEqual(r.code, 0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/cli/test/script-shell.test.ts`
Expected: FAIL — script-shell.ts does not exist (spawn errors / non-zero, but assertions about message/absence won't hold as intended). Confirm it fails.

- [ ] **Step 3: Implement `packages/cli/src/script-shell.ts`**

```ts
#!/usr/bin/env node
import { homedir } from "node:os";
import { createSandbox, scrubEnv } from "@sentinel/sandbox";
import type { Capability } from "@sentinel/core";
import { approvedCapsForManifest, isRootScript, commandFromArgv, EnforceError } from "./enforce.js";
import { parseApprovals } from "./index.js";
import type { Manifest } from "./format.js";

/**
 * npm invokes this as the lifecycle script-shell: `sentinel-script-shell -c "<cmd>"`, with cwd set
 * to the package's directory and the full npm env present. It runs <cmd> under createSandbox() with
 * the package's APPROVED capabilities and a scrubbed env. Fail-closed: any inability to guarantee
 * containment exits non-zero, which aborts the npm install. NEVER runs <cmd> unsandboxed.
 */
async function main(): Promise<number> {
  if (process.env.SENTINEL_ENFORCE !== "1") {
    throw new EnforceError("sentinel-script-shell invoked without SENTINEL_ENFORCE=1 (refusing to act as a shell)");
  }
  const cmd = commandFromArgv(process.argv.slice(2));
  const cwd = process.cwd();
  const name = process.env.npm_package_name;
  const version = process.env.npm_package_version;

  let approved: Capability[];
  if (isRootScript(cwd, process.env.INIT_CWD)) {
    // The install root's own scripts: operator-supplied approvals only (default: none → strict).
    approved = parseApprovals((process.env.SENTINEL_APPROVE ?? "").split(/\s+/).filter(Boolean));
  } else {
    // A dependency's script: resolve approved capabilities from its proxy manifest (fail closed if unapproved).
    const proxy = process.env.SENTINEL_PROXY;
    if (!proxy || !name || !version) {
      throw new EnforceError(`cannot resolve approvals for dependency script (proxy/name/version missing)`);
    }
    const res = await fetch(`${proxy}/-/manifest/${encodeURIComponent(name)}/${encodeURIComponent(version)}`);
    if (!res.ok) throw new EnforceError(`manifest fetch failed for ${name}@${version}: ${res.status}`);
    approved = approvedCapsForManifest((await res.json()) as Manifest);
  }

  const env = scrubEnv(process.env, approved);
  const sandbox = createSandbox();   // throws (fail closed) on unsupported platform / missing bwrap
  const r = sandbox.run(cmd, { cwd, approved, homeDir: homedir(), env });
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  return r.exitCode;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    const tag = err instanceof EnforceError ? "enforcement" : "error";
    console.error(`\x1b[31msentinel-script-shell (${tag}): ${(err as Error).message}\x1b[0m`);
    process.exit(70);   // non-zero → npm aborts the install (fail closed)
  },
);
```

- [ ] **Step 4: Add the bin to `packages/cli/package.json`**

Change the `"bin"` field to expose both executables:

```json
  "bin": {
    "sentinel": "./dist/index.js",
    "sentinel-script-shell": "./dist/script-shell.js"
  },
```

- [ ] **Step 5: Guard against import side-effects**

`script-shell.ts` imports `parseApprovals` from `./index.js`. `index.ts` auto-runs `program.parseAsync()` guarded by `if (process.argv[1]?.endsWith("index.ts") || ...endsWith("index.js"))`. When script-shell is the entry, `process.argv[1]` ends with `script-shell.ts`/`.js`, so the guard is false and index.ts does NOT parse argv on import. Verify this guard still holds (do not weaken it). If importing `index.js` pulls in heavy CLI setup you want to avoid, move `parseApprovals` to `enforce.ts` and import it from there in both files instead — note which you did in your report.

- [ ] **Step 6: Run the guard test to verify it passes**

Run: `npx tsc --build --force packages/sandbox packages/cli && npx tsx --test packages/cli/test/script-shell.test.ts`
Expected: PASS — both invocations exit non-zero and the command never runs.

- [ ] **Step 7: Commit**

```bash
git add packages/cli/src/script-shell.ts packages/cli/package.json packages/cli/test/script-shell.test.ts
git commit -m "feat(cli): sentinel-script-shell wrapper — runs each lifecycle script under createSandbox() (fail-closed)"
```

---

### Task 4: `install --enforce` flag wiring (cli)

Add `--enforce`/`--approve` to the existing `install` command; when set, inject the script-shell + enforce env into the npm child.

**Files:**
- Modify: `packages/cli/src/index.ts` (the `install` command + a small env-builder helper)
- Test: `packages/cli/test/enforce-env.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces: `enforceNpmEnv(base: NodeJS.ProcessEnv, opts: { proxy: string; wrapperPath: string; approve: string[] }): NodeJS.ProcessEnv` — exported for testing; the `install` command uses it when `--enforce` is set.

- [ ] **Step 1: Write the failing test**

```ts
// packages/cli/test/enforce-env.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { enforceNpmEnv } from "../src/index.js";

describe("enforceNpmEnv", () => {
  test("injects script-shell + enforce env, preserving the base env", () => {
    const env = enforceNpmEnv({ PATH: "/usr/bin", HOME: "/h" }, {
      proxy: "http://localhost:4873", wrapperPath: "/abs/dist/script-shell.js", approve: ["network:api.example.com"],
    });
    assert.equal(env.npm_config_script_shell, "/abs/dist/script-shell.js");
    assert.equal(env.SENTINEL_ENFORCE, "1");
    assert.equal(env.SENTINEL_PROXY, "http://localhost:4873");
    assert.equal(env.SENTINEL_APPROVE, "network:api.example.com");
    assert.equal(env.PATH, "/usr/bin", "base env preserved");
    assert.equal(env.HOME, "/h");
  });
  test("empty approvals yield an empty SENTINEL_APPROVE", () => {
    assert.equal(enforceNpmEnv({}, { proxy: "p", wrapperPath: "w", approve: [] }).SENTINEL_APPROVE, "");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/cli/test/enforce-env.test.ts`
Expected: FAIL — `enforceNpmEnv` not exported.

- [ ] **Step 3: Add `enforceNpmEnv` and wire the flag in `packages/cli/src/index.ts`**

Add the exported helper near the other exported helpers (e.g. after `planApprovals`):

```ts
export function enforceNpmEnv(base: NodeJS.ProcessEnv, opts: { proxy: string; wrapperPath: string; approve: string[] }): NodeJS.ProcessEnv {
  return {
    ...base,
    npm_config_script_shell: opts.wrapperPath,
    SENTINEL_ENFORCE: "1",
    SENTINEL_PROXY: opts.proxy,
    SENTINEL_APPROVE: opts.approve.join(" "),
  };
}
```

Update the `install` command to accept `--enforce`/`--approve` and, when enforcing, spawn npm with the enforce env. Replace the current `install` command block (lines ~62-68) with:

```ts
program
  .command("install")
  .description("Run `npm install` with resolution routed through the Sentinel proxy (add --enforce to sandbox every lifecycle script).")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--enforce", "run every lifecycle script in the tree under the sandbox (fail-closed)", false)
  .option("--approve <cap...>", "capabilities to approve for the ROOT project's own scripts (kind:target)", [])
  .allowUnknownOption(true)
  .argument("[args...]", "arguments passed straight to npm install")
  .action((args: string[], opts: { proxy: string; enforce: boolean; approve: string[] }) => {
    if (!opts.enforce) return runNpm("install", args, opts.proxy);
    let sandbox;
    try { sandbox = createSandbox(); } catch (e) {
      console.error(`\x1b[31msentinel: --enforce unavailable: ${(e as Error).message}\x1b[0m`);
      process.exit(2);
    }
    void sandbox;   // constructed only to fail fast here; the wrapper builds its own per script
    const wrapperPath = fileURLToPath(new URL("./script-shell.js", import.meta.url));
    const env = enforceNpmEnv(process.env, { proxy: opts.proxy, wrapperPath, approve: opts.approve });
    runNpmWithEnv("install", args, opts.proxy, env);
  });
```

Add the `fileURLToPath`/`URL` import (`import { fileURLToPath } from "node:url";`) and a `runNpmWithEnv` variant next to `runNpm`/`runBin`:

```ts
function runNpmWithEnv(sub: string, args: string[], proxy: string, env: NodeJS.ProcessEnv): void {
  const finalArgs = [sub, "--registry", proxy, ...args];
  console.error(`\x1b[90m$ npm ${finalArgs.join(" ")}  (enforced)\x1b[0m`);
  const child = spawn("npm", finalArgs, { stdio: "inherit", shell: false, env });
  child.on("exit", (code) => process.exit(code ?? 0));
  child.on("error", (err) => fail(err, proxy));
}
```

(The `createSandbox()` fail-fast gives the operator a clean "unavailable on this platform" message *before* npm starts, in addition to the wrapper's per-script fail-closed.)

- [ ] **Step 4: Run test + build to verify**

Run: `npx tsc --build --force packages/cli && npx tsx --test packages/cli/test/enforce-env.test.ts`
Expected: PASS. Build clean (the `install` action compiles with the new options).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/index.ts packages/cli/test/enforce-env.test.ts
git commit -m "feat(cli): install --enforce wires script-shell + enforce env; fail-fast on unsupported platform"
```

---

### Task 5: benign enforce-probe fixture

A benign package that exercises the capstone: a declared capability (so the approval gate engages) plus a `postinstall` that attempts an **undeclared** sensitive read (so enforcement demonstrably denies it).

**Files:**
- Create: `fixtures/benign/enforce-probe/1.0.0/package/package.json`
- Create: `fixtures/benign/enforce-probe/1.0.0/package/index.js`
- Run: `npm run fixtures` (regenerates `fixtures/registry.json` + `.tarballs`)

**Interfaces:**
- Produces: fixture package `enforce-probe@1.0.0` served by `LocalFixtureUpstream`, with one detected capability (`network:198.51.100.7`) and a `postinstall` that reads `~/.ssh/id_rsa` via a **dynamically built path** (no `.ssh/id_rsa` literal → not detected as a covering `filesystem` capability → denied under the sandbox even when the package is approved).

- [ ] **Step 1: Create `fixtures/benign/enforce-probe/1.0.0/package/package.json`**

```json
{
  "name": "enforce-probe",
  "version": "1.0.0",
  "description": "SYNTHETIC BENIGN FIXTURE — postinstall probes sandbox denial; writes only locally, never exfiltrates.",
  "scripts": {
    "postinstall": "node -e \"const fs=require('fs'),os=require('os'),p=require('path');const key=p.join(os.homedir(),'.'+'ssh','id_'+'rsa');try{fs.writeFileSync('leaked.txt',fs.readFileSync(key,'utf8'))}catch(e){};fs.writeFileSync('ran.txt','ran')\""
  }
}
```

Note: the postinstall builds `~/.ssh/id_rsa` from concatenated fragments so the literal `.ssh/id_rsa` never appears (the detector's `filesystem:.ssh/id_rsa` matcher does not fire); it writes `leaked.txt` (what it managed to read) and `ran.txt` (proof it ran) into its own package dir.

- [ ] **Step 2: Create `fixtures/benign/enforce-probe/1.0.0/package/index.js`**

```js
// SYNTHETIC BENIGN FIXTURE. A declared capability so the approval gate engages; never actually connects.
// RFC 5737 documentation IP.
const ENDPOINT = "http://198.51.100.7/telemetry";
module.exports = { ENDPOINT };
```

- [ ] **Step 3: Regenerate fixtures and confirm the capability shape**

Run: `npm run fixtures`
Then confirm the detected capability set is `network:198.51.100.7` only (NO `filesystem:.ssh/...`):

Run: `npx tsx -e "import('@sentinel/core').then(async c=>{const {readFileSync}=await import('node:fs');const reg=JSON.parse(readFileSync('fixtures/registry.json','utf8'));console.log(JSON.stringify(Object.keys(reg)))})"`
Expected: the registry lists `enforce-probe`. (Capability detail is asserted in Task 6; here just confirm the fixture packs.)

- [ ] **Step 4: Commit**

```bash
git add fixtures/benign/enforce-probe fixtures/registry.json fixtures/.tarballs 2>/dev/null || git add fixtures/benign/enforce-probe fixtures/registry.json
git commit -m "fixtures: benign enforce-probe (declared network cap + undeclared ssh-read postinstall)"
```

(If `.tarballs` is gitignored, only `fixtures/benign/enforce-probe` + `fixtures/registry.json` are tracked — that matches the existing fixture convention; check `git status` and add what the repo tracks.)

---

### Task 6: capstone DoD integration test — enforced install blocks an undeclared action

The test proving Phases 2–6 compose: a real `npm install` through the proxy, with `--enforce`, denies the fixture's undeclared ssh read while the install otherwise succeeds; the same install without enforcement does not.

**Files:**
- Create: `packages/proxy/test/enforce-e2e.test.ts`

**Interfaces:**
- Consumes: `createServer`, `AuditStore`, `ApprovalStore`, `LocalFixtureUpstream` (proxy); the built/tsx `sentinel-script-shell` at `packages/cli/src/script-shell.ts`; real `npm`.

- [ ] **Step 1: Write the integration test**

```ts
// packages/proxy/test/enforce-e2e.test.ts
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { spawnSync, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { DEFAULT_POLICY } from "@sentinel/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "..", "..", "fixtures");
// Use the BUILT wrapper (plain node — no tsx). The shim runs in a temp project cwd where a bare
// `tsx` specifier would NOT resolve, so pointing at compiled dist/ is what makes the shim work.
const CLI_DIST_SHELL = join(HERE, "..", "..", "cli", "dist", "script-shell.js");

function ensureFixtures() {
  if (!existsSync(join(FIXTURES, "registry.json")))
    execFileSync("npx", ["tsx", join(HERE, "..", "..", "..", "scripts", "make-fixtures.ts")], { stdio: "ignore" });
}
function ensureBuilt() {
  // The e2e test needs the compiled wrapper. `npm test` is preceded by `npm run build`, but build if missing.
  if (!existsSync(CLI_DIST_SHELL))
    execFileSync("npx", ["tsc", "--build", "--force", join(HERE, "..", "..", "cli")], { stdio: "ignore" });
}

// Sandbox availability: darwin always; linux only when bwrap can create namespaces.
const sandboxWorks = (() => {
  if (process.platform === "darwin") return true;
  if (process.platform !== "linux") return false;
  const r = spawnSync("bwrap", ["--ro-bind", "/", "/", "--dev", "/dev", "true"], { encoding: "utf8" });
  return !r.error && r.status === 0;
})();

describe("install --enforce (e2e) blocks an undeclared action; install otherwise succeeds", {
  skip: sandboxWorks ? false : "requires a working sandbox (Seatbelt on darwin / bwrap on Linux)",
}, () => {
  let server: Server; let base: string;

  before(async () => {
    ensureFixtures();
    ensureBuilt();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(), approvals: new ApprovalStore(),
      enterprisePolicy: DEFAULT_POLICY, policy: "block",
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  // Build one enforced install into `home`, returning the fixture's install dir. Approves the fixture first.
  async function enforcedInstall(home: string, enforce: boolean): Promise<string> {
    // approve enforce-probe via the real gate (fetch manifest → POST approval)
    const m = await (await fetch(`${base}/-/manifest/enforce-probe/1.0.0`)).json() as any;
    await fetch(`${base}/-/approvals`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify([{ name: "enforce-probe", version: "1.0.0", integrity: m.meta.integrity, decision: "approved", actor: { type: "test", id: "e2e" } }]),
    });
    const proj = realpathSync(mkdtempSync(join(home, "proj-")));
    writeFileSync(join(proj, "package.json"), JSON.stringify({ name: "consumer", version: "1.0.0" }));
    // executable script-shell shim → runs our wrapper under tsx (no build needed)
    const shim = join(proj, "shim.sh");
    writeFileSync(shim, `#!/bin/sh\nexec node "${CLI_DIST_SHELL}" "$@"\n`);
    chmodSync(shim, 0o755);
    const env: NodeJS.ProcessEnv = {
      ...process.env, HOME: home, npm_config_cache: join(home, ".npmcache"), npm_config_audit: "false", npm_config_fund: "false",
    };
    if (enforce) Object.assign(env, { npm_config_script_shell: shim, SENTINEL_ENFORCE: "1", SENTINEL_PROXY: base });
    const r = spawnSync("npm", ["install", "enforce-probe@1.0.0", "--registry", base, "--no-audit", "--no-fund"], {
      cwd: proj, env, encoding: "utf8",
    });
    assert.equal(r.status, 0, `npm install must succeed. stderr:\n${r.stderr}`);
    return join(proj, "node_modules", "enforce-probe");
  }

  test("ENFORCED: the undeclared ssh read is blocked, but the package installs and its script runs", async () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "enf-home-")));
    mkdirSync(join(home, ".ssh"), { recursive: true });
    writeFileSync(join(home, ".ssh", "id_rsa"), "TOPSECRET-ENFORCE-KEY");
    const dir = await enforcedInstall(home, true);
    assert.ok(existsSync(join(dir, "ran.txt")), "positive control: the postinstall must have run under the sandbox");
    const leaked = existsSync(join(dir, "leaked.txt")) ? readFileSync(join(dir, "leaked.txt"), "utf8") : "";
    assert.ok(!leaked.includes("TOPSECRET-ENFORCE-KEY"), "the undeclared ssh read must have been DENIED");
    assert.equal(readFileSync(join(home, ".ssh", "id_rsa"), "utf8"), "TOPSECRET-ENFORCE-KEY", "real secret untouched");
  });

  test("CONTROL: without --enforce, the same read is NOT blocked (proves --enforce is the cause)", async () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "enf-home2-")));
    mkdirSync(join(home, ".ssh"), { recursive: true });
    writeFileSync(join(home, ".ssh", "id_rsa"), "TOPSECRET-ENFORCE-KEY");
    const dir = await enforcedInstall(home, false);
    const leaked = existsSync(join(dir, "leaked.txt")) ? readFileSync(join(dir, "leaked.txt"), "utf8") : "";
    assert.ok(leaked.includes("TOPSECRET-ENFORCE-KEY"), "unsandboxed, the postinstall reads the secret (control)");
  });
});
```

- [ ] **Step 2: Run on darwin to confirm enforcement blocks and control leaks**

Run: `npx tsc --build --force packages/sandbox packages/cli packages/proxy && npx tsx --test packages/proxy/test/enforce-e2e.test.ts`
Expected (darwin): 2 tests pass — enforced read blocked (`ran.txt` present, `leaked.txt` empty), control read leaks. If npm reaches the network or the shim isn't found, debug env/paths before proceeding.

- [ ] **Step 3: (controller/CI) Linux validation**

The controller re-runs this on Linux (Colima/CI) where the backend is bwrap; the describe skips if bwrap can't create namespaces. No action for the implementer beyond confirming the darwin run.

- [ ] **Step 4: Commit**

```bash
git add packages/proxy/test/enforce-e2e.test.ts
git commit -m "test(e2e): install --enforce blocks an undeclared action while the install succeeds (Phases 2–6 compose)"
```

---

### Task 7: docs — ADR-0019 + ARCHITECTURE + CLAUDE count

**Files:**
- Create: `docs/adr/0019-enforced-install-script-shell.md`
- Modify: `docs/adr/README.md` (index it)
- Modify: `ARCHITECTURE.md` (§3.6 or a new §3.7 on the enforced-install path; §5/§6 command list)
- Modify: `CLAUDE.md` (Phase summary + `npm test` count line)

- [ ] **Step 1: Write ADR-0019**

```markdown
# ADR-0019: Enforced install via script-shell interposition

**Status:** Accepted (Phase 6)
**Date:** 2026-07-01

## Context
`sentinel install` routed resolution through the proxy (audited + approval-gated downloads) but
npm still ran every lifecycle script UNSANDBOXED. Phases 3–5 built cross-platform containment
(`createSandbox()` + `scrubEnv`) but only reachable via `sentinel run-scripts <dir>` on one
unpacked package. ADR-0016/0017 deferred the full `npm install --enforce` tree orchestration and
flagged (0017) that the `npm_` env allowlist prefix must narrow / credential-screen before it.

## Decision
`sentinel install --enforce` runs a NORMAL `npm install --registry <proxy>` with
`npm_config_script_shell` set to a shipped `sentinel-script-shell` wrapper. npm invokes it as
`<wrapper> -c "<cmd>"` for every lifecycle script, in dependency order, with the full npm env,
cwd, and `.bin` PATH already constructed. The wrapper scrubs the env, resolves the package's
approved capabilities, and runs `<cmd>` under `createSandbox()`.

- **Why interposition, not `--ignore-scripts` + re-enumeration.** A probe confirmed npm calls a
  custom script-shell as `<shell> -c <cmd>` with cwd = the package dir and the full npm env
  (`npm_package_*`, `npm_lifecycle_*`, `INIT_CWD`, `.bin` PATH). Interposition reuses npm's
  ordering, env construction, workspaces, and tree walk; re-enumeration would re-implement all of
  it, brittly. Rejected.
- **Approval resolution.** A dependency's approved capabilities come from its proxy manifest
  (`GET /-/manifest/:name/:version`): `approved`/`inherited` ⇒ its detected capabilities,
  `n-a` ⇒ none, `required`/`denied` ⇒ fail closed. The install root's own scripts use
  operator-supplied `--approve` (default: none → strict).
- **Env credential-screen (the ADR-0017 pre-condition, now met).** `scrubEnv`'s blanket `npm_`
  prefix is narrowed to `npm_package_`/`npm_lifecycle_`/`npm_node_`/`npm_config_` (+ exact
  `npm_command`/`npm_execpath`), and ANY var matching `/_auth|authtoken|_password|passwd|token|secret|credential/i`
  is dropped regardless of allowlist match. A probe showed current npm exposes no credential
  `npm_config_*` (scoped `.npmrc` tokens do not leak), so the screen preserves working installs
  while failing closed on any auth-shaped config on any npm version.

## Fail-closed
`--enforce` NEVER runs a lifecycle script unsandboxed. The wrapper exits non-zero (npm aborts)
when: `SENTINEL_ENFORCE` is unset, the invocation isn't `-c <cmd>`, a dependency is unapproved,
the manifest is unreachable, or `createSandbox()` rejects the platform (Windows / missing bwrap /
refused userns). `install --enforce` also fail-fasts with a clean message before spawning npm if
the platform has no sandbox.

## Consequences
- Every lifecycle script in the tree is contained: the enforcement value is precisely catching
  UNDECLARED capabilities static analysis missed (an approved package's script attempting an
  action outside its detected/approved caps is still denied by the kernel). The DoD test proves
  this end-to-end (undeclared ssh read denied; install otherwise succeeds; unenforced control
  leaks).
- Native builds needing network (cold `node-gyp` header cache) require a `network` approval —
  the correct posture, documented.
- Windows: `--enforce` fails closed (no sandbox backend).

## Rejected
- `--ignore-scripts` + re-enumerate/re-order the tree and replicate npm's env — re-implements
  npm; brittle. (See Decision.)
- Blanket-drop all `npm_config_*` — breaks legitimate config (registry, cache, node_gyp); the
  credential-screen is the targeted fail-closed choice ADR-0017 offered.

Extends ADR-0011/0013 (approval gate), ADR-0016/0017/0018 (sandbox); supersedes nothing.
```

- [ ] **Step 2: Index the ADR in `docs/adr/README.md`** (follow the existing format/section for Phase 3–6).

- [ ] **Step 3: Update ARCHITECTURE.md**

Add a subsection (after §3.6) describing the enforced-install path:

```markdown
### 3.7 Enforced install (Phase 6, ADR-0019)

`sentinel install --enforce` runs a normal `npm install --registry <proxy>` with
`npm_config_script_shell` set to the shipped `sentinel-script-shell` wrapper. npm invokes it as
`<wrapper> -c "<cmd>"` for every lifecycle script in the tree — in dependency order, with the
full npm env, cwd, and `.bin` PATH — and the wrapper runs each command under `createSandbox()`
with the package's approved capabilities and a credential-screened env. Approvals come from the
proxy manifest for dependencies (`required`/`denied` ⇒ fail closed) and from operator `--approve`
for the root project. This is the difference from plain `sentinel install`, which redirects the
registry but runs scripts unsandboxed. `scrubEnv` now narrows the `npm_` allowlist to safe
sub-groups and drops any credential-shaped var (ADR-0017's pre-condition, met). Fail-closed:
sandbox unavailable / unapproved dependency ⇒ the wrapper exits non-zero and npm aborts.
```

Also add `install --enforce` to the CLI command list in §6 if one is enumerated there.

- [ ] **Step 4: Update CLAUDE.md**

Add a Phase 6 line to the phase summary (`install --enforce` sandboxes the whole tree via
script-shell interposition; ADR-0019). Then run the suite and update the count line honestly:

Run: `npm run build && npm test 2>&1 | tail -8`
Expected (darwin): the new `enforce-e2e` tests run (Seatbelt) and pass; `enforce.test`,
`script-shell.test`, `enforce-env.test`, and the env-scrub tests pass. Record the actual
`# tests` / `# pass` / `# skip` numbers and update the CLAUDE.md `npm test` line to match, noting
that `enforce-e2e` is platform-gated like the other enforcement effect-tests.

- [ ] **Step 5: Verify build + full suite, then commit**

Run: `npm run build && npm test`
Expected: green (enforcement effect-tests run on darwin; skip where no sandbox).

```bash
git add docs/adr/0019-enforced-install-script-shell.md docs/adr/README.md ARCHITECTURE.md CLAUDE.md
git commit -m "docs(phase6): ADR-0019 enforced install; ARCHITECTURE §3.7; CLAUDE phase + count"
```

---

## Self-Review

**Spec coverage:**
- §1 success criteria: 1 (denied action blocked) + 2 (control) → Task 6; 3 (credential env absent, benign present) → Task 1 tests (+ Task 6 exercises env end-to-end); 4 (fail closed) → Task 3 guard test + wrapper fail-closed paths + Task 4 fail-fast; 5 (determinism/offline untouched) → no scoring/proxy-audit/policy changes; env-scrub stays pure (Task 1).
- §3 architecture (interposition) → Tasks 3–4. §4.1 flag → Task 4; §4.2 wrapper → Task 3; §4.2 approval resolution → Task 2; §4.3 credential-screen → Task 1; §4.4 root scripts → Task 2 `isRootScript` + Task 3 `SENTINEL_APPROVE`. §5 fail-closed → Tasks 3–4. §6 native/network caveat → ADR/ARCHITECTURE (Task 7). §7 DoD test → Task 6. §8/§9 → Task 7 docs + count.

**Placeholder scan:** No "TBD"/"add error handling"/"similar to". The only emergent value — exact `npm test` totals — is gathered by a concrete command in Task 7 Step 4 and written from observed output.

**Type consistency:** `Manifest` (from `./format.js`) fields (`meta.{name,version,integrity}`, `verdict`, `approvalState`, `capabilities`, `approvalRequired`, `inheritedFrom`) used consistently in Tasks 2/3/6. `approvedCapsForManifest`/`isRootScript`/`commandFromArgv`/`EnforceError` (Task 2) consumed with matching signatures in Task 3. `enforceNpmEnv(base, {proxy, wrapperPath, approve})` (Task 4) — env keys (`npm_config_script_shell`, `SENTINEL_ENFORCE`, `SENTINEL_PROXY`, `SENTINEL_APPROVE`) match what the wrapper (Task 3) reads. `scrubEnv`/`createSandbox` (sandbox pkg) used with their existing signatures. Fixture capability shape (`network:198.51.100.7`, no covering `filesystem`) matches the Task 6 assertion that the ssh read is denied even when approved.
