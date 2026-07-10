# Phase 17 — CI-Native GitHub Action Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a packaged GitHub Action (`uses: your-org/sentinel@v1`) that audits a PR's dependency tree, uploads a CycloneDX SBOM, posts an idempotent verdict comment, and fails the check on a gated tree.

**Architecture:** A new `packages/action` workspace (`@sentinel/action`, bin `sentinel-ci`) whose `runCi()` self-boots the proxy in-process (injectable upstream), runs the existing `/-/audit-tree` flow, and emits GitHub-native outputs; a thin composite `action.yml` maps inputs and posts the comment. The scoring engine is untouched.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; reuses `@sentinel/proxy` (`createServer`, stores, `NpmUpstream`/`LocalFixtureUpstream`) + `@sentinel/core` (`parseAnyLockfile`, `toCycloneDX`, `loadPolicy`, `DEFAULT_POLICY`); `node:test` via `tsx`. No new runtime dependencies.

## Global Constraints

- **New workspace `@sentinel/action`** — bin `sentinel-ci`; deps `@sentinel/core@0.1.0` + `@sentinel/proxy@0.1.0`; wired into root `package.json` `workspaces` and root `tsconfig.json` `references`. Mirror `packages/mcp`'s package.json + tsconfig shape.
- **Self-boot, injected upstream.** `runCi` constructs `createServer({ upstream, store: new AuditStore(), approvals: new ApprovalStore(), enterprisePolicy, privateStore: new PrivatePackageStore(), violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore() })` and `listen(0)`; `upstream` is a parameter (default `NpmUpstream` in the bin; tests pass `LocalFixtureUpstream`). Always `close()` the server.
- **Hermetic tests.** Never hit live npm — inject `LocalFixtureUpstream(fixturesDir)`. GitHub env is a passed object, pointed at temp files. Async `fetch` against the in-process server; never `spawnSync`.
- **Determinism.** `renderPrComment` and `toCycloneDX` take an injected `now` string. No `Date.now()` in the report/SBOM path.
- **Fail-on semantics (verbatim):** `none` ⇒ exit 0 always (observe); `warn` ⇒ exit 2 when aggregate verdict is `warn`/`block` **or** the tree is `gated`; `block` (default) ⇒ exit 2 when aggregate verdict is `block` or the tree is `gated`. The action sends `failOnError: failOn !== "none"` to `/-/audit-tree`.
- **No package code executes** — the proxy fetches + scores tarballs as text (unchanged). The malicious fixture must still gate the tree (verdict `block`).
- **GitHub-native but local-runnable** — absent `GITHUB_OUTPUT`/`GITHUB_STEP_SUMMARY` ⇒ print the report to stdout and still return the correct exit code.
- ESM only, NodeNext: internal imports use `.js` specifiers; cross-package imports use the package name (`@sentinel/core`, `@sentinel/proxy`).
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/action`.
- Run all commands from repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.

---

### Task 1: `@sentinel/action` workspace scaffold + `renderPrComment`

**Files:**
- Create: `packages/action/package.json`, `packages/action/tsconfig.json`
- Modify: root `package.json` (`workspaces`), root `tsconfig.json` (`references`)
- Create: `packages/action/src/report.ts`
- Test: `packages/action/test/report.test.ts`

**Interfaces:**
- Consumes: `TreeAuditResult`, `TreeAggregate`, `TreePackageRow` (from `@sentinel/core` or `@sentinel/proxy` — whichever exports them; they live in `@sentinel/core`'s tree module and are re-exported).
- Produces (used by Tasks 2–3): `renderPrComment(result: TreeAuditResult, opts: { now: string }): string`; `export const REPORT_MARKER = "<!-- sentinel-report -->"`.

- [ ] **Step 1: Scaffold the workspace.** Create `packages/action/package.json` (mirror `packages/mcp/package.json`):

```json
{
  "name": "@sentinel/action",
  "version": "0.1.0",
  "description": "Sentinel CI runner: self-booting dependency-tree audit for GitHub Actions (sentinel-ci).",
  "license": "Apache-2.0",
  "type": "module",
  "main": "./dist/index.js",
  "bin": { "sentinel-ci": "./dist/index.js" },
  "dependencies": {
    "@sentinel/core": "0.1.0",
    "@sentinel/proxy": "0.1.0"
  },
  "devDependencies": { "@types/node": "^24.13.2" }
}
```

Create `packages/action/tsconfig.json` (mirror `packages/mcp/tsconfig.json`; ensure `references` includes core AND proxy — read `packages/mcp/tsconfig.json` first and copy its shape, adding a `{ "path": "../proxy" }` reference):

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "outDir": "./dist", "rootDir": "./src", "composite": true },
  "references": [{ "path": "../core" }, { "path": "../proxy" }],
  "include": ["src/**/*"]
}
```

(If `packages/mcp/tsconfig.json` differs from this shape — e.g. a different `extends` path or extra options — match ITS shape exactly and just add the proxy reference.)

Add `"packages/action"` to root `package.json`'s `workspaces` array, and `{ "path": "packages/action" }` to root `tsconfig.json`'s `references` array.

Run `npm install` so the workspace symlinks resolve:

```bash
npm install
```

- [ ] **Step 2: Write the failing test** (`packages/action/test/report.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { renderPrComment, REPORT_MARKER } from "../src/report.js";
import type { TreeAuditResult } from "@sentinel/core";

const result: TreeAuditResult = {
  aggregate: {
    verdict: "block", gated: true,
    counts: { allow: 1, warn: 1, block: 1, error: 0 },
    provenance: { verified: 1, invalid: 0, absent: 2, unknown: 0 },
    integrityMismatch: 0,
  },
  packages: [
    { name: "evil-pkg", version: "2.0.0", status: "block", score: 10, topFinding: "changed hands: possible takeover", error: null, provenance: "absent", integrityMismatch: false },
    { name: "warny", version: "1.2.0", status: "warn", score: 60, topFinding: "network egress", error: null, provenance: "absent", integrityMismatch: false },
    { name: "fine", version: "1.0.0", status: "allow", score: 100, topFinding: null, error: null, provenance: "verified", integrityMismatch: false },
  ],
};

describe("renderPrComment", () => {
  const md = renderPrComment(result, { now: "2026-07-08T00:00:00Z" });
  test("begins with the hidden idempotency marker", () => {
    assert.ok(md.startsWith(REPORT_MARKER));
  });
  test("shows the aggregate verdict and counts", () => {
    assert.match(md, /BLOCK/);
    assert.match(md, /1 allow/);
    assert.match(md, /1 block/);
  });
  test("lists the worst offenders (block before warn) with finding text", () => {
    const iEvil = md.indexOf("evil-pkg");
    const iWarn = md.indexOf("warny");
    assert.ok(iEvil > 0 && iWarn > 0 && iEvil < iWarn, "block row should precede warn row");
    assert.match(md, /changed hands/);
  });
  test("does not list allow rows in the offenders table", () => {
    // 'fine' (allow) should not appear as an offender row
    assert.equal(md.includes("| fine@1.0.0"), false);
  });
});
```

- [ ] **Step 3: Run to verify it fails**

```bash
npm run build
npx tsx --test packages/action/test/report.test.ts
```

Expected: FAIL — cannot find `../src/report.js`. (If the BUILD fails, the workspace wiring is wrong — fix tsconfig references / workspaces before proceeding.)

- [ ] **Step 4: Implement `packages/action/src/report.ts`**

```ts
import type { TreeAuditResult, TreePackageRow } from "@sentinel/core";

export const REPORT_MARKER = "<!-- sentinel-report -->";

const RANK: Record<string, number> = { block: 0, warn: 1, allow: 2, error: 3 };

/** Render the PR/CI Markdown report for a tree audit. Pure; deterministic given `now`.
 *  Starts with a hidden marker so the Action can find-and-update its comment idempotently. */
export function renderPrComment(result: TreeAuditResult, opts: { now: string }): string {
  const a = result.aggregate;
  const badge = a.verdict.toUpperCase();
  const offenders = result.packages
    .filter((p) => p.status === "block" || p.status === "warn" || p.status === "error")
    .sort((x, y) => (RANK[x.status]! - RANK[y.status]!) || (x.name < y.name ? -1 : 1))
    .slice(0, 15);

  const L: string[] = [];
  L.push(REPORT_MARKER);
  L.push(`## Sentinel dependency audit — **${badge}**${a.gated ? " · ✗ gated" : " · ✓ ok"}`);
  L.push("");
  L.push(`${a.counts.allow} allow · ${a.counts.warn} warn · ${a.counts.block} block · ${a.counts.error} error`);
  const pv = a.provenance;
  L.push(`_provenance: ${pv.verified} verified · ${pv.invalid} invalid · ${pv.absent} absent · ${pv.unknown} unknown_`);
  L.push("");
  if (offenders.length) {
    L.push("| package | verdict | score | finding |");
    L.push("| --- | --- | --- | --- |");
    for (const p of offenders) {
      const finding = p.error ?? p.topFinding ?? "";
      L.push(`| ${p.name}@${p.version} | ${p.status} | ${scoreCell(p)} | ${escapePipe(finding)} |`);
    }
    L.push("");
  } else {
    L.push("_No flagged packages._");
    L.push("");
  }
  L.push(`<sub>Sentinel · ${result.packages.length} packages audited · ${opts.now} · SBOM uploaded as a build artifact</sub>`);
  return L.join("\n");
}

function scoreCell(p: TreePackageRow): string {
  return p.score === null ? "—" : `${p.score}/100`;
}
function escapePipe(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ");
}
```

- [ ] **Step 5: Run the test + build**

```bash
npm run build
npx tsx --test packages/action/test/report.test.ts
```

Expected: PASS (4/4). Build clean. Then a quick full `npm test` to confirm the new workspace didn't break the build graph.

- [ ] **Step 6: Commit**

```bash
git add packages/action/package.json packages/action/tsconfig.json packages/action/src/report.ts packages/action/test/report.test.ts package.json tsconfig.json package-lock.json
git commit -m "feat(phase17): @sentinel/action workspace scaffold + renderPrComment"
```

---

### Task 2: `runCi` orchestrator

**Files:**
- Create: `packages/action/src/run.ts`
- Test: `packages/action/test/run-e2e.test.ts`

**Interfaces:**
- Consumes: `createServer`, `AuditStore`, `ApprovalStore`, `PrivatePackageStore`, `ViolationStore`, `ApprovalRequestStore`, `LocalFixtureUpstream`, `type Upstream` (all from `@sentinel/proxy`); `parseAnyLockfile`, `toCycloneDX`, `DEFAULT_POLICY`, `type EnterprisePolicy`, `type TreeAuditResult` (from `@sentinel/core`); `renderPrComment`, `REPORT_MARKER` (Task 1).
- Produces (used by Task 3): `runCi(opts: RunCiOptions): Promise<CiResult>` where
  `interface RunCiOptions { upstream: Upstream; cwd: string; lockfile?: string; policy?: EnterprisePolicy; sbomPath: string; failOn: "block" | "warn" | "none"; omitDev: boolean; now: string; env: NodeJS.ProcessEnv }`
  and `interface CiResult { exitCode: number; result: TreeAuditResult; sbomPath: string; markdown: string }`.

- [ ] **Step 1: Write the failing e2e** (`packages/action/test/run-e2e.test.ts`)

First find the exact fixture names/versions to reference:

```bash
node -e "const r=require('./fixtures/registry.json');for(const [n,p] of Object.entries(r.packages)){for(const v of Object.keys(p.versions)) console.log(n+'@'+v)}" | grep -Ei "leftpad|color-stream|net-fetch"
```

Use a benign one (e.g. `leftpad-lite`) and the malicious `color-stream` (confirm its exact version from the output). Then:

```ts
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { describe, test } from "node:test";
import { LocalFixtureUpstream } from "@sentinel/proxy";
import { runCi } from "../src/run.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO, "scripts", "make-fixtures.ts")], { cwd: REPO, stdio: "ignore" });
}

// A v3 package-lock.json referencing a benign + the malicious fixture.
// CONFIRM the exact malicious name@version from the grep above and substitute here.
function writeLockfile(dir: string): void {
  const lock = {
    name: "demo", lockfileVersion: 3,
    packages: {
      "": { name: "demo" },
      "node_modules/leftpad-lite": { version: "1.0.0" },
      "node_modules/color-stream": { version: "1.4.1" },
    },
  };
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify(lock, null, 2));
}

function fakeEnv(dir: string): NodeJS.ProcessEnv {
  return { GITHUB_OUTPUT: join(dir, "out.txt"), GITHUB_STEP_SUMMARY: join(dir, "summary.md") };
}

describe("runCi (e2e, hermetic)", () => {
  test("fail-on=block gates a tree containing the malicious fixture (exit 2), writes SBOM + outputs + summary", async () => {
    ensureFixtures();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-ci-"));
    writeLockfile(dir);
    const env = fakeEnv(dir);
    const r = await runCi({
      upstream: new LocalFixtureUpstream(FIXTURES), cwd: dir, sbomPath: join(dir, "sbom.json"),
      failOn: "block", omitDev: false, now: "2026-07-08T00:00:00Z", env,
    });
    assert.equal(r.exitCode, 2);
    assert.equal(r.result.aggregate.counts.block >= 1, true);
    // SBOM written + valid CycloneDX
    const sbom = JSON.parse(readFileSync(join(dir, "sbom.json"), "utf8"));
    assert.equal(sbom.bomFormat, "CycloneDX");
    // GITHUB_OUTPUT carries verdict + sbom-path
    const out = readFileSync(env.GITHUB_OUTPUT!, "utf8");
    assert.match(out, /verdict=block/);
    assert.match(out, /gated=true/);
    assert.match(out, /sbom-path=/);
    // step summary written with the report
    assert.match(readFileSync(env.GITHUB_STEP_SUMMARY!, "utf8"), /Sentinel dependency audit/);
  });

  test("fail-on=none is observe-only (exit 0) but still audits + writes the SBOM", async () => {
    ensureFixtures();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-ci-"));
    writeLockfile(dir);
    const r = await runCi({
      upstream: new LocalFixtureUpstream(FIXTURES), cwd: dir, sbomPath: join(dir, "sbom.json"),
      failOn: "none", omitDev: false, now: "2026-07-08T00:00:00Z", env: {},
    });
    assert.equal(r.exitCode, 0);
    assert.equal(existsSync(join(dir, "sbom.json")), true);
  });

  test("auto-detects the lockfile when none is given", async () => {
    ensureFixtures();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-ci-"));
    writeLockfile(dir);
    const r = await runCi({
      upstream: new LocalFixtureUpstream(FIXTURES), cwd: dir, sbomPath: join(dir, "sbom.json"),
      failOn: "none", omitDev: false, now: "2026-07-08T00:00:00Z", env: {},
    });
    assert.equal(r.result.packages.length >= 2, true);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/action/test/run-e2e.test.ts
```

Expected: FAIL — `../src/run.js` not found.

- [ ] **Step 3: Implement `packages/action/src/run.ts`**

```ts
import { existsSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import {
  createServer, AuditStore, ApprovalStore, PrivatePackageStore, ViolationStore, ApprovalRequestStore,
  type Upstream,
} from "@sentinel/proxy";
import { parseAnyLockfile, toCycloneDX, DEFAULT_POLICY, type EnterprisePolicy, type TreeAuditResult } from "@sentinel/core";
import { renderPrComment } from "./report.js";

export interface RunCiOptions {
  upstream: Upstream;
  cwd: string;
  lockfile?: string;
  policy?: EnterprisePolicy;
  sbomPath: string;
  failOn: "block" | "warn" | "none";
  omitDev: boolean;
  now: string;
  env: NodeJS.ProcessEnv;
}
export interface CiResult {
  exitCode: number;
  result: TreeAuditResult;
  sbomPath: string;
  markdown: string;
}

const LOCKFILES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"];

function detectLockfile(cwd: string, explicit?: string): string {
  if (explicit) {
    const p = explicit.startsWith("/") ? explicit : join(cwd, explicit);
    if (!existsSync(p)) throw new Error(`lockfile not found: ${p}`);
    return p;
  }
  for (const name of LOCKFILES) {
    const p = join(cwd, name);
    if (existsSync(p)) return p;
  }
  throw new Error(`no lockfile found in ${cwd} (looked for ${LOCKFILES.join(", ")})`);
}

const VERDICT_RANK: Record<string, number> = { allow: 0, warn: 1, block: 2 };

function exitFor(agg: TreeAuditResult["aggregate"], failOn: RunCiOptions["failOn"]): number {
  if (failOn === "none") return 0;
  const need = failOn === "warn" ? 1 : 2;
  if (VERDICT_RANK[agg.verdict]! >= need) return 2;
  if (agg.gated) return 2; // server-side gate (treeGate / failOnError on error rows)
  return 0;
}

/** Run a self-contained CI tree audit: self-boot the proxy, audit the lockfile tree, write the
 *  SBOM + GitHub-native outputs, and compute the fail-on exit code. Injectable upstream + env. */
export async function runCi(opts: RunCiOptions): Promise<CiResult> {
  const lockPath = detectLockfile(opts.cwd, opts.lockfile);
  const coords = parseAnyLockfile(readFileSync(lockPath, "utf8"), { filename: lockPath, omitDev: opts.omitDev });

  const app = createServer({
    upstream: opts.upstream,
    store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: opts.policy ?? DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(),
  });
  const server: Server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
  try {
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const res = await fetch(`${base}/-/audit-tree`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ packages: coords, failOnError: opts.failOn !== "none" }),
    });
    if (!res.ok) throw new Error(`audit-tree failed: ${res.status}`);
    const result = (await res.json()) as TreeAuditResult;

    writeFileSync(opts.sbomPath, JSON.stringify(toCycloneDX(result, { now: opts.now }), null, 2));
    const markdown = renderPrComment(result, { now: opts.now });
    const exitCode = exitFor(result.aggregate, opts.failOn);

    // GitHub-native surfacing (all defensive — absent env ⇒ stdout).
    if (opts.env.GITHUB_STEP_SUMMARY) writeFileSync(opts.env.GITHUB_STEP_SUMMARY, markdown);
    else console.log(markdown);
    if (opts.env.GITHUB_OUTPUT) {
      const c = result.aggregate.counts;
      appendFileSync(opts.env.GITHUB_OUTPUT,
        `verdict=${result.aggregate.verdict}\ngated=${result.aggregate.gated}\n` +
        `blocked=${c.block}\nwarned=${c.warn}\nerrored=${c.error}\nsbom-path=${opts.sbomPath}\n`);
    }
    if (opts.env.SENTINEL_COMMENT_BODY) writeFileSync(opts.env.SENTINEL_COMMENT_BODY, markdown);
    for (const p of result.packages) {
      if (p.status === "block") console.log(`::error::${p.name}@${p.version} — ${p.topFinding ?? p.error ?? "blocked"}`);
      else if (p.status === "warn") console.log(`::warning::${p.name}@${p.version} — ${p.topFinding ?? "warn"}`);
    }

    return { exitCode, result, sbomPath: opts.sbomPath, markdown };
  } finally {
    server.close();
  }
}
```

- [ ] **Step 4: Build + run the e2e**

```bash
npm run build
npx tsx --test packages/action/test/run-e2e.test.ts
```

Expected: PASS (3/3). If `color-stream@1.4.1` isn't the right malicious coordinate, fix the lockfile in the test to the actual one from the Step 1 grep.

- [ ] **Step 5: Commit**

```bash
git add packages/action/src/run.ts packages/action/test/run-e2e.test.ts
git commit -m "feat(phase17): runCi — self-boot proxy, audit-tree, SBOM + GitHub outputs + fail-on gate"
```

---

### Task 3: `sentinel-ci` bin entrypoint (env/flags → runCi → exit) + policy loading

**Files:**
- Create: `packages/action/src/index.ts`
- Test: `packages/action/test/bin-e2e.test.ts`

**Interfaces:**
- Consumes: `runCi` (Task 2), `NpmUpstream` + `LocalFixtureUpstream` (`@sentinel/proxy`), `loadPolicy` + `DEFAULT_POLICY` (`@sentinel/core`).
- Produces: a runnable `sentinel-ci` bin. Reads config from env vars set by `action.yml` (`INPUT_LOCKFILE`, `INPUT_POLICY`, `INPUT_SBOM_PATH`, `INPUT_FAIL_ON`, `INPUT_OMIT_DEV`, `INPUT_WORKING_DIRECTORY`) with sensible defaults; `process.exit(exitCode)`.

- [ ] **Step 1: Write the failing e2e** (`packages/action/test/bin-e2e.test.ts`) — run the built bin as a child, hermetically, with a fixture-backed upstream. Since the bin defaults to `NpmUpstream` (live npm), the test sets `SENTINEL_CI_FIXTURES=<dir>` to force `LocalFixtureUpstream` (the bin reads this test-only escape hatch — see Step 3). Assert: a malicious-tree lockfile → exit 2; observe mode → exit 0; no GitHub env → the report prints to stdout.

```ts
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { describe, test } from "node:test";

const execFileAsync = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO, "fixtures");
const BIN = join(REPO, "packages", "action", "dist", "index.js");

function ensureBuilt(): void {
  if (!existsSync(BIN)) execFileSync("npm", ["run", "build"], { cwd: REPO, stdio: "ignore" });
  if (!existsSync(join(FIXTURES, "registry.json"))) execFileSync("npx", ["tsx", join(REPO, "scripts", "make-fixtures.ts")], { cwd: REPO, stdio: "ignore" });
}
function lockDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-bin-"));
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify({
    name: "demo", lockfileVersion: 3,
    packages: { "": { name: "demo" }, "node_modules/leftpad-lite": { version: "1.0.0" }, "node_modules/color-stream": { version: "1.4.1" } },
  }));
  return dir;
}
async function run(dir: string, extraEnv: Record<string, string>): Promise<{ code: number; stdout: string }> {
  try {
    const { stdout } = await execFileAsync("node", [BIN], { cwd: dir, env: { ...process.env, SENTINEL_CI_FIXTURES: FIXTURES, ...extraEnv } });
    return { code: 0, stdout };
  } catch (e) {
    const err = e as { code?: number; stdout?: string };
    return { code: err.code ?? 1, stdout: err.stdout ?? "" };
  }
}

describe("sentinel-ci bin (e2e)", () => {
  test("fail-on=block on a malicious tree exits non-zero", async () => {
    ensureBuilt();
    const { code } = await run(lockDir(), { INPUT_FAIL_ON: "block", INPUT_SBOM_PATH: join(tmpdir(), `sb-${Date.now()}.json`) });
    assert.equal(code, 2);
  });
  test("fail-on=none exits 0 and prints the report to stdout (no GitHub env)", async () => {
    ensureBuilt();
    const { code, stdout } = await run(lockDir(), { INPUT_FAIL_ON: "none", INPUT_SBOM_PATH: join(tmpdir(), `sb2-${Date.now()}.json`) });
    assert.equal(code, 0);
    assert.match(stdout, /Sentinel dependency audit/);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/action/test/bin-e2e.test.ts
```

Expected: FAIL — the bin doesn't exist / doesn't behave.

- [ ] **Step 3: Implement `packages/action/src/index.ts`**

```ts
import { readFileSync } from "node:fs";
import { NpmUpstream, LocalFixtureUpstream, type Upstream } from "@sentinel/proxy";
import { loadPolicy, DEFAULT_POLICY, type EnterprisePolicy } from "@sentinel/core";
import { runCi } from "./run.js";

function env(name: string, fallback = ""): string {
  return process.env[name] ?? fallback;
}

/** Load a signed policy when INPUT_POLICY is set (reuses core's loadPolicy); else DEFAULT_POLICY. */
function resolvePolicy(): EnterprisePolicy {
  const file = env("INPUT_POLICY");
  if (!file) return DEFAULT_POLICY;
  const sig = env("INPUT_POLICY_SIG", `${file}.sig`);
  const pub = env("INPUT_POLICY_PUBKEY");
  if (!pub) throw new Error("INPUT_POLICY requires INPUT_POLICY_PUBKEY (path to the signer's public key PEM)");
  return loadPolicy({ file, sig, publicKeyPem: readFileSync(pub, "utf8") }).policy;
}

function pickUpstream(): Upstream {
  // Test-only escape hatch: force fixtures so bin e2e stays hermetic.
  const fx = env("SENTINEL_CI_FIXTURES");
  if (fx) return new LocalFixtureUpstream(fx);
  return new NpmUpstream(env("SENTINEL_REGISTRY", "https://registry.npmjs.org"));
}

async function main(): Promise<void> {
  const failOnRaw = env("INPUT_FAIL_ON", "block");
  const failOn = (["block", "warn", "none"] as const).includes(failOnRaw as never) ? (failOnRaw as "block" | "warn" | "none") : "block";
  const cwd = env("INPUT_WORKING_DIRECTORY") || process.cwd();
  const result = await runCi({
    upstream: pickUpstream(),
    cwd,
    lockfile: env("INPUT_LOCKFILE") || undefined,
    policy: resolvePolicy(),
    sbomPath: env("INPUT_SBOM_PATH", "sentinel-sbom.json"),
    failOn,
    omitDev: env("INPUT_OMIT_DEV") === "true",
    now: new Date().toISOString(),
    env: process.env,
  });
  process.exit(result.exitCode);
}

main().catch((err) => {
  console.error(`::error::sentinel-ci failed: ${(err as Error).message}`);
  process.exit(1);
});
```

- [ ] **Step 4: Build + run the bin e2e + full suite**

```bash
npm run build
npx tsx --test packages/action/test/bin-e2e.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS; record counts.

- [ ] **Step 5: Commit**

```bash
git add packages/action/src/index.ts packages/action/test/bin-e2e.test.ts
git commit -m "feat(phase17): sentinel-ci bin — env-driven entrypoint + signed-policy loading + fixtures escape hatch"
```

---

### Task 4: The composite `action.yml` + example workflow + structural test

**Files:**
- Create: `action.yml` (repo root)
- Create: `.github/workflows/sentinel-example.yml`
- Test: `packages/action/test/action-yml.test.ts`

**Interfaces:**
- Consumes: the `sentinel-ci` bin (Task 3) + its `INPUT_*` env contract.
- Produces: a publishable composite Action.

- [ ] **Step 1: Write the failing structural test** (`packages/action/test/action-yml.test.ts`)

```ts
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { parse } from "yaml";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const doc = parse(readFileSync(join(REPO, "action.yml"), "utf8")) as {
  name?: string; runs?: { using?: string; steps?: unknown[] };
  inputs?: Record<string, unknown>; outputs?: Record<string, unknown>;
};

describe("action.yml", () => {
  test("is a composite action", () => {
    assert.equal(doc.runs?.using, "composite");
    assert.ok(Array.isArray(doc.runs?.steps) && doc.runs!.steps!.length > 0);
  });
  test("declares the documented inputs", () => {
    for (const k of ["lockfile", "policy", "sbom-path", "fail-on", "comment", "working-directory"]) {
      assert.ok(doc.inputs && k in doc.inputs, `missing input ${k}`);
    }
  });
  test("declares the documented outputs", () => {
    for (const k of ["verdict", "gated", "blocked", "warned", "errored", "sbom-path"]) {
      assert.ok(doc.outputs && k in doc.outputs, `missing output ${k}`);
    }
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/action/test/action-yml.test.ts
```

Expected: FAIL — `action.yml` not found.

- [ ] **Step 3: Write `action.yml`** (repo root). Map inputs → `INPUT_*` env for the bin; upload the SBOM and post the comment with `if: always()`; find-and-update the comment by the marker.

```yaml
name: "Sentinel dependency audit"
description: "Audit the dependency tree, upload a CycloneDX SBOM, comment the verdict, and gate the PR."
author: "Sentinel"
branding: { icon: "shield", color: "purple" }
inputs:
  lockfile: { description: "Path to the lockfile (default: auto-detect)", required: false, default: "" }
  policy: { description: "Path to a signed enterprise policy file (default: built-in)", required: false, default: "" }
  sbom-path: { description: "Where to write the CycloneDX SBOM", required: false, default: "sentinel-sbom.json" }
  fail-on: { description: "block | warn | none — the verdict level that fails the check", required: false, default: "block" }
  comment: { description: "Post a PR comment with the verdict", required: false, default: "true" }
  working-directory: { description: "Directory to audit", required: false, default: "." }
outputs:
  verdict: { description: "Aggregate verdict (allow|warn|block)", value: "${{ steps.sentinel.outputs.verdict }}" }
  gated: { description: "Whether the tree was gated", value: "${{ steps.sentinel.outputs.gated }}" }
  blocked: { description: "Count of blocked packages", value: "${{ steps.sentinel.outputs.blocked }}" }
  warned: { description: "Count of warned packages", value: "${{ steps.sentinel.outputs.warned }}" }
  errored: { description: "Count of errored packages", value: "${{ steps.sentinel.outputs.errored }}" }
  sbom-path: { description: "Path to the written SBOM", value: "${{ steps.sentinel.outputs.sbom-path }}" }
runs:
  using: composite
  steps:
    - uses: actions/setup-node@v4
      with: { node-version: "24" }
    - name: Install & build Sentinel
      shell: bash
      run: |
        npm ci --prefix "${{ github.action_path }}"
        npm run build --prefix "${{ github.action_path }}"
    - name: Run Sentinel audit
      id: sentinel
      shell: bash
      working-directory: ${{ inputs.working-directory }}
      env:
        INPUT_LOCKFILE: ${{ inputs.lockfile }}
        INPUT_POLICY: ${{ inputs.policy }}
        INPUT_SBOM_PATH: ${{ inputs.sbom-path }}
        INPUT_FAIL_ON: ${{ inputs.fail-on }}
        INPUT_WORKING_DIRECTORY: ${{ inputs.working-directory }}
        SENTINEL_COMMENT_BODY: ${{ runner.temp }}/sentinel-comment.md
      run: node "${{ github.action_path }}/packages/action/dist/index.js"
    - name: Upload SBOM
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: sentinel-sbom
        path: ${{ inputs.working-directory }}/${{ inputs.sbom-path }}
        if-no-files-found: ignore
    - name: Comment verdict on PR
      if: always() && inputs.comment == 'true' && github.event_name == 'pull_request'
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const path = `${process.env.RUNNER_TEMP}/sentinel-comment.md`;
          if (!fs.existsSync(path)) return;
          const body = fs.readFileSync(path, 'utf8');
          const marker = '<!-- sentinel-report -->';
          const { data: comments } = await github.rest.issues.listComments({ owner: context.repo.owner, repo: context.repo.repo, issue_number: context.issue.number });
          const existing = comments.find((c) => c.body && c.body.includes(marker));
          if (existing) await github.rest.issues.updateComment({ owner: context.repo.owner, repo: context.repo.repo, comment_id: existing.id, body });
          else await github.rest.issues.createComment({ owner: context.repo.owner, repo: context.repo.repo, issue_number: context.issue.number, body });
```

(Note: the `github.action_path` install/build steps assume the Action ships its source; a published-package variant is documented in the README. This shape is what the structural test validates.)

- [ ] **Step 4: Write `.github/workflows/sentinel-example.yml`** — a usage example (also dogfoods on this repo):

```yaml
name: Sentinel
on: { pull_request: {} }
permissions: { contents: read, pull-requests: write }
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Sentinel audit (enforce)
        uses: ./
        with:
          fail-on: block
      # Observe-only onboarding variant:
      # with: { fail-on: none }
```

- [ ] **Step 5: Run the structural test + full suite**

```bash
npm run build
npx tsx --test packages/action/test/action-yml.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add action.yml .github/workflows/sentinel-example.yml packages/action/test/action-yml.test.ts
git commit -m "feat(phase17): composite action.yml + example workflow + structural test"
```

---

### Task 5: Docs, ADR-0030, final verification

**Files:**
- Create: `docs/adr/0030-ci-native-github-action.md`
- Modify: `ARCHITECTURE.md` (the CI/Action layer + self-boot pattern)
- Modify: `CLAUDE.md` (What-this-is phase list; the new `@sentinel/action` workspace; test-count line)
- Modify: `README.md` (a top-level "GitHub Action" usage section)

- [ ] **Step 1: Write ADR-0030** — follow the style of `docs/adr/0027-ecosystem-breadth-sbom.md`. Required content: **Context** (16 phases of capability, no adoption on-ramp; the CLI needs a separate proxy; nothing surfaces in a PR). **Decision** (a `@sentinel/action` workspace with a `sentinel-ci` runner that self-boots the proxy in-process with an injected upstream, runs the existing `/-/audit-tree` flow, writes a CycloneDX SBOM + GitHub-native outputs/summary/annotations, and exits per `fail-on`; a thin composite `action.yml` uploads the SBOM and posts an idempotent PR comment found by a `<!-- sentinel-report -->` marker). **Determinism** (the Action only *runs* the audit; `renderPrComment`/SBOM take an injected `now`; scoring untouched — invariant #1 intact). **Consequences** (self-boot avoids background-process fragility and reuses all machinery; injected upstream keeps tests hermetic; `fail-on: none` gives an observe→enforce onboarding path; no package code executes). **Deferred** (SARIF/code-scanning; GitLab/other CI; pre-commit hook; Marketplace publish workflow; auto-remediation in the comment). **Rejected** (a Docker action — heavier, an image to publish; a background-proxy step — PID/readiness fragility; putting the runner in `@sentinel/cli` — muddies the pure HTTP client). VERIFY any ADR cross-reference number with `head -1 docs/adr/00*.md` before citing. Extends ADR-0020/0027.

- [ ] **Step 2: ARCHITECTURE.md** — add a CI/Action section: the `@sentinel/action` workspace, `runCi` self-boot + injected upstream, the GitHub-native outputs, and the composite `action.yml`. Note the scoring engine is untouched and no package code executes.

- [ ] **Step 3: CLAUDE.md** — add the Phase 17 sentence to "What this is" (mirror recent-phase density). Note the new `@sentinel/action` workspace (bin `sentinel-ci`) in the stack/workspace list. Update the `npm test` count to the ACTUAL number from Step 5 (preserve darwin-skip caveats).

- [ ] **Step 4: README.md** — add a top-level "GitHub Action" section: a `uses:` snippet, the inputs/outputs table, the minimal `permissions: { contents: read, pull-requests: write }`, the SBOM artifact + PR comment behavior, and the observe→enforce (`fail-on`) onboarding path.

- [ ] **Step 5: Full Definition-of-Done run**

```bash
npm run build
npm run fixtures
npm test 2>&1 | tail -8
npm run demo 2>&1 | tail -3
```

Expected: build clean; ALL tests pass (record exact count for CLAUDE.md); demo still blocks the malicious fixture. If the count differs from CLAUDE.md, update the doc to reality.

- [ ] **Step 6: Commit**

```bash
git add docs ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs(phase17): ADR-0030 CI-native GitHub Action; ARCHITECTURE/CLAUDE/README"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 architecture → Task 1 (workspace + report) + Task 2 (runCi self-boot); §2 runner (inputs/flow/gate/renderPrComment/local-runnable/policy) → Task 2 (runCi, fail-on, auto-detect, outputs/summary/annotations) + Task 3 (bin env contract, policy via loadPolicy, no-GitHub-env stdout); §3 action.yml/commenting/example/permissions → Task 4; §4 testing/DoD → each task's tests + Task 5. The malicious-fixture-still-blocks requirement is Task 2's e2e (exit 2) + Task 5's demo.
- **Type consistency:** `renderPrComment(result, {now})` + `REPORT_MARKER` (Task 1) consumed by `runCi` (Task 2); `RunCiOptions`/`CiResult` (Task 2) consumed by the bin (Task 3); the `INPUT_*` env contract (Task 3) is what `action.yml` sets (Task 4). `fail-on` union `"block"|"warn"|"none"` consistent across runCi, the bin, and action.yml's default.
- **Known judgment calls:** the runner self-boots `createServer` (reuses all machinery, no background process); `loadPolicy` is already exported from core (no new export needed — the spec's "export if needed" was precautionary); a test-only `SENTINEL_CI_FIXTURES` escape hatch lets the bin e2e stay hermetic without hitting live npm; `exitFor` makes the action's `fail-on` authoritative but also honors the server-side `gated` flag (so `--fail-on-error`-style error gating still works); the comment-body path is passed via `SENTINEL_COMMENT_BODY` so `action.yml` (not the runner) owns the GitHub API call.
