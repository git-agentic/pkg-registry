# Phase 18 — Actionable Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn a verdict into a next action — per-finding remediation guidance, a computed last-known-good version, and a ready-to-use waiver — surfaced via `sentinel explain`, the PR comment, and MCP.

**Architecture:** A pure `remediate(report)` in `@sentinel/core` maps findings to `{ summary, action }` guidance + a waiver template; a proxy `GET /-/explain/:pkg/:version` route audits the target, runs `remediate`, and walks back prior versions for a last-known-good `allow`; three thin surfaces (CLI/PR/MCP) project those. Advisory-only — never mutates a lockfile. Scoring is untouched.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; reuses `@sentinel/proxy` (`auditVersion`, `cmpSemver`) + `@sentinel/core`; `node:test` via `tsx`. No new dependencies.

## Global Constraints

- **Advisory-only.** Remediation SUGGESTS; it never rewrites a lockfile or applies a change. No `sentinel fix` / auto-mutation in this phase.
- **`remediate` is pure & deterministic** — a pure function of the `AuditReport`; no network, no clock; same report ⇒ same `Remediation`. It NEVER feeds `score.ts` (invariant #1 untouched).
- **Total / crash-safe** — an unknown `ruleId` falls back to category-generic then a generic default; never throws. The last-known-good walk wraps each prior-version audit and returns `lastKnownGood: null` rather than crashing.
- **Last-known-good is bounded** — the newest `allow` among at most the **10** most recent *prior* versions (semver, strictly older than the target), newest-first, short-circuiting on the first clean one; the window cap is documented.
- **Off the inline gate** (invariant #3) — the explain route (audit + walk) is a separate route; the PR-comment hint is a cheap `ruleId → string` lookup with no extra audits.
- **Waiver payload = the Phase 11 shape** — `{ name, version, integrity, reason }` (the `POST /-/approval-requests` request-not-grant payload); the approve command mirrors the real `sentinel approve <package> <version> --reason <r>` signature.
- **Types (verbatim):** `RemediationItem { ruleId: string; severity: Severity; summary: string; action: string }`; `WaiverTemplate { name: string; version: string; integrity: string | null; approveCommand: string; requestPayload: { name: string; version: string; integrity: string | null; reason: string } }`; `Remediation { items: RemediationItem[]; waiver: WaiverTemplate | null; guidance: string }`.
- ESM only, NodeNext: internal imports use `.js` specifiers; cross-package imports use the package name.
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/<pkg>`.
- Run all commands from repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.

---

### Task 1: Core `remediate` + `remediationHint` + the REMEDIATIONS map

**Files:**
- Create: `packages/core/src/remediation.ts`
- Modify: `packages/core/src/index.ts` (export)
- Test: `packages/core/test/remediation.test.ts`

**Interfaces:**
- Consumes: `AuditReport`, `Finding`, `Severity`, `Category`, `Verdict` (types).
- Produces (used by Tasks 2–5): `remediate(report: AuditReport): Remediation`; `remediationHint(ruleId: string): string`; the three interfaces above.

- [ ] **Step 1: Write the failing test** (`packages/core/test/remediation.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { remediate, remediationHint } from "../src/remediation.js";
import type { AuditReport, Finding } from "../src/types.js";

function finding(over: Partial<Finding> = {}): Finding {
  return { ruleId: "install-scripts", category: "capability", severity: "high", message: "runs a postinstall", onChangedFile: false, evidence: [], ...over } as Finding;
}
function report(over: Partial<AuditReport> = {}): AuditReport {
  return {
    schema: 3,
    meta: { name: "acme", version: "2.0.0", integrity: "sha512-x", author: null, maintainers: [], license: "MIT", hasInstallScripts: true, signature: "unsigned", provenance: "absent" },
    score: 40, verdict: "block", findings: [finding()],
    ...over,
  } as unknown as AuditReport;
}

describe("remediate", () => {
  test("maps a known ruleId to summary + action", () => {
    const r = remediate(report());
    assert.equal(r.items.length, 1);
    assert.equal(r.items[0]!.ruleId, "install-scripts");
    assert.match(r.items[0]!.action, /approve|manifest|alternative/i);
  });

  test("orders items worst-severity first", () => {
    const r = remediate(report({ findings: [
      finding({ ruleId: "provenance", severity: "low", message: "no provenance" }),
      finding({ ruleId: "install-scripts", severity: "high", message: "postinstall" }),
    ] }));
    assert.deepEqual(r.items.map((i) => i.ruleId), ["install-scripts", "provenance"]);
  });

  test("block verdict yields a waiver with the correct coordinates + payload", () => {
    const r = remediate(report());
    assert.ok(r.waiver);
    assert.equal(r.waiver!.name, "acme");
    assert.equal(r.waiver!.version, "2.0.0");
    assert.equal(r.waiver!.requestPayload.integrity, "sha512-x");
    assert.match(r.waiver!.approveCommand, /^sentinel approve acme 2\.0\.0/);
  });

  test("allow verdict yields no waiver", () => {
    assert.equal(remediate(report({ verdict: "allow", score: 100, findings: [] })).waiver, null);
  });

  test("unknown ruleId falls back to a generic action, never throws", () => {
    const r = remediate(report({ findings: [finding({ ruleId: "brand-new-rule", category: "metadata" })] }));
    assert.equal(r.items.length, 1);
    assert.ok(r.items[0]!.action.length > 0);
  });

  test("remediationHint returns a short action string for a known ruleId", () => {
    assert.ok(remediationHint("release-anomaly").length > 0);
    assert.ok(remediationHint("nonexistent").length > 0); // generic fallback
  });

  test("deterministic — same report yields the same remediation", () => {
    assert.deepEqual(remediate(report()), remediate(report()));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/core/test/remediation.test.ts
```

Expected: FAIL — `../src/remediation.js` not found.

- [ ] **Step 3: Implement `packages/core/src/remediation.ts`**

```ts
import type { AuditReport, Category, Finding, Severity } from "./types.js";

export interface RemediationItem { ruleId: string; severity: Severity; summary: string; action: string; }
export interface WaiverTemplate {
  name: string;
  version: string;
  integrity: string | null;
  approveCommand: string;
  requestPayload: { name: string; version: string; integrity: string | null; reason: string };
}
export interface Remediation { items: RemediationItem[]; waiver: WaiverTemplate | null; guidance: string; }

interface Guide { summary: string; action: string; }

/** Per-ruleId remediation guidance. Authored here (not in the rules) so rules stay pure. */
const REMEDIATIONS: Record<string, Guide> = {
  "install-scripts": { summary: "Runs install-time lifecycle scripts.", action: "Review the scripts; approve the capability manifest (`sentinel approve …`) if they're required, otherwise prefer a script-free alternative." },
  "secret-exfil": { summary: "Reads credentials/tokens and may exfiltrate them.", action: "Do not install until reviewed. If this is a false positive, waive with a recorded rationale; otherwise remove the dependency." },
  "network-egress": { summary: "Makes network connections.", action: "Confirm the egress is expected for this package's purpose; if not, remove it or pin to a version without it." },
  "obfuscation": { summary: "Contains obfuscated/minified-beyond-normal code.", action: "Inspect the source; obfuscation in a dependency is a red flag — prefer a readable, well-known alternative." },
  "provenance": { summary: "Missing or unverifiable build provenance.", action: "Request an exception, or choose a package that publishes SLSA build provenance (`dist.attestations`)." },
  "provenance-identity": { summary: "Provenance identity does not match the required repo/workflow/builder.", action: "Verify the release's build identity; if the mismatch is unexpected, do not install and report it." },
  "typosquat": { summary: "Name resembles a popular package.", action: "Confirm you meant this exact package name — check for a one-character typo against the intended dependency." },
  "dependency-confusion": { summary: "Public name look-alike of a claimed private namespace.", action: "Confirm this is the intended public package, not an attacker shadowing your internal name; if internal, install from the private registry." },
  "release-anomaly": { summary: "This release differs from the package's own history (maintainer change, dormancy, or a new first-version capability).", action: "Confirm the change is legitimate; if the ownership/behavior change is unexpected, pin to a known-good earlier version (run `sentinel explain` for a suggestion)." },
  "capability-novelty": { summary: "Adds a dangerous capability the prior version did not have.", action: "Review why this version newly needs network/process access; if unexpected, pin to the prior version." },
  "integrity-mismatch": { summary: "The lockfile's pinned hash differs from what the registry serves.", action: "Regenerate the lockfile from a trusted source, or investigate possible tampering/registry compromise." },
};

const CATEGORY_FALLBACK: Partial<Record<Category, Guide>> = {
  capability: { summary: "Requests a sensitive capability.", action: "Review the capability; approve it via the manifest if required, else avoid the package." },
  metadata: { summary: "A supply-chain metadata signal.", action: "Review the finding; confirm the package's identity and provenance before installing." },
};

const GENERIC: Guide = { summary: "A security finding was flagged.", action: "Review the finding details; approve with a recorded rationale only if you understand and accept the risk." };

function guideFor(ruleId: string, category: Category): Guide {
  return REMEDIATIONS[ruleId] ?? CATEGORY_FALLBACK[category] ?? GENERIC;
}

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Short action string for a ruleId — used by compact surfaces (the PR comment). */
export function remediationHint(ruleId: string): string {
  return (REMEDIATIONS[ruleId] ?? GENERIC).action;
}

/**
 * Advisory remediation for an audited package: per-finding `{ summary, action }` guidance ordered
 * worst-first, plus a waiver / approval-request template when the verdict is warn/block. Pure,
 * deterministic, total (unknown ruleId → generic). Never feeds scoring.
 */
export function remediate(report: AuditReport): Remediation {
  const items: RemediationItem[] = [...report.findings]
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])
    .map((f: Finding) => {
      const g = guideFor(f.ruleId, f.category);
      return { ruleId: f.ruleId, severity: f.severity, summary: g.summary, action: g.action };
    });

  const m = report.meta;
  const waiver: WaiverTemplate | null =
    report.verdict === "allow"
      ? null
      : {
          name: m.name, version: m.version, integrity: m.integrity,
          approveCommand: `sentinel approve ${m.name} ${m.version} --reason "reviewed and accepted"`,
          requestPayload: { name: m.name, version: m.version, integrity: m.integrity, reason: "reviewed and accepted" },
        };

  const guidance =
    report.verdict === "allow"
      ? `allow — no action required${items.length ? ` (${items.length} informational finding(s))` : ""}.`
      : `${report.verdict} — ${items.length} finding(s); see the actions below${waiver ? " or waive with the recorded rationale" : ""}.`;

  return { items, waiver, guidance };
}
```

- [ ] **Step 4: Export from `packages/core/src/index.ts`**

```ts
export { remediate, remediationHint, type Remediation, type RemediationItem, type WaiverTemplate } from "./remediation.js";
```

- [ ] **Step 5: Run the test + build**

```bash
npm run build
npx tsx --test packages/core/test/remediation.test.ts
```

Expected: PASS (7/7). Then a quick full `npm test`.

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/remediation.ts packages/core/src/index.ts packages/core/test/remediation.test.ts
git commit -m "feat(phase18): remediate core — per-finding guidance + waiver template + remediationHint"
```

---

### Task 2: Proxy `GET /-/explain/:pkg/:version` + last-known-good

**Files:**
- Modify: `packages/proxy/src/server.ts` (the explain route + `findLastKnownGood` helper)
- Test: `packages/proxy/test/explain-e2e.test.ts`

**Interfaces:**
- Consumes: `auditVersion` (in-scope in `createServer`), `remediate` (`@sentinel/core`), `cmpSemver` (`./upstream.js`), `opts.upstream.getPackument`.
- Produces (used by Tasks 3, 5): `GET /-/explain/:pkg/:version` → `{ report: AuditReport, remediation: Remediation, lastKnownGood: { version: string; score: number } | null }`.

- [ ] **Step 1: Write the failing e2e** (`packages/proxy/test/explain-e2e.test.ts`) — boot the in-process proxy (model on `packages/proxy/test/audit-tree-integrity-e2e.test.ts`), audit the Phase 16 `hijacked-lib` fixture (v2 blocks, v1 is clean):

```ts
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const FIXTURES = join(REPO, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO, "scripts", "make-fixtures.ts")], { cwd: REPO, stdio: "ignore" });
}
function boot(): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(),
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` })); });
}

describe("GET /-/explain (e2e)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot()); });
  after(() => server?.close());

  test("blocked release returns report + remediation + last-known-good earlier version", async () => {
    const r = await (await fetch(`${base}/-/explain/hijacked-lib/2.0.0`)).json() as {
      report: { verdict: string; findings: unknown[] };
      remediation: { items: { ruleId: string }[]; waiver: unknown };
      lastKnownGood: { version: string; score: number } | null;
    };
    assert.notEqual(r.report.verdict, "allow"); // v2 is flagged
    assert.ok(r.remediation.items.length >= 1);
    assert.ok(r.remediation.waiver); // block/warn → waiver present
    assert.equal(r.lastKnownGood?.version, "1.0.0"); // v1 is the clean earlier release
  });

  test("a clean package has no last-known-good need (or itself is fine)", async () => {
    const r = await (await fetch(`${base}/-/explain/leftpad-lite/1.0.0`)).json() as {
      report: { verdict: string }; lastKnownGood: unknown;
    };
    assert.equal(r.report.verdict, "allow");
    // no earlier clean version required; lastKnownGood may be null (no priors) — just assert shape
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/explain-e2e.test.ts
```

Expected: FAIL — `/-/explain/…` 404s.

- [ ] **Step 3: Add the route + helper in `server.ts`** (near the `/-/audit/:pkg/:version` route). Import `remediate` from `@sentinel/core` and `cmpSemver` from `./upstream.js`:

```ts
  /** Newest prior version (semver, strictly older, most-recent 10) that audits `allow`. */
  async function findLastKnownGood(pkg: string, version: string): Promise<{ version: string; score: number } | null> {
    let priors: string[];
    try {
      const pm = await upstream.getPackument(pkg);
      priors = Object.keys(pm.versions).filter((v) => cmpSemver(v, version) < 0).sort(cmpSemver).reverse().slice(0, 10);
    } catch {
      return null;
    }
    for (const v of priors) {
      try {
        const { report } = await auditVersion(pkg, v);
        if (report.verdict === "allow") return { version: v, score: report.score };
      } catch { /* skip an unauditeable prior version */ }
    }
    return null;
  }

  app.get(/^\/-\/explain\/(.+)\/([^/]+)$/, async (req, res) => {
    const pkg = decodeURIComponent(req.params[0] ?? "");
    const version = req.params[1] ?? "";
    try {
      const { report } = await auditVersion(pkg, version);
      const remediation = remediate(report);
      const lastKnownGood = await findLastKnownGood(pkg, version);
      res.json({ report, remediation, lastKnownGood });
    } catch (err) {
      sendError(res, err);
    }
  });
```

(Add `remediate` to the `@sentinel/core` import and `cmpSemver` to the `./upstream.js` import. `upstream` is `opts.upstream`, already in scope.)

- [ ] **Step 4: Build + run the e2e + existing proxy suite**

```bash
npm run build
npx tsx --test packages/proxy/test/explain-e2e.test.ts packages/proxy/test/audit-tree-integrity-e2e.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/explain-e2e.test.ts
git commit -m "feat(phase18): GET /-/explain — audit + remediate + last-known-good walk"
```

---

### Task 3: CLI `sentinel explain` + `formatExplain`

**Files:**
- Modify: `packages/cli/src/index.ts` (the `explain` command)
- Modify: `packages/cli/src/format.ts` (`formatExplain`)
- Test: `packages/cli/test/explain-cli-e2e.test.ts`

**Interfaces:**
- Consumes: `GET /-/explain/:pkg/:version` (Task 2); `Remediation` types (`@sentinel/core`).
- Produces: `sentinel explain <package> <version>`.

- [ ] **Step 1: Write the failing e2e** (`packages/cli/test/explain-cli-e2e.test.ts`) — boot an in-process proxy with `LocalFixtureUpstream`, run the CLI child via async `execFile` with `SENTINEL_PROXY` (model on an existing CLI e2e in `packages/cli/test`). Assert `sentinel explain hijacked-lib 2.0.0`: output contains the verdict, a finding action, the last-known-good line (`1.0.0`), and the `sentinel approve hijacked-lib 2.0.0` waiver command; exits 0.

```ts
// Skeleton — fill boot/run helpers from an existing CLI e2e in packages/cli/test:
// boot(): createServer(...) with LocalFixtureUpstream + all stores, listen(0)
// runCli(args, base): promisify(execFile)("npx", ["tsx", CLI_INDEX, ...args], { env: { ...process.env, SENTINEL_PROXY: base } })
// test: runCli(["explain", "hijacked-lib", "2.0.0"], base) →
//   stdout matches /BLOCK|WARN/, /pin to|known-good|1\.0\.0/, /sentinel approve hijacked-lib 2\.0\.0/
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/cli/test/explain-cli-e2e.test.ts
```

Expected: FAIL — `explain` command doesn't exist.

- [ ] **Step 3: Add the `explain` command in `packages/cli/src/index.ts`** (model on the `manifest` command). Import `formatExplain` from `./format.js`:

```ts
program
  .command("explain")
  .description("Explain a package's verdict and how to remediate it: per-finding actions, a suggested known-good version, and a ready waiver.")
  .argument("<package>")
  .argument("<version>")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .action(async (pkg: string, version: string, opts: { proxy: string }) => {
    try {
      const res = await fetch(`${opts.proxy}/-/explain/${encodeURIComponent(pkg)}/${encodeURIComponent(version)}`);
      if (!res.ok) return fail(new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? `explain failed: ${res.status}`), opts.proxy);
      console.log(formatExplain(await res.json() as ExplainResult));
    } catch (err) {
      fail(err, opts.proxy);
    }
  });
```

Add the `formatExplain` function + `ExplainResult` type to `packages/cli/src/format.ts` (pure; match the existing colored-formatter style):

```ts
import type { AuditReport, Remediation } from "@sentinel/core";

export interface ExplainResult {
  report: AuditReport;
  remediation: Remediation;
  lastKnownGood: { version: string; score: number } | null;
}

export function formatExplain(r: ExplainResult): string {
  const L: string[] = ["", `  ${r.report.meta.name}@${r.report.meta.version}  —  ${c(verdictColor[r.report.verdict] ?? C.gray, r.report.verdict.toUpperCase())}  ${r.report.score}/100`, ""];
  L.push(c(C.bold, "  " + r.remediation.guidance));
  L.push("");
  for (const it of r.remediation.items) {
    L.push(`  • ${c(C.bold, it.ruleId)} (${it.severity}) — ${it.summary}`);
    L.push(`      ${c(C.gray, it.action)}`);
  }
  if (r.remediation.items.length) L.push("");
  if (r.lastKnownGood) {
    L.push(c(C.green, `  ✓ suggested: pin to ${r.report.meta.name}@${r.lastKnownGood.version} — the most recent clean release (${r.lastKnownGood.score}/100).`));
    L.push("");
  }
  if (r.remediation.waiver) {
    L.push("  To waive after review:");
    L.push(`      ${r.remediation.waiver.approveCommand}`);
    L.push("");
  }
  return L.join("\n");
}
```

(Import `formatExplain` + `ExplainResult` in `index.ts`; ensure `c`/`C`/`verdictColor` are in scope in `format.ts` — they already are for the other formatters.)

- [ ] **Step 4: Build + run the e2e + full suite**

```bash
npm run build
npx tsx --test packages/cli/test/explain-cli-e2e.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS; record counts.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/index.ts packages/cli/src/format.ts packages/cli/test/explain-cli-e2e.test.ts
git commit -m "feat(phase18): sentinel explain CLI command + formatExplain"
```

---

### Task 4: PR-comment remediation hint (`topFindingRuleId` + `renderPrComment`)

**Files:**
- Modify: `packages/core/src/tree.ts` (`TreePackageRow.topFindingRuleId`)
- Modify: `packages/proxy/src/server.ts` (audit-tree route sets `topFindingRuleId`)
- Modify: `packages/action/src/report.ts` (`renderPrComment` shows the hint + pointer)
- Test: `packages/action/test/report.test.ts` (extend); update any `TreePackageRow` literals

**Interfaces:**
- Consumes: `remediationHint` (`@sentinel/core`, Task 1).
- Produces: `TreePackageRow.topFindingRuleId: string | null`.

- [ ] **Step 1: Extend the failing test** in `packages/action/test/report.test.ts` — add `topFindingRuleId` to the fixture rows and assert the rendered comment shows the remediation hint + the explain pointer:

```ts
test("shows a remediation hint per offender and an explain pointer", () => {
  const withRule: TreeAuditResult = {
    aggregate: { verdict: "block", gated: true, counts: { allow: 0, warn: 0, block: 1, error: 0 }, provenance: { verified: 0, invalid: 0, absent: 1, unknown: 0 }, integrityMismatch: 0 },
    packages: [{ name: "evil", version: "2.0.0", status: "block", score: 10, topFinding: "changed hands", topFindingRuleId: "release-anomaly", error: null, provenance: "absent", integrityMismatch: false }],
  };
  const md = renderPrComment(withRule, { now: "2026-07-08T00:00:00Z" });
  assert.match(md, /pin to|known-good|earlier version/i); // release-anomaly hint text
  assert.match(md, /sentinel explain/);
});
```

(Add `topFindingRuleId: null` to the other `TreePackageRow` literals already in this test file so they typecheck.)

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/action/test/report.test.ts
```

Expected: FAIL — `topFindingRuleId` missing / no hint rendered.

- [ ] **Step 3a: Add `topFindingRuleId` to `TreePackageRow` in `packages/core/src/tree.ts`**

```ts
  /** ruleId of the top finding, for remediation lookup (Phase 18); null on error/no-finding rows. */
  topFindingRuleId: string | null;
```

- [ ] **Step 3b: Set it in the audit-tree route** (`packages/proxy/src/server.ts`) — in the row builder, alongside `topFinding`:

```ts
            topFindingRuleId: report.findings[0]?.ruleId ?? null,
```
and in the `catch` (error row) builder: `topFindingRuleId: null,`. Also add `topFindingRuleId: null` to the mismatch-forced-block row if it constructs a separate literal (it reuses the same object — just ensure the field is set once).

- [ ] **Step 3c: Render the hint + pointer in `renderPrComment`** (`packages/action/src/report.ts`) — import `remediationHint` from `@sentinel/core`; in the offenders table (or just below it), add a remediation column/line and a footer pointer. Minimal change: add a "remediation" cell to the table row and a footer:

```ts
import type { TreeAuditResult, TreePackageRow } from "@sentinel/core";
import { remediationHint } from "@sentinel/core";
```
In the offenders loop, change the table header + rows to include a hint column:
```ts
    L.push("| package | verdict | score | finding | how to fix |");
    L.push("| --- | --- | --- | --- | --- |");
    for (const p of offenders) {
      const finding = p.error ?? p.topFinding ?? "";
      const hint = p.topFindingRuleId ? remediationHint(p.topFindingRuleId) : "";
      L.push(`| ${escapePipe(`${p.name}@${p.version}`)} | ${p.status} | ${scoreCell(p)} | ${escapePipe(finding)} | ${escapePipe(hint)} |`);
    }
    L.push("");
    L.push("▶ Run `sentinel explain <package> <version>` for a suggested safe version and a ready waiver.");
```

- [ ] **Step 4: Build + run the report test + the existing tree/audit-tree suites** (the `TreePackageRow` field is required, so existing row literals across tests need `topFindingRuleId: null` — the compiler/tests flag them; add it mechanically)

```bash
npm run build
npx tsx --test packages/action/test/report.test.ts packages/proxy/test/audit-tree-integrity-e2e.test.ts packages/core/test/tree.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS; record counts.

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/tree.ts packages/proxy/src/server.ts packages/action/src/report.ts packages/action/test/report.test.ts packages/proxy/test/*.test.ts packages/core/test/tree.test.ts
git commit -m "feat(phase18): PR-comment remediation hint via TreePackageRow.topFindingRuleId + explain pointer"
```

---

### Task 5: MCP `sentinel_explain` tool + `ProxyClient.explain`

**Files:**
- Modify: `packages/mcp/src/client.ts` (`explain` method)
- Modify: `packages/mcp/src/tools.ts` (`sentinel_explain` tool)
- Test: `packages/mcp/test/tools.test.ts` (or the existing mcp tool test file)

**Interfaces:**
- Consumes: `GET /-/explain/:pkg/:version` (Task 2).
- Produces: `ProxyClient.explain(pkg: string, version: string): Promise<ExplainResult>`; a `sentinel_explain` tool.

- [ ] **Step 1: Extend the failing test** — in the mcp tool test (find it: `ls packages/mcp/test`), add a case that `sentinel_explain` returns the `{ report, remediation, lastKnownGood }` structured shape. Model on the existing `sentinel_audit` tool test (boot an in-process proxy with `LocalFixtureUpstream`, construct the client, call the tool handler). Assert the structured result has `remediation.items` and `lastKnownGood` for `hijacked-lib@2.0.0`.

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/mcp/test/*.test.ts
```

Expected: FAIL — `sentinel_explain` / `client.explain` missing.

- [ ] **Step 3a: Add `explain` to `ProxyClient`** (`packages/mcp/src/client.ts`) — mirror the existing `audit` method:

```ts
  async explain(pkg: string, version: string): Promise<unknown> {
    const res = await fetch(`${this.base}/-/explain/${encodeURIComponent(pkg)}/${encodeURIComponent(version)}`);
    if (!res.ok) throw new Error(`explain failed: ${res.status}`);
    return res.json();
  }
```

(Match the exact style/return-typing of the existing `audit`/`auditTree` methods in that file — read them first.)

- [ ] **Step 3b: Add the `sentinel_explain` tool** to `TOOLS` in `packages/mcp/src/tools.ts`:

```ts
  {
    name: "sentinel_explain",
    description: "Explain a package version's verdict and how to remediate it: per-finding actions, a suggested known-good earlier version, and a ready approval-request payload.",
    inputSchema: { package: z.string(), version: z.string() },
    async handler(args, client) {
      const result = await client.explain(args.package as string, args.version as string);
      const r = result as { report: { verdict: string; score: number }; remediation: { guidance: string; items: { ruleId: string; action: string }[] }; lastKnownGood: { version: string } | null };
      const lines = [r.remediation.guidance, ...r.remediation.items.map((i) => `- ${i.ruleId}: ${i.action}`)];
      if (r.lastKnownGood) lines.push(`Suggested safe version: ${r.lastKnownGood.version}`);
      return { text: lines.join("\n"), structured: result };
    },
  },
```

- [ ] **Step 4: Build + run the mcp test + full suite**

```bash
npm run build
npx tsx --test packages/mcp/test/*.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS; record counts.

- [ ] **Step 5: Commit**

```bash
git add packages/mcp/src/client.ts packages/mcp/src/tools.ts packages/mcp/test/*.test.ts
git commit -m "feat(phase18): MCP sentinel_explain tool + ProxyClient.explain"
```

---

### Task 6: Docs, ADR-0031, final verification

**Files:**
- Create: `docs/adr/0031-actionable-remediation.md`
- Modify: `ARCHITECTURE.md` (the remediation layer + explain endpoint + last-known-good)
- Modify: `CLAUDE.md` (What-this-is phase list; `sentinel explain`; test-count line)
- Modify: `README.md` (the explain/remediation feature)

- [ ] **Step 1: Write ADR-0031** — follow the style of `docs/adr/0027-ecosystem-breadth-sbom.md`. Required content: **Context** (17 phases detect/contain/record/gate but never guide; no remediation field; Phase 17 made "how do I get green?" urgent). **Decision** (a pure `remediate(report)` mapping findings → `{summary, action}` + a waiver template; a `GET /-/explain/:pkg/:version` that audits + remediates + walks back a bounded window for last-known-good; surfaced via `sentinel explain`, a PR-comment hint (`topFindingRuleId` + `remediationHint`), and an MCP `sentinel_explain` tool; **advisory-only** — never mutates a lockfile). **Determinism** (remediate pure, never feeds the score; invariant #1 intact; last-known-good reuses deterministic per-version audits). **Consequences** (advisory-only preserves trust; off-gate; the waiver reuses Phase 11's request-not-grant payload; last-known-good is a bounded window — documented cap). **Deferred** (auto-fix `sentinel fix`; cross-package remediation; full-history search; specific-alternative recommender). **Rejected** (a `remediation` field on every rule — scatters guidance, couples rules; auto-editing the lockfile — unsafe). **VERIFY** the request-not-grant / approval-gate ADR number with `head -1 docs/adr/00*.md | grep -i "approv\|request\|mcp"` before citing it; extends ADR-0002.

- [ ] **Step 2: ARCHITECTURE.md** — document the remediation layer (`remediate` pure core), the `/-/explain` endpoint + last-known-good walk (bounded window, off-gate), and the three surfaces (CLI/PR/MCP). Note advisory-only + invariant #1 untouched.

- [ ] **Step 3: CLAUDE.md** — add the Phase 18 sentence to "What this is" (mirror recent-phase density). Note `sentinel explain` in the CLI list. Update the `npm test` count to the ACTUAL number from Step 5 (preserve darwin-skip caveats).

- [ ] **Step 4: README.md** — document `sentinel explain <package> <version>` (per-finding actions, last-known-good suggestion, ready waiver), the `/-/explain` endpoint, and that the PR comment + MCP surface remediation. Note advisory-only (no auto-fix).

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
git commit -m "docs(phase18): ADR-0031 actionable remediation; ARCHITECTURE/CLAUDE/README"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 architecture/advisory → Task 1 (pure remediate) + Task 2 (explain route); §2 remediate core (per-finding + waiver) → Task 1; §3 last-known-good + explain endpoint → Task 2, CLI → Task 3, PR comment → Task 4, MCP → Task 5; §4 testing/DoD → each task's tests + Task 6. Advisory-only (no lockfile mutation) is a global constraint honored across all surfaces. Invariant #1 (remediate pure, never feeds score) in Task 1 + reaffirmed in Task 6.
- **Type consistency:** `Remediation`/`RemediationItem`/`WaiverTemplate` + `remediate`/`remediationHint` (Task 1) consumed by the explain route (Task 2), `formatExplain`/`ExplainResult` (Task 3), `renderPrComment` (Task 4), and the mcp tool (Task 5); `ExplainResult { report, remediation, lastKnownGood }` shape is identical across the endpoint (Task 2), CLI (Task 3), and MCP (Task 5); `TreePackageRow.topFindingRuleId: string | null` (Task 4) set by the route + read by `renderPrComment`.
- **Known judgment calls:** guidance lives in one `REMEDIATIONS` map (not a field on every rule — keeps rules pure, one place to maintain); the waiver `approveCommand` matches the real `sentinel approve <package> <version> --reason` signature; last-known-good is a bounded 10-version window off the gate path; `remediationHint` (a short `ruleId → action`) is the cheap PR-comment projection so the batch path needs no extra audits; `topFindingRuleId` is required (not optional) on `TreePackageRow` so every builder + test literal sets it (mechanical, like Phase 14's `integrityMismatch`).
