# Phase 20 — Policy Authoring + Impact Preview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give operators tooling to author, validate, and understand a scoring policy: `sentinel policy init` scaffolds, `policy validate` lints, and `policy preview` replays the durable audit history under a candidate policy to show the verdict deltas.

**Architecture:** A pure `lintPolicy` in `@sentinel/core`; a proxy `POST /-/policy/preview` that re-scores the Phase-15 `HistoryDb`'s stored audits under a candidate policy via the existing pure `score()`; three new CLI subcommands under `sentinel policy`. The live scoring path is untouched — the preview is the deterministic scorer replayed.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; reuses `@sentinel/core` (`score`, `parsePolicy`, `DEFAULT_POLICY`, `severityRank`); `node:test` via `tsx`. No new dependencies.

## Global Constraints

- **`lintPolicy` is pure** — a function of the `EnterprisePolicy` only; no I/O, no scoring, no clock. Same policy ⇒ same result.
- **The preview replays the deterministic scorer** — `POST /-/policy/preview` re-scores stored audits via `score(audit, candidatePolicy)`; a `ScoredFinding` IS a `Finding`, so a stored `AuditReport` can be passed to `score()` directly (cast to `Audit`). Same `(audit, policy)` ⇒ same verdict. Invariant #1 untouched; the live scoring path is unchanged.
- **The candidate is a dry-run** — the preview never applies, stores, or requires a signature on the candidate; a malformed candidate ⇒ `400`, no crash.
- **Preview requires history** — no `HistoryDb` ⇒ the explicit `501 { enabled: false }` (reuse the `disabled(res)` helper the metrics routes use). The bounded replay reads at most `HistoryDb.allReports(limit = 1000)`.
- **Lint `LintFinding` = `{ code: string; message: string }`.** `lintPolicy(policy) → { errors: LintFinding[]; warnings: LintFinding[] }`. `validate` exits non-zero iff `errors.length > 0`.
- **Reuse the existing `sentinel policy` group** (`policyCmd`) — add `init`/`validate`/`preview` beside `keygen`/`sign`/`verify`. `init` writes `DEFAULT_POLICY` as pretty JSON.
- ESM only, NodeNext: internal imports use `.js` specifiers; cross-package imports use the package name.
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/<pkg>`.
- Run all commands from repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.

---

### Task 1: Core `lintPolicy`

**Files:**
- Create: `packages/core/src/policy-lint.ts`
- Modify: `packages/core/src/index.ts` (export)
- Test: `packages/core/test/policy-lint.test.ts`

**Interfaces:**
- Consumes: `EnterprisePolicy` (policy.js), `Severity` (types.js), `severityRank` (score.js).
- Produces (used by Tasks 3–4): `lintPolicy(policy: EnterprisePolicy): { errors: LintFinding[]; warnings: LintFinding[] }`; `interface LintFinding { code: string; message: string }`.

- [ ] **Step 1: Write the failing test** (`packages/core/test/policy-lint.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { lintPolicy } from "../src/policy-lint.js";
import { DEFAULT_POLICY } from "../src/policy.js";
import type { EnterprisePolicy } from "../src/policy.js";

function pol(mut: (p: EnterprisePolicy) => void): EnterprisePolicy {
  const p = structuredClone(DEFAULT_POLICY);
  mut(p);
  return p;
}
const codes = (fs: { code: string }[]) => fs.map((f) => f.code);

describe("lintPolicy", () => {
  test("DEFAULT_POLICY is clean (no errors, no warnings)", () => {
    const r = lintPolicy(DEFAULT_POLICY);
    assert.deepEqual(r.errors, []);
    assert.deepEqual(r.warnings, []);
  });

  test("inverted thresholds (allow < warn) → error", () => {
    const r = lintPolicy(pol((p) => { p.scoring.thresholds = { allow: 40, warn: 80 }; }));
    assert.ok(codes(r.errors).includes("threshold-inverted"));
  });

  test("threshold out of 0–100 → error", () => {
    assert.ok(codes(lintPolicy(pol((p) => { p.scoring.thresholds.allow = 140; })).errors).includes("threshold-range"));
  });

  test("bad hardBlockSeverity → error", () => {
    assert.ok(codes(lintPolicy(pol((p) => { (p.scoring as { hardBlockSeverity: string }).hardBlockSeverity = "boom"; })).errors).includes("bad-hard-block-severity"));
  });

  test("negative severityWeight → error", () => {
    assert.ok(codes(lintPolicy(pol((p) => { p.scoring.severityWeight.high = -5; })).errors).includes("bad-severity-weight"));
  });

  test("diffMultiplier <= 0 → error", () => {
    assert.ok(codes(lintPolicy(pol((p) => { p.scoring.diffMultiplier = 0; })).errors).includes("diff-multiplier-nonpositive"));
  });

  test("a package in both deny and allow → error", () => {
    const r = lintPolicy(pol((p) => { p.deny = [{ package: "evil" }]; p.allow = [{ package: "evil", rules: [] }]; }));
    assert.ok(codes(r.errors).includes("deny-allow-conflict"));
  });

  test("non-monotonic severityWeight (low >= high) → warning", () => {
    const r = lintPolicy(pol((p) => { p.scoring.severityWeight.low = 99; }));
    assert.ok(codes(r.warnings).includes("non-monotonic-weights"));
    assert.deepEqual(r.errors, []); // legal, just suspicious
  });

  test("diffMultiplier < 1 → warning", () => {
    assert.ok(codes(lintPolicy(pol((p) => { p.scoring.diffMultiplier = 0.5; })).warnings).includes("diff-multiplier-weak"));
  });

  test("aggressive hardBlockSeverity (low) → warning", () => {
    assert.ok(codes(lintPolicy(pol((p) => { p.scoring.hardBlockSeverity = "low"; })).warnings).includes("aggressive-hard-block"));
  });

  test("threshold-too-low: a lone critical still scores allow → warning", () => {
    // allow so low that (100 - critical weight) >= allow
    const r = lintPolicy(pol((p) => { p.scoring.thresholds = { allow: 10, warn: 5 }; }));
    assert.ok(codes(r.warnings).includes("threshold-too-low"));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/core/test/policy-lint.test.ts
```

Expected: FAIL — `../src/policy-lint.js` not found.

- [ ] **Step 3: Implement `packages/core/src/policy-lint.ts`**

```ts
import type { EnterprisePolicy } from "./policy.js";
import type { Severity } from "./types.js";
import { severityRank } from "./score.js";

export interface LintFinding { code: string; message: string }

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

/**
 * Structural + semantic lint of an EnterprisePolicy. Pure. Errors mark a dangerously-broken
 * policy (an operator should not sign it); warnings are suspicious-but-legal values. Never scores.
 */
export function lintPolicy(policy: EnterprisePolicy): { errors: LintFinding[]; warnings: LintFinding[] } {
  const errors: LintFinding[] = [];
  const warnings: LintFinding[] = [];
  const s = policy.scoring;

  // Thresholds.
  const { allow, warn } = s.thresholds;
  for (const [name, v] of [["allow", allow], ["warn", warn]] as const) {
    if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 100) {
      errors.push({ code: "threshold-range", message: `thresholds.${name} (${v}) must be a number in 0–100.` });
    }
  }
  if (Number.isFinite(allow) && Number.isFinite(warn) && allow < warn) {
    errors.push({ code: "threshold-inverted", message: `thresholds.allow (${allow}) is below thresholds.warn (${warn}) — a package could out-score "allow" yet be classed "warn".` });
  }

  // hardBlockSeverity.
  if (!SEVERITIES.includes(s.hardBlockSeverity)) {
    errors.push({ code: "bad-hard-block-severity", message: `hardBlockSeverity "${s.hardBlockSeverity}" is not one of ${SEVERITIES.join("|")}.` });
  } else if (s.hardBlockSeverity === "info" || s.hardBlockSeverity === "low") {
    warnings.push({ code: "aggressive-hard-block", message: `hardBlockSeverity "${s.hardBlockSeverity}" hard-blocks on trivial findings.` });
  }

  // severityWeight: presence + non-negative + finite.
  for (const sev of SEVERITIES) {
    const w = s.severityWeight[sev];
    if (typeof w !== "number" || !Number.isFinite(w) || w < 0) {
      errors.push({ code: "bad-severity-weight", message: `severityWeight.${sev} (${w}) must be a finite number ≥ 0.` });
    }
  }
  // Monotonicity (only when all weights are valid numbers).
  const weightsOk = SEVERITIES.every((sev) => Number.isFinite(s.severityWeight[sev]) && s.severityWeight[sev] >= 0);
  if (weightsOk) {
    for (let i = 1; i < SEVERITIES.length; i++) {
      const lower = SEVERITIES[i - 1]!, higher = SEVERITIES[i]!;
      if (s.severityWeight[lower] > s.severityWeight[higher]) {
        warnings.push({ code: "non-monotonic-weights", message: `severityWeight.${lower} (${s.severityWeight[lower]}) outweighs severityWeight.${higher} (${s.severityWeight[higher]}).` });
      }
    }
    // A lone critical finding still allows?
    if (Number.isFinite(allow) && 100 - s.severityWeight.critical >= allow) {
      warnings.push({ code: "threshold-too-low", message: `thresholds.allow (${allow}) is low enough that a single critical finding still scores "allow".` });
    }
    // Nothing but a perfect score can be allow?
    if (Number.isFinite(allow) && allow >= 100) {
      warnings.push({ code: "threshold-too-high", message: `thresholds.allow (${allow}) means only a finding-free package can be "allow".` });
    }
  }

  // diffMultiplier.
  if (typeof s.diffMultiplier !== "number" || !Number.isFinite(s.diffMultiplier) || s.diffMultiplier <= 0) {
    errors.push({ code: "diff-multiplier-nonpositive", message: `scoring.diffMultiplier (${s.diffMultiplier}) must be > 0.` });
  } else if (s.diffMultiplier < 1) {
    warnings.push({ code: "diff-multiplier-weak", message: `scoring.diffMultiplier (${s.diffMultiplier}) < 1 weakens the changed-in-this-release signal.` });
  }

  // List hygiene: malformed entries + deny/allow conflict.
  const badEntry = (arr: unknown[], field: string) =>
    arr.some((x) => typeof x !== "string" || x.trim() === "") &&
    errors.push({ code: "malformed-list-entry", message: `${field} has a non-string or empty entry.` });
  badEntry(policy.privateNamespaces ?? [], "privateNamespaces");
  badEntry(policy.requireSignature ?? [], "requireSignature");
  if ((policy.allow ?? []).some((a) => typeof a.package !== "string" || a.package.trim() === "")) {
    errors.push({ code: "malformed-list-entry", message: "allow has an entry with a non-string or empty package." });
  }
  if ((policy.deny ?? []).some((d) => typeof d.package !== "string" || d.package.trim() === "")) {
    errors.push({ code: "malformed-list-entry", message: "deny has an entry with a non-string or empty package." });
  }
  const denySet = new Set((policy.deny ?? []).map((d) => d.package));
  for (const a of policy.allow ?? []) {
    if (denySet.has(a.package)) {
      errors.push({ code: "deny-allow-conflict", message: `"${a.package}" is in both allow and deny.` });
    }
  }

  void severityRank; // (kept import parity; SEVERITIES ordering above is the source of truth)
  return { errors, warnings };
}
```

(If the unused `severityRank` import trips lint/build, drop it and the `void severityRank;` line — `SEVERITIES` ordering is self-contained. Keep only if it compiles cleanly.)

- [ ] **Step 4: Export from `packages/core/src/index.ts`**

```ts
export { lintPolicy, type LintFinding } from "./policy-lint.js";
```

- [ ] **Step 5: Run the test + build**

```bash
npm run build
npx tsx --test packages/core/test/policy-lint.test.ts
```

Expected: PASS (11/11). Then a quick full `npm test`.

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/policy-lint.ts packages/core/src/index.ts packages/core/test/policy-lint.test.ts
git commit -m "feat(phase20): lintPolicy — structural + semantic policy linter (pure)"
```

---

### Task 2: `HistoryDb.allReports`

**Files:**
- Modify: `packages/proxy/src/history-db.ts` (`allReports` method)
- Test: `packages/proxy/test/history-db-queries.test.ts` (extend) or the existing history-db test

**Interfaces:**
- Consumes: the stored `report_json` column.
- Produces (used by Task 3): `HistoryDb.allReports(limit = 1000): AuditReport[]`.

- [ ] **Step 1: Extend the failing test** — in the history-db query test (find it: `ls packages/proxy/test | grep history`), add:

```ts
test("allReports returns the stored AuditReports, newest-first, bounded by limit", () => {
  const db = new HistoryDb(":memory:");
  const rep = (integrity: string, name: string, verdict: "allow" | "block"): AuditReport =>
    ({ schema: 3, meta: { name, version: "1.0.0", integrity, signature: "unsigned", provenance: "absent" }, score: verdict === "block" ? 10 : 100, verdict, findings: [] } as unknown as AuditReport);
  db.recordAudit(rep("sha512-1", "a", "allow"), "2026-07-01T00:00:00Z");
  db.recordAudit(rep("sha512-2", "b", "block"), "2026-07-02T00:00:00Z");
  const all = db.allReports();
  assert.equal(all.length, 2);
  assert.equal(all.every((r) => r.schema === 3), true);
  assert.equal(all[0]!.meta.name, "b"); // newest-first
  assert.equal(db.allReports(1).length, 1); // limit caps
  db.close();
});
```

(Ensure `AuditReport` is imported from `@sentinel/core` in that test file.)

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/history-db-queries.test.ts
```

Expected: FAIL — `allReports` is not a method.

- [ ] **Step 3: Add the method to `HistoryDb`** (`packages/proxy/src/history-db.ts`, near the other query methods)

```ts
  /** All stored audit reports, newest-first, bounded. For policy-impact replay (Phase 20). */
  allReports(limit = 1000): AuditReport[] {
    const rows = this.db.prepare(`SELECT report_json FROM audit_events ORDER BY audited_at DESC LIMIT ?`).all(limit);
    const out: AuditReport[] = [];
    for (const r of rows) {
      try { out.push(JSON.parse(r.report_json as string) as AuditReport); } catch { /* skip a corrupt row */ }
    }
    return out;
  }
```

(`AuditReport` is already imported in `history-db.ts` — it's used by `recordAudit`. Confirm; if not, add `import type { AuditReport } from "@sentinel/core";`.)

- [ ] **Step 4: Build + run the test**

```bash
npm run build
npx tsx --test packages/proxy/test/history-db-queries.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/history-db.ts packages/proxy/test/history-db-queries.test.ts
git commit -m "feat(phase20): HistoryDb.allReports — bounded newest-first report replay corpus"
```

---

### Task 3: Proxy `POST /-/policy/preview`

**Files:**
- Modify: `packages/proxy/src/server.ts` (the preview route)
- Test: `packages/proxy/test/policy-preview-e2e.test.ts`

**Interfaces:**
- Consumes: `history` (in `createServer` scope), `score` + `parsePolicy` + `type EnterprisePolicy` + `type Audit` (`@sentinel/core`), the `disabled(res)` helper.
- Produces (used by Task 4): `POST /-/policy/preview` → `{ enabled: false }` (501) OR `{ enabled: true, total, transitions, changed }`.

- [ ] **Step 1: Write the failing e2e** (`packages/proxy/test/policy-preview-e2e.test.ts`) — boot the in-process proxy WITH a `:memory:` HistoryDb, seed reports via `history.recordAudit`, POST candidate policies.

```ts
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
import type { AuditReport, EnterprisePolicy } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import { HistoryDb } from "../src/history-db.js";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "fixtures");

// A report with ONE high-severity finding: scores 75 under DEFAULT (high weight 25) → allow (>=80? no).
// Use meta+findings the scorer will re-weight. We craft findings so a stricter candidate flips the verdict.
function reportWith(name: string, integrity: string, severity: "high" | "info"): AuditReport {
  return {
    schema: 3,
    meta: { name, version: "1.0.0", integrity, signature: "unsigned", provenance: "absent", author: null, maintainers: [], license: "MIT", hasInstallScripts: false, unpackedSize: 1, fileCount: 1 },
    score: 100, verdict: "allow",
    findings: severity === "high" ? [{ ruleId: "network-egress", category: "network", severity: "high", message: "x", onChangedFile: false, evidence: [], weight: 25, waived: false }] : [],
    capabilities: [], capabilityDelta: null,
    engine: { version: "0.1.0", rules: [], llm: null, mode: "full" }, llmSummary: null,
    auditedAt: "2026-07-01T00:00:00Z", durationMs: 0, policy: { version: "default", hash: "h" },
  } as unknown as AuditReport;
}

function boot(withHistory: boolean): Promise<{ server: Server; base: string; history?: HistoryDb }> {
  const history = withHistory ? new HistoryDb(":memory:") : undefined;
  if (history) {
    // seed: one clean (no findings → allow under any sane policy) + one with a high finding.
    history.recordAudit(reportWith("clean", "sha512-a", "info"), "2026-07-01T00:00:00Z");
    history.recordAudit(reportWith("risky", "sha512-b", "high"), "2026-07-02T00:00:00Z");
  }
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(), history,
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, history })); });
}
const preview = async (base: string, policy: unknown) =>
  (await fetch(`${base}/-/policy/preview`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ policy }) }));

describe("POST /-/policy/preview (e2e)", () => {
  test("a stricter candidate flips the risky audit's verdict; the clean one is unchanged", async () => {
    const { server, base, history } = await boot(true);
    // Stricter: raise the allow threshold so the high-finding package (score 75) drops below allow.
    const strict: EnterprisePolicy = structuredClone(DEFAULT_POLICY);
    strict.scoring.thresholds = { allow: 80, warn: 50 }; // 75 < 80 → not allow; 75 >= 50 → warn
    const r = await (await preview(base, strict)).json() as { enabled: boolean; total: number; transitions: Record<string, number>; changed: { name: string; from: string; to: string }[] };
    assert.equal(r.enabled, true);
    assert.equal(r.total, 2);
    assert.ok(r.transitions.allowToWarn >= 1);
    assert.ok(r.changed.some((c) => c.name === "risky" && c.from === "allow" && c.to === "warn"));
    assert.equal(r.changed.some((c) => c.name === "clean"), false); // clean stays allow
    server.close(); history?.close();
  });

  test("an identical candidate → all unchanged, changed empty (faithful replay)", async () => {
    const { server, base, history } = await boot(true);
    const r = await (await preview(base, DEFAULT_POLICY)).json() as { total: number; transitions: { unchanged: number }; changed: unknown[] };
    assert.equal(r.transitions.unchanged, r.total);
    assert.equal(r.changed.length, 0);
    server.close(); history?.close();
  });

  test("no history → 501 { enabled: false }", async () => {
    const { server, base } = await boot(false);
    const res = await preview(base, DEFAULT_POLICY);
    assert.equal(res.status, 501);
    assert.equal(((await res.json()) as { enabled: boolean }).enabled, false);
    server.close();
  });

  test("a malformed candidate policy → 400", async () => {
    const { server, base, history } = await boot(true);
    const res = await preview(base, { not: "a policy" });
    assert.equal(res.status, 400);
    server.close(); history?.close();
  });
});
```

(Note: the DEFAULT_POLICY thresholds are `{ allow: 80, warn: 50 }` per `score.ts`; the "stricter" candidate in test 1 keeps allow at 80 but the *seeded* report re-scores to 75 (100 − high 25) → `warn`. If DEFAULT already scores the high-finding package as `warn`, the seed's stored verdict is `allow` (we set it), so the transition still shows allow→warn on replay. Confirm the seeded verdicts vs the re-scored verdicts produce a real transition; adjust the candidate thresholds if the exact numbers differ.)

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/policy-preview-e2e.test.ts
```

Expected: FAIL — `/-/policy/preview` 404s.

- [ ] **Step 3: Add the route in `server.ts`** (near the other `/-/policy`/metrics routes; `history` and `disabled` are in scope). Import `score`, `parsePolicy`, `type Audit` from `@sentinel/core`:

```ts
  app.post("/-/policy/preview", (req, res) => {
    if (!history) return disabled(res);
    let candidate;
    try {
      candidate = parsePolicy(Buffer.from(JSON.stringify((req.body as { policy?: unknown }).policy ?? {})));
    } catch {
      return res.status(400).json({ error: "invalid candidate policy" });
    }
    const transitions = { allowToWarn: 0, allowToBlock: 0, warnToAllow: 0, warnToBlock: 0, blockToAllow: 0, blockToWarn: 0, unchanged: 0 };
    const changed: { name: string; version: string; from: string; to: string; fromScore: number; toScore: number }[] = [];
    for (const report of history.allReports()) {
      let to;
      try {
        to = score(report as unknown as Audit, candidate);
      } catch { continue; } // skip an un-scoreable stored report (invariant #6)
      const from = report.verdict;
      if (to.verdict === from) { transitions.unchanged++; continue; }
      const key = `${from}To${to.verdict[0]!.toUpperCase()}${to.verdict.slice(1)}` as keyof typeof transitions;
      if (key in transitions) transitions[key]++;
      changed.push({ name: report.meta.name, version: report.meta.version, from, to: to.verdict, fromScore: report.score, toScore: to.score });
    }
    const rank: Record<string, number> = { block: 0, warn: 1, allow: 2 };
    changed.sort((a, b) => (rank[a.to]! - rank[b.to]!) || (a.toScore - b.toScore));
    res.json({ enabled: true, total: transitions.unchanged + changed.length, transitions, changed: changed.slice(0, 100) });
  });
```

- [ ] **Step 4: Build + run the e2e + existing proxy suite**

```bash
npm run build
npx tsx --test packages/proxy/test/policy-preview-e2e.test.ts
```

Expected: PASS. (If the transition-key composition or the seed verdicts don't line up, adjust the candidate thresholds / seed so a real transition occurs — the mechanism is what's under test.)

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/policy-preview-e2e.test.ts
git commit -m "feat(phase20): POST /-/policy/preview — replay history under a candidate policy (deterministic)"
```

---

### Task 4: CLI `policy init` / `validate` / `preview`

**Files:**
- Modify: `packages/cli/src/index.ts` (three subcommands under `policyCmd`)
- Modify: `packages/cli/src/format.ts` (`formatLint`, `formatPreview`)
- Test: `packages/cli/test/policy-authoring-cli-e2e.test.ts`

**Interfaces:**
- Consumes: `lintPolicy` + `parsePolicy` + `DEFAULT_POLICY` (`@sentinel/core`); `POST /-/policy/preview` (Task 3).
- Produces: `sentinel policy init`, `sentinel policy validate <file>`, `sentinel policy preview <candidate>`.

- [ ] **Step 1: Write the failing e2e** (`packages/cli/test/policy-authoring-cli-e2e.test.ts`) — async `execFile`; for `preview`, boot an in-process proxy with a seeded `:memory:` HistoryDb (model on the Task 3 boot + an existing CLI e2e). Assert:
- `policy init --out <tmp>/p.json` writes a file; `policy validate <tmp>/p.json` exits 0 (the default is clean).
- a hand-written bad policy (inverted thresholds) → `policy validate` exits non-zero and prints the error code/message.
- `policy preview <candidate> -p <base>` against the seeded proxy prints the transition summary; against a no-history proxy prints "history not enabled".

```ts
// Skeleton — fill boot/run helpers from an existing CLI e2e + the Task 3 boot:
//   init: runCli(["policy","init","--out",p]) → existsSync(p); JSON.parse(p) is a policy
//   validate clean: runCli(["policy","validate",p]) → code 0
//   validate bad: write a policy with thresholds {allow:40,warn:80}; runCli(["policy","validate",bad]) → code !== 0, stdout/stderr matches /threshold-inverted/
//   preview: boot proxy w/ seeded :memory: history; runCli(["policy","preview",p,"-p",base]) → stdout matches /replayed|would change|unchanged/
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/cli/test/policy-authoring-cli-e2e.test.ts
```

Expected: FAIL — the subcommands don't exist.

- [ ] **Step 3: Add the subcommands under `policyCmd` in `packages/cli/src/index.ts`** (mirror the existing `sign`/`verify` shape). Import `lintPolicy`, `DEFAULT_POLICY` from `@sentinel/core`; `formatLint`, `formatPreview` from `./format.js`:

```ts
policyCmd
  .command("init")
  .description("Scaffold a policy file from the built-in default (edit, then validate + sign).")
  .requiredOption("--out <file>", "where to write the policy JSON")
  .action((opts: { out: string }) => {
    writeFileSync(opts.out, JSON.stringify(DEFAULT_POLICY, null, 2) + "\n");
    console.log(`wrote ${opts.out}\nnext: edit weights/thresholds/namespaces → \`sentinel policy validate ${opts.out}\` → \`sentinel policy sign ${opts.out} --key <priv>\``);
  });

policyCmd
  .command("validate")
  .description("Parse + lint a policy file. Exits non-zero if it has errors.")
  .argument("<file>", "path to the policy JSON")
  .action((file: string) => {
    let policy;
    try {
      policy = parsePolicy(readFileSync(file));
    } catch (err) {
      console.error(`✗ ${(err as Error).message}`);
      process.exit(2);
    }
    const r = lintPolicy(policy);
    console.log(formatLint(r));
    if (r.errors.length) process.exitCode = 2;
  });

policyCmd
  .command("preview")
  .description("Replay the proxy's audit history under a candidate policy and show the verdict deltas.")
  .argument("<file>", "path to the candidate policy JSON")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .action(async (file: string, opts: { proxy: string }) => {
    let policy;
    try { policy = parsePolicy(readFileSync(file)); } catch (err) { return fail(err, opts.proxy); }
    const res = await fetch(`${opts.proxy}/-/policy/preview`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ policy }) });
    if (res.status === 501) { console.log("history not enabled — set SENTINEL_HISTORY_DB on the proxy to preview impact."); return; }
    if (!res.ok) return fail(new Error(`preview failed: ${res.status}`), opts.proxy);
    console.log(formatPreview(await res.json() as PreviewResult));
  });
```

Add to `packages/cli/src/format.ts` (pure):

```ts
import type { LintFinding } from "@sentinel/core";

export function formatLint(r: { errors: LintFinding[]; warnings: LintFinding[] }): string {
  const L: string[] = [];
  for (const e of r.errors) L.push(c(C.red, `  ✗ ${e.code}: ${e.message}`));
  for (const w of r.warnings) L.push(c(C.yellow, `  ⚠ ${w.code}: ${w.message}`));
  if (!r.errors.length && !r.warnings.length) L.push(c(C.green, "  ✓ policy is valid — no issues."));
  else L.push(`  ${r.errors.length} error(s), ${r.warnings.length} warning(s).`);
  return L.join("\n");
}

export interface PreviewResult {
  enabled: boolean;
  total: number;
  transitions: Record<string, number>;
  changed: { name: string; version: string; from: string; to: string; fromScore: number; toScore: number }[];
}

export function formatPreview(r: PreviewResult): string {
  const L: string[] = ["", `  ${r.total} audit(s) replayed · ${c(C.bold, String(r.changed.length))} would change`, ""];
  const t = r.transitions;
  const parts = Object.entries(t).filter(([k, v]) => k !== "unchanged" && v > 0).map(([k, v]) => `${k}: ${v}`);
  if (parts.length) L.push("  " + parts.join(" · "));
  L.push("");
  for (const ch of r.changed) {
    L.push(`  ${ch.name}@${ch.version}  ${c(verdictColor[ch.from] ?? C.gray, ch.from)} → ${c(verdictColor[ch.to] ?? C.gray, ch.to)}  (${ch.fromScore} → ${ch.toScore})`);
  }
  if (r.changed.length) L.push("");
  return L.join("\n");
}
```

(Import `formatLint`/`formatPreview`/`PreviewResult` into `index.ts`; ensure `c`/`C`/`verdictColor` are in scope in `format.ts` — they already are.)

- [ ] **Step 4: Build + run the e2e + full suite**

```bash
npm run build
npx tsx --test packages/cli/test/policy-authoring-cli-e2e.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS; record counts.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/index.ts packages/cli/src/format.ts packages/cli/test/policy-authoring-cli-e2e.test.ts
git commit -m "feat(phase20): sentinel policy init/validate/preview CLI"
```

---

### Task 5: Docs, ADR-0033, final verification

**Files:**
- Create: `docs/adr/0033-policy-authoring-impact-preview.md`
- Modify: `ARCHITECTURE.md` (the policy lint + impact-preview layer)
- Modify: `CLAUDE.md` (What-this-is phase list; `policy init/validate/preview`; test-count line)
- Modify: `README.md` (the policy authoring + preview workflow)

- [ ] **Step 1: Write ADR-0033** — follow the style of `docs/adr/0027-ecosystem-breadth-sbom.md`. Required content: **Context** (the policy governs every verdict but is hand-authored JSON with only keygen/sign/verify tooling — no scaffold, no lint, no impact insight; a bad value silently re-scores everything). **Decision** (a pure `lintPolicy` (structural + semantic, errors vs warnings); a proxy `POST /-/policy/preview` that replays the Phase-15 HistoryDb audits under a candidate via the existing pure `score()` — a `ScoredFinding` is a `Finding`, so a stored report re-scores directly; `sentinel policy init`/`validate`/`preview`; the preview is a dry-run, never applies/signs the candidate; requires history). **Determinism** (the preview IS the deterministic scorer replayed — same inputs ⇒ same verdict; `lintPolicy` pure; invariant #1 exercised not endangered). **Consequences** (answers "what will this policy change do?" before signing; requires the opt-in HistoryDb; the replay is bounded (allReports limit); the live scoring path is untouched). **Deferred** (auto-apply/hot-reload; a visual editor; `policy diff A B` text diff; preview-against-a-lockfile; an auto-tuner). **Rejected** (CLI-side replay shipping all report_json to the client — heavier, leaks the full history; a policy field on every rule). **VERIFY** any policy/history ADR number you cite with `head -1 docs/adr/00*.md | grep -iE "policy|history|observability|scoring"` before citing; extends ADR-0002.

- [ ] **Step 2: ARCHITECTURE.md** — document `lintPolicy` (pure, errors/warnings), the `/-/policy/preview` replay endpoint (re-score HistoryDb audits under a candidate, bounded, off-gate), and the `sentinel policy init/validate/preview` commands. Note invariant #1 is exercised, the live scoring path unchanged, and preview requires history.

- [ ] **Step 3: CLAUDE.md** — add the Phase 20 sentence to "What this is" (mirror recent-phase density). Note `sentinel policy init/validate/preview` in the CLI list. Update the `npm test` count to the ACTUAL number from Step 5 (preserve darwin-skip caveats).

- [ ] **Step 4: README.md** — document the policy authoring workflow: `sentinel policy init --out <f>` → edit → `sentinel policy validate <f>` (lint, CI-gate) → `sentinel policy preview <f> -p <proxy>` (impact against history) → `sentinel policy sign`. Note preview needs `SENTINEL_HISTORY_DB` on the proxy.

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
git commit -m "docs(phase20): ADR-0033 policy authoring + impact preview; ARCHITECTURE/CLAUDE/README"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 architecture → Task 1 (lintPolicy) + Task 3 (preview endpoint); §2 lint rules + validate/init → Task 1 (lintPolicy) + Task 4 (init/validate CLI); §3 preview endpoint + replay + CLI → Task 2 (allReports) + Task 3 (route) + Task 4 (preview CLI); §4 testing/DoD → each task's tests + Task 5. The disabled-when-no-history (501) is Task 3; the deterministic-replay/invariant #1 is Task 3 (`score()` reuse) + reaffirmed Task 5.
- **Type consistency:** `lintPolicy(policy): { errors: LintFinding[]; warnings: LintFinding[] }` + `LintFinding` (Task 1) consumed by the CLI `validate` + `formatLint` (Task 4); `HistoryDb.allReports(limit)` (Task 2) consumed by the preview route (Task 3); the preview response shape `{ enabled, total, transitions, changed }` produced by Task 3 and consumed by `formatPreview`/`PreviewResult` (Task 4). `transitions` keys (`allowToWarn`… `unchanged`) consistent between the route (Task 3) and the formatter (Task 4).
- **Known judgment calls:** the preview re-scores by casting the stored `AuditReport` to `Audit` (a `ScoredFinding` is a `Finding`, so `score()` reads the base fields and recomputes) — no manual reconstruction; the preview runs server-side (keeps `report_json` in the HistoryDb, reuses `score()`); lint errors vs warnings are split so `validate` is a clean CI gate (non-zero only on errors); the `threshold-too-low`/`too-high` heuristics are computed against the weights (a lone critical still allowing / only a perfect score allowing); the candidate is structurally validated via `parsePolicy` so a malformed body is `400`, not a crash.
