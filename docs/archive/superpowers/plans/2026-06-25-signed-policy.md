# Signed Per-Enterprise Policy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Externalize the hard-coded `POLICY` into a versioned, Ed25519-signed per-enterprise policy document; make scoring policy-dependent (computed at score time, not baked into findings) while keeping audit findings policy-independent and integrity-cached.

**Architecture:** Split the engine into a policy-independent `runAudit` (findings + capabilities, cached by integrity) and a pure `score(audit, policy)` that applies weights, rule toggles, allow/deny waivers, thresholds, and the hard-block override. The proxy loads one signed policy at startup (fail-closed), scores every audit under it, and stamps `policy:{version,hash}` on each report. `auditTarball` survives as `score(runAudit(...), DEFAULT_POLICY)` so the offline CLI and existing tests are unaffected.

**Tech Stack:** Node 24 (≥22), TypeScript (NodeNext, ESM, `.js` import specifiers), `node:crypto` (Ed25519), Express 5, `commander` 15, tests on `node:test` + `tsx`.

## Global Constraints

- ESM only (`"type": "module"`); internal imports use `.js` specifiers even from `.ts` sources.
- **No new runtime dependencies** — signing/verification use `node:crypto` (Ed25519) only.
- **Findings are policy-independent**: `runAudit` produces `Finding[]` carrying `severity` + `onChangedFile` (a boolean), never a baked weight. Weight is computed only in `score()`.
- **Naming:** the signed scoring policy type is `EnterprisePolicy` / variable `enterprisePolicy` everywhere. NEVER bare `Policy`/`policy` — the proxy already has `ProxyPolicy` (`"observe"|"block"`) and a `policy` variable, and the `SENTINEL_POLICY` env var already means the proxy mode. The new env vars are `SENTINEL_POLICY_FILE`, `SENTINEL_POLICY_SIG`, `SENTINEL_POLICY_PUBKEY`.
- **`auditTarball` survives** as `score(runAudit(input), DEFAULT_POLICY)`; under `DEFAULT_POLICY` the weights/score/verdict equal today's values exactly.
- **Fail closed**: a configured-but-invalid policy (missing file, parse error, bad signature, no pubkey, schema-invalid) must make the proxy exit non-zero at startup — never silently fall back to `DEFAULT_POLICY`. No policy configured → use `DEFAULT_POLICY` and log it.
- **Sign raw bytes**: verification is `crypto.verify(null, rawBytes, pubKey, sig)` over the file as-is; `policyHash = sha256(rawBytes)`. The in-code `DEFAULT_POLICY` (no file) is hashed via canonical JSON instead.
- **Glob matching** for `package` patterns is anchored full-name, `*` the only metacharacter, all other regex metacharacters escaped. Not substring, not regex passthrough.
- Determinism invariant is **superseded, not edited** (CLAUDE.md): "same bytes + same policy ⇒ same verdict." Keep `scoring is deterministic across runs` green by going through `auditTarball`/`DEFAULT_POLICY`.
- The malicious `color-stream@1.4.1` fixture must stay **blocked under the default policy**.
- Build with `npx tsc --build --force <pkg>` if `rm` of `dist/` fails with EPERM.

**Commands:**
- Build: `npm run build`  ·  Full suite: `npm test`  (`node --import tsx --test packages/**/test/*.test.ts`)
- Single file: `node --import tsx --test packages/core/test/score.test.ts`
- Single test by name: `node --import tsx --test --test-name-pattern "<name>" <file>`

---

## File structure

**Create:**
- `packages/core/src/policy.ts` — `EnterprisePolicy` type, `DEFAULT_POLICY`, `policyHashOf`, `matchPackage` (glob), and (Task 3) signing/loading helpers.
- `packages/core/test/score.test.ts` — scoring-with-policy unit tests.
- `packages/core/test/policy.test.ts` — signing/loading/glob unit tests.
- `packages/cli/test/policy.test.ts` — CLI `policy` command + core helper round-trip tests.
- `docs/adr/0014-score-time-policy-and-raw-bytes-signing.md`.

**Modify:**
- `packages/core/src/types.ts` — `Finding` (drop `weight`, add `onChangedFile`), add `ScoredFinding`, `Audit`; `AuditReport` (schema 3, `findings: ScoredFinding[]`, `policy`).
- `packages/core/src/rules/util.ts` — `mkFinding` drops weight, sets `onChangedFile`; drop the `POLICY` import.
- `packages/core/src/score.ts` — replace `POLICY`/`scoreFindings`/`verdictFor` with `score(audit, policy, hash?)` + `severityRank`.
- `packages/core/src/audit.ts` — split into `buildAudit`/`runAudit` (policy-independent) + `auditTarball = score(runAudit, DEFAULT_POLICY)`.
- `packages/core/src/index.ts` — export the new policy/score API + types.
- `packages/core/test/audit.test.ts`, `packages/core/test/capabilities.test.ts` — update for schema 3 and the `Finding`→`ScoredFinding` shape.
- `packages/proxy/src/store.ts` — `schema: 3` guard + active-policy-hash load filter.
- `packages/proxy/src/server.ts` — `enterprisePolicy` in `ServerOptions`; `auditVersion` uses `runAudit`+`score`; `x-sentinel-policy` header.
- `packages/proxy/src/index.ts` — env-driven `loadPolicy` (fail-closed); pass `enterprisePolicy`+hash.
- `packages/proxy/test/proxy.test.ts` — pass `enterprisePolicy` to both `createServer` calls; add policy gate tests.
- `scripts/demo.ts` — pass `enterprisePolicy: DEFAULT_POLICY`.
- `packages/cli/src/index.ts` — `sentinel policy` command (verify/sign/keygen).
- `ARCHITECTURE.md`, `CLAUDE.md`, `docs/adr/0012-…md`, `docs/adr/0008-…md`.

---

## Task 1: Core split — policy-independent audit + base scoring

**Files:**
- Modify: `packages/core/src/types.ts`, `packages/core/src/rules/util.ts`, `packages/core/src/score.ts`, `packages/core/src/audit.ts`, `packages/core/src/index.ts`
- Create: `packages/core/src/policy.ts`
- Modify (tests): `packages/core/test/audit.test.ts`, `packages/core/test/capabilities.test.ts`

**Interfaces:**
- Produces:
  - `Finding = { ruleId, category, severity, message, onChangedFile: boolean, evidence }` (no `weight`).
  - `ScoredFinding = Finding & { weight: number; waived: boolean; waivedBy?: string }`.
  - `Audit = { schema: 3, meta, findings: Finding[], capabilities, capabilityDelta, engine: {version, rules, mode}, auditedAt, durationMs }`.
  - `AuditReport = { schema: 3, meta, score, verdict, findings: ScoredFinding[], capabilities, capabilityDelta, engine, llmSummary, auditedAt, durationMs, policy: {version, hash} }`.
  - `EnterprisePolicy`, `DEFAULT_POLICY`, `policyHashOf(policy): string`, `matchPackage(pattern, name): boolean` (in `policy.ts`).
  - `score(audit: Audit, policy?: EnterprisePolicy, hash?: string): AuditReport`, `severityRank(s): number` (in `score.ts`).
  - `buildAudit(meta, files, opts): Audit`, `runAudit(input: AuditTarballInput): Promise<Audit>`, `auditTarball(input): Promise<AuditReport>` (in `audit.ts`).

This task lands the whole split atomically (intermediate states do not compile). Under `DEFAULT_POLICY` the numbers equal today's, so the existing core tests stay green after the shape updates below.

- [ ] **Step 1: Rewrite the type model**

In `packages/core/src/types.ts`, replace the `Finding` interface (lines 29-37) with:

```ts
export interface Finding {
  ruleId: string;
  category: Category;
  severity: Severity;
  message: string;
  /** True if any cited evidence is in a file added/changed vs the diff baseline. */
  onChangedFile: boolean;
  evidence: Evidence[];
}

/** A finding after a policy has been applied (weight computed, waivers resolved). */
export interface ScoredFinding extends Finding {
  /** Points deducted (0 when waived). */
  weight: number;
  waived: boolean;
  waivedBy?: string;
}
```

Replace the `AuditReport` interface (lines 74-95) with both the policy-independent `Audit` and the scored `AuditReport`:

```ts
/** Policy-independent audit: what is cached by integrity. */
export interface Audit {
  schema: 3;
  meta: PackageMeta;
  findings: Finding[];
  capabilities: Capability[];
  capabilityDelta: CapabilityDelta | null;
  engine: { version: string; rules: string[]; mode: "full" | "diff" };
  auditedAt: string;
  durationMs: number;
}

export interface AuditReport {
  schema: 3;
  meta: PackageMeta;
  /** 0–100, where 100 is "no detected risk". */
  score: number;
  verdict: Verdict;
  findings: ScoredFinding[];
  capabilities: Capability[];
  capabilityDelta: CapabilityDelta | null;
  engine: { version: string; rules: string[]; llm: string | null; mode: "full" | "diff" };
  llmSummary: string | null;
  auditedAt: string;
  durationMs: number;
  /** The policy under which this report was scored. */
  policy: { version: string; hash: string };
}
```

- [ ] **Step 2: Create `policy.ts` (type + default + hash + glob)**

Create `packages/core/src/policy.ts`:

```ts
import { createHash } from "node:crypto";
import type { Severity } from "./types.js";

export interface EnterprisePolicy {
  schema: 1;
  /** Free-form version string recorded on every verdict. */
  version: string;
  scoring: {
    severityWeight: Record<Severity, number>;
    diffMultiplier: number;
    thresholds: { allow: number; warn: number };
    hardBlockSeverity: Severity;
  };
  rules: { disabled: string[] };
  allow: { package: string; rules: string[]; reason?: string }[];
  deny: { package: string; reason?: string }[];
}

/** Compiled-in default. Equals the historical POLICY so out-of-the-box behavior is unchanged. */
export const DEFAULT_POLICY: EnterprisePolicy = {
  schema: 1,
  version: "default",
  scoring: {
    severityWeight: { info: 0, low: 4, medium: 12, high: 25, critical: 55 },
    diffMultiplier: 1.6,
    thresholds: { allow: 80, warn: 50 },
    hardBlockSeverity: "critical",
  },
  rules: { disabled: [] },
  allow: [],
  deny: [],
};

/** Stable hash of a policy OBJECT (used for the in-code default; external policies hash raw bytes). */
export function policyHashOf(policy: EnterprisePolicy): string {
  return "sha256-" + createHash("sha256").update(canonicalJSON(policy)).digest("hex");
}

function canonicalJSON(v: unknown): string {
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  if (v && typeof v === "object") {
    return "{" + Object.keys(v as object).sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalJSON((v as Record<string, unknown>)[k]))
      .join(",") + "}";
  }
  return JSON.stringify(v);
}

/** Anchored full-name glob: `*` is the only metacharacter; everything else is literal. */
export function matchPackage(pattern: string, name: string): boolean {
  const re = new RegExp("^" + pattern.split("*").map(escapeRe).join(".*") + "$");
  return re.test(name);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
```

- [ ] **Step 3: Rewrite `score.ts` to apply a policy**

Replace the entire contents of `packages/core/src/score.ts` with:

```ts
import type { Audit, AuditReport, ScoredFinding, Severity, Verdict } from "./types.js";
import { DEFAULT_POLICY, matchPackage, policyHashOf, type EnterprisePolicy } from "./policy.js";

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/**
 * Apply an EnterprisePolicy to a policy-independent {@link Audit}, producing the
 * scored {@link AuditReport}. Pure: same (audit, policy) ⇒ same report. Waived
 * findings stay visible but are excluded from BOTH the penalty sum and the
 * hard-block check.
 */
export function score(
  audit: Audit,
  policy: EnterprisePolicy = DEFAULT_POLICY,
  hash: string = policyHashOf(policy),
): AuditReport {
  const disabled = new Set(policy.rules.disabled);
  const scored: ScoredFinding[] = audit.findings.map((f) => {
    let waived = false;
    let waivedBy: string | undefined;
    if (disabled.has(f.ruleId)) {
      waived = true;
      waivedBy = `rule disabled: ${f.ruleId}`;
    } else {
      const allow = policy.allow.find(
        (a) => matchPackage(a.package, audit.meta.name) && a.rules.some((r) => r === f.ruleId || r === f.category),
      );
      if (allow) {
        waived = true;
        waivedBy = `allow: ${allow.package}${allow.reason ? ` — ${allow.reason}` : ""}`;
      }
    }
    const base = policy.scoring.severityWeight[f.severity];
    const weight = waived ? 0 : Math.round(base * (f.onChangedFile ? policy.scoring.diffMultiplier : 1));
    return { ...f, weight, waived, waivedBy };
  });

  const penalty = scored.reduce((s, f) => s + Math.max(0, f.weight), 0);
  const value = clamp(Math.round(100 - penalty), 0, 100);
  const denied = policy.deny.some((d) => matchPackage(d.package, audit.meta.name));
  const hardBlock = scored.some(
    (f) => !f.waived && severityRank(f.severity) >= severityRank(policy.scoring.hardBlockSeverity),
  );

  let verdict: Verdict;
  if (denied || hardBlock) verdict = "block";
  else if (value >= policy.scoring.thresholds.allow) verdict = "allow";
  else if (value >= policy.scoring.thresholds.warn) verdict = "warn";
  else verdict = "block";

  return {
    schema: 3,
    meta: audit.meta,
    score: value,
    verdict,
    findings: scored.sort((a, b) => b.weight - a.weight),
    capabilities: audit.capabilities,
    capabilityDelta: audit.capabilityDelta,
    engine: { ...audit.engine, llm: null },
    llmSummary: null,
    auditedAt: audit.auditedAt,
    durationMs: audit.durationMs,
    policy: { version: policy.version, hash },
  };
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}
```

- [ ] **Step 4: `mkFinding` records `onChangedFile`, no weight**

In `packages/core/src/rules/util.ts`: remove the `import { POLICY } from "../score.js";` line, and replace the `mkFinding` function (lines 43-65) with:

```ts
/**
 * Construct a finding. Records whether any cited file is new/changed in this
 * release (`onChangedFile`); the diff multiplier and severity weight are applied
 * later in `score()`, not here, so findings stay policy-independent.
 */
export function mkFinding(args: {
  ruleId: string;
  category: Category;
  severity: Severity;
  message: string;
  evidence: Evidence[];
  files: PackageFile[];
}): Finding {
  const changedPaths = new Set(args.files.filter((f) => f.changed).map((f) => f.path));
  const onChangedFile = args.evidence.some((e) => changedPaths.has(e.file));
  return {
    ruleId: args.ruleId,
    category: args.category,
    severity: args.severity,
    message: args.message,
    onChangedFile,
    evidence: args.evidence,
  };
}
```

(The four rule files call `mkFinding` with the same args and are unchanged.)

- [ ] **Step 5: Split `audit.ts` into `buildAudit`/`runAudit` + `auditTarball`**

In `packages/core/src/audit.ts`, update imports — replace the `scoreFindings, verdictFor` import (line 5) with:

```ts
import { score } from "./score.js";
import { DEFAULT_POLICY } from "./policy.js";
```

and add `Audit` to the type import from `./types.js`. Replace `buildReport` (lines 29-66) with `buildAudit`:

```ts
/** Assemble the policy-independent {@link Audit} from metadata + extracted files. */
export function buildAudit(
  meta: PackageMeta,
  files: PackageFile[],
  opts: {
    mode: "full" | "diff";
    durationMs: number;
    baselineCapabilities?: Capability[];
  } = { mode: "full", durationMs: 0 },
): Audit {
  const input: AuditInput = { meta, files, mode: opts.mode };
  const findings = runRules(input);
  const capabilities = extractCapabilities(input);
  const capabilityDelta = opts.baselineCapabilities
    ? diffCapabilities(capabilities, opts.baselineCapabilities)
    : null;
  return {
    schema: 3,
    meta,
    findings,
    capabilities,
    capabilityDelta,
    engine: { version: ENGINE_VERSION, rules: RULES.map((r) => r.id), mode: opts.mode },
    auditedAt: new Date().toISOString(),
    durationMs: opts.durationMs,
  };
}
```

Replace the final `auditTarball` (lines 82-108) with a `runAudit` that returns the `Audit`, plus an `auditTarball` convenience that scores under the default policy:

```ts
/** Extract + diff + run rules + capabilities → policy-independent {@link Audit}. */
export async function runAudit(input: AuditTarballInput): Promise<Audit> {
  const started = Date.now();
  const mode: "full" | "diff" = input.baselineTarball ? "diff" : "full";

  let baseline: Map<string, string> | undefined;
  let baselineCapabilities: Capability[] | undefined;
  if (input.baselineTarball) {
    const prev = await extractTarball(input.baselineTarball);
    baseline = baselineFrom(prev.files);
    baselineCapabilities = extractCapabilities({ meta: input.meta as PackageMeta, files: prev.files, mode: "diff" });
  }

  const extracted = await extractTarball(input.tarball, baseline);
  const meta: PackageMeta = {
    ...input.meta,
    integrity: input.meta.integrity ?? integrityOf(input.tarball),
    unpackedSize: extracted.unpackedSize,
    fileCount: extracted.fileCount,
    hasInstallScripts: detectInstallScripts(extracted.files) || input.meta.hasInstallScripts,
  };

  return buildAudit(meta, extracted.files, { mode, durationMs: Date.now() - started, baselineCapabilities });
}

/**
 * End-to-end audit scored under the built-in {@link DEFAULT_POLICY}. The proxy
 * does NOT use this (it scores under the loaded enterprise policy); it is for the
 * offline CLI `scan` and for tests, and reproduces today's numbers exactly.
 */
export async function auditTarball(input: AuditTarballInput): Promise<AuditReport> {
  return score(await runAudit(input), DEFAULT_POLICY);
}
```

Add `AuditReport` to the type import list at the top if not already present (it is). Remove the now-unused `Finding` import only if TypeScript flags it (runRules still returns `Finding[]`, so keep it).

- [ ] **Step 6: Update core exports**

In `packages/core/src/index.ts`, replace the score export line
`export { POLICY, scoreFindings, verdictFor, severityRank } from "./score.js";` with:

```ts
export { score, severityRank } from "./score.js";
export {
  DEFAULT_POLICY,
  policyHashOf,
  matchPackage,
  type EnterprisePolicy,
} from "./policy.js";
```

and update the `audit.js` export block to export `buildAudit`, `runAudit` (and keep `auditTarball`, `runRules`, `ENGINE_VERSION`, `AuditTarballInput`) — replace `buildReport` with `buildAudit`/`runAudit`:

```ts
export {
  ENGINE_VERSION,
  auditTarball,
  buildAudit,
  runAudit,
  runRules,
  type AuditTarballInput,
} from "./audit.js";
```

(`Audit`, `ScoredFinding` flow through `export * from "./types.js"`.)

- [ ] **Step 7: Update existing core tests for the new shape**

In `packages/core/test/capabilities.test.ts`, change the assertion `assert.equal(r.schema, 2);` to `assert.equal(r.schema, 3);`.

`packages/core/test/audit.test.ts` reads `r.score`, `r.verdict`, `r.findings`, `f.weight`, `f.severity`, `r.engine.mode`, `r.meta.*` — all still present on the scored `AuditReport` (weights under `DEFAULT_POLICY` are unchanged). No edits should be needed; confirm by running it in Step 8. If the `diff mode weights changed files more heavily` test references a now-removed export, leave the asserts (they read `f.weight` on findings, which still exists).

- [ ] **Step 8: Build and run the core suite**

Run: `npx tsc --build --force packages/core && node --import tsx --test packages/core/test/*.test.ts`
Expected: PASS — `audit.test.ts` (unchanged numbers under default policy), `capabilities.test.ts` (schema 3). If `tsc` flags an unused import in `audit.ts`, remove only the flagged symbol.

- [ ] **Step 9: Commit**

```bash
git add packages/core/src packages/core/test
git commit -m "refactor(core): split audit (policy-independent) from score(audit, policy); add EnterprisePolicy + DEFAULT_POLICY"
```

---

## Task 2: Core scoring tests — toggles, allow/deny, waivers, glob

**Files:**
- Create: `packages/core/test/score.test.ts`

**Interfaces:**
- Consumes: `runAudit`, `score`, `DEFAULT_POLICY`, `matchPackage`, `type EnterprisePolicy` from `../src/index.js`; `ensureFixtures`, `tarball` from `./helpers.js`.

This task adds the behavioral tests for the scoring semantics implemented in Task 1 (no new source — if a test fails it reveals a Task 1 bug to fix).

- [ ] **Step 1: Write the scoring tests**

Create `packages/core/test/score.test.ts`:

```ts
import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { runAudit, score, DEFAULT_POLICY, matchPackage, type EnterprisePolicy } from "../src/index.js";
import { ensureFixtures, tarball } from "./helpers.js";

const baseMeta = {
  author: null, maintainers: [] as string[], license: null,
  hasInstallScripts: false, signatureStatus: "unknown" as const,
};
const auditOf = (name: string, version: string, baseline?: string) =>
  runAudit({ meta: { name, version, ...baseMeta }, tarball: tarball(name, version),
    baselineTarball: baseline ? tarball(name, baseline) : undefined });

function policy(over: Partial<EnterprisePolicy> = {}): EnterprisePolicy {
  return { ...DEFAULT_POLICY, version: "test", ...over };
}

describe("matchPackage glob", () => {
  test("exact and prefix match, anchored", () => {
    assert.equal(matchPackage("esbuild", "esbuild"), true);
    assert.equal(matchPackage("esbuild", "esbuild-wasm"), false);   // anchored, not substring
    assert.equal(matchPackage("evilcorp-*", "evilcorp-utils"), true);
    assert.equal(matchPackage("@acme/*", "@acme/payments"), true);
    assert.equal(matchPackage("@acme/*", "@other/x"), false);
    assert.equal(matchPackage("a.b", "axb"), false);                // '.' is literal, not regex
  });
});

describe("score under policies", () => {
  before(() => ensureFixtures());

  test("default policy blocks the malicious fixture (regression)", async () => {
    const r = score(await auditOf("color-stream", "1.4.1", "1.4.0"), DEFAULT_POLICY);
    assert.equal(r.verdict, "block");
    assert.equal(r.score, 0);
    assert.equal(r.policy.version, "default");
    assert.match(r.policy.hash, /^sha256-/);
  });

  test("same bytes, two policies → different verdicts", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    const strict = score(audit, DEFAULT_POLICY);
    const lax = score(audit, policy({
      rules: { disabled: ["secret-exfil", "install-scripts", "network-egress", "obfuscation"] },
    }));
    assert.equal(strict.verdict, "block");
    assert.equal(lax.verdict, "allow");           // all rules disabled → nothing scores or hard-blocks
    assert.equal(lax.score, 100);
  });

  test("allow waiver clears a finding from score AND hard-block, keeps it visible", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    // Waive every rule that fires, for this package only.
    const waived = score(audit, policy({
      allow: [{ package: "color-stream", rules: ["secret-exfil", "install-scripts", "network-egress", "obfuscation"], reason: "test" }],
    }));
    assert.equal(waived.verdict, "allow", "no non-waived critical remains to hard-block");
    assert.ok(waived.findings.length > 0, "findings still present");
    assert.ok(waived.findings.every((f) => f.waived), "all marked waived");
    assert.ok(waived.findings[0]?.waivedBy?.startsWith("allow: color-stream"));
  });

  test("deny forces block on an otherwise-clean package", async () => {
    const clean = await auditOf("leftpad-lite", "1.0.1");
    const denied = score(clean, policy({ deny: [{ package: "leftpad-lite", reason: "blocked" }] }));
    assert.equal(denied.verdict, "block");
    const allowed = score(clean, DEFAULT_POLICY);
    assert.equal(allowed.verdict, "allow");
  });

  test("threshold + weight overrides change the verdict", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    const lenient = score(audit, policy({
      scoring: { ...DEFAULT_POLICY.scoring, hardBlockSeverity: "critical", severityWeight: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, thresholds: { allow: 0, warn: 0 } },
    }));
    // hardBlock still fires on the (non-waived) critical severity regardless of zeroed weights
    assert.equal(lenient.verdict, "block");
  });

  test("scoring is deterministic for a fixed policy", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    const a = score(audit, DEFAULT_POLICY);
    const b = score(audit, DEFAULT_POLICY);
    assert.deepEqual(a.findings.map((f) => [f.ruleId, f.weight, f.waived]), b.findings.map((f) => [f.ruleId, f.weight, f.waived]));
    assert.equal(a.verdict, b.verdict);
  });
});
```

- [ ] **Step 2: Run the tests**

Run: `node --import tsx --test packages/core/test/score.test.ts`
Expected: PASS. If `allow waiver clears … keeps it visible` fails because a waived critical still blocks, the Task 1 `hardBlock` check is wrong (`!f.waived` missing) — fix in `score.ts` and re-run.

- [ ] **Step 3: Commit**

```bash
git add packages/core/test/score.test.ts
git commit -m "test(core): scoring under policies — toggles, allow/deny waivers, glob, determinism"
```

---

## Task 3: Core — policy signing, verification & loading

**Files:**
- Modify: `packages/core/src/policy.ts`, `packages/core/src/index.ts`
- Test: `packages/core/test/policy.test.ts`

**Interfaces:**
- Produces (in `policy.ts`):
  - `generateKeypair(): { publicKey: string; privateKey: string }` (Ed25519 PEM).
  - `signPolicy(raw: Buffer, privateKeyPem: string): string` (base64 detached sig).
  - `verifyPolicyBytes(raw: Buffer, sigB64: string, publicKeyPem: string): boolean`.
  - `policyHashOfBytes(raw: Buffer): string`.
  - `parsePolicy(raw: Buffer): EnterprisePolicy` (throws on invalid schema).
  - `loadPolicy(opts: { file: string; sig: string; publicKeyPem: string }): { policy: EnterprisePolicy; hash: string }` (throws on any failure — caller decides fail-closed).

- [ ] **Step 1: Write the failing test**

Create `packages/core/test/policy.test.ts`:

```ts
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import {
  DEFAULT_POLICY, generateKeypair, signPolicy, verifyPolicyBytes,
  policyHashOfBytes, parsePolicy, loadPolicy,
} from "../src/index.js";

const rawDefault = Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, version: "acme-1" }));

describe("policy signing", () => {
  test("sign → verify round-trips; tamper fails", () => {
    const { publicKey, privateKey } = generateKeypair();
    const sig = signPolicy(rawDefault, privateKey);
    assert.equal(verifyPolicyBytes(rawDefault, sig, publicKey), true);
    const tampered = Buffer.from(rawDefault.toString().replace("acme-1", "acme-2"));
    assert.equal(verifyPolicyBytes(tampered, sig, publicKey), false);
  });

  test("policyHashOfBytes is stable and prefixed", () => {
    assert.equal(policyHashOfBytes(rawDefault), policyHashOfBytes(rawDefault));
    assert.match(policyHashOfBytes(rawDefault), /^sha256-[0-9a-f]{64}$/);
  });

  test("parsePolicy rejects a non-schema-1 document", () => {
    assert.throws(() => parsePolicy(Buffer.from(JSON.stringify({ schema: 9 }))));
  });

  test("loadPolicy verifies signature and returns policy + raw-bytes hash", () => {
    const { publicKey, privateKey } = generateKeypair();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-policy-"));
    const file = join(dir, "policy.json");
    writeFileSync(file, rawDefault);
    writeFileSync(file + ".sig", signPolicy(rawDefault, privateKey));
    const { policy, hash } = loadPolicy({ file, sig: file + ".sig", publicKeyPem: publicKey });
    assert.equal(policy.version, "acme-1");
    assert.equal(hash, policyHashOfBytes(rawDefault));
  });

  test("loadPolicy throws on a bad signature (caller fails closed)", () => {
    const { publicKey } = generateKeypair();
    const other = generateKeypair();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-policy-"));
    const file = join(dir, "policy.json");
    writeFileSync(file, rawDefault);
    writeFileSync(file + ".sig", signPolicy(rawDefault, other.privateKey)); // wrong key
    assert.throws(() => loadPolicy({ file, sig: file + ".sig", publicKeyPem: publicKey }), /signature/i);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/core/test/policy.test.ts`
Expected: FAIL — `generateKeypair`/`signPolicy`/… not exported.

- [ ] **Step 3: Add the signing/loading helpers to `policy.ts`**

Append to `packages/core/src/policy.ts` (and add the imports at the top):

```ts
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
```

```ts
export function policyHashOfBytes(raw: Buffer): string {
  return "sha256-" + createHash("sha256").update(raw).digest("hex");
}

export function generateKeypair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

export function signPolicy(raw: Buffer, privateKeyPem: string): string {
  // Ed25519: algorithm is null in node:crypto.
  return edSign(null, raw, createPrivateKey(privateKeyPem)).toString("base64");
}

export function verifyPolicyBytes(raw: Buffer, sigB64: string, publicKeyPem: string): boolean {
  try {
    return edVerify(null, raw, createPublicKey(publicKeyPem), Buffer.from(sigB64, "base64"));
  } catch {
    return false;
  }
}

export function parsePolicy(raw: Buffer): EnterprisePolicy {
  const p = JSON.parse(raw.toString("utf8")) as Partial<EnterprisePolicy>;
  if (p?.schema !== 1 || typeof p.version !== "string" || !p.scoring || typeof p.scoring !== "object") {
    throw new Error("invalid policy: expected schema 1 with a version and scoring block");
  }
  const s = p.scoring as EnterprisePolicy["scoring"];
  if (!s.severityWeight || typeof s.diffMultiplier !== "number" || !s.thresholds || !s.hardBlockSeverity) {
    throw new Error("invalid policy: incomplete scoring block");
  }
  return {
    schema: 1,
    version: p.version,
    scoring: s,
    rules: { disabled: p.rules?.disabled ?? [] },
    allow: p.allow ?? [],
    deny: p.deny ?? [],
  };
}

export function loadPolicy(opts: { file: string; sig: string; publicKeyPem: string }): {
  policy: EnterprisePolicy;
  hash: string;
} {
  const raw = readFileSync(opts.file);
  const sigB64 = readFileSync(opts.sig, "utf8").trim();
  if (!verifyPolicyBytes(raw, sigB64, opts.publicKeyPem)) {
    throw new Error(`policy signature verification failed for ${opts.file}`);
  }
  return { policy: parsePolicy(raw), hash: policyHashOfBytes(raw) };
}
```

Note `Buffer` is a global in Node; if `tsc` requires it, add `import { Buffer } from "node:buffer";` at the top.

- [ ] **Step 4: Export the helpers**

In `packages/core/src/index.ts`, extend the `policy.js` export block to add:

```ts
export {
  DEFAULT_POLICY,
  policyHashOf,
  policyHashOfBytes,
  matchPackage,
  generateKeypair,
  signPolicy,
  verifyPolicyBytes,
  parsePolicy,
  loadPolicy,
  type EnterprisePolicy,
} from "./policy.js";
```

- [ ] **Step 5: Run to verify it passes**

Run: `npx tsc --build --force packages/core && node --import tsx --test packages/core/test/policy.test.ts`
Expected: PASS (all five cases).

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/policy.ts packages/core/src/index.ts packages/core/test/policy.test.ts
git commit -m "feat(core): Ed25519 policy signing, verification, and fail-on-invalid loadPolicy"
```

---

## Task 4: Proxy — thread the enterprise policy through scoring

**Files:**
- Modify: `packages/proxy/src/store.ts`, `packages/proxy/src/server.ts`
- Test: `packages/proxy/test/proxy.test.ts`

**Interfaces:**
- Consumes: `runAudit`, `score`, `DEFAULT_POLICY`, `policyHashOf`, `type EnterprisePolicy` from `@sentinel/core`.
- Produces: `ServerOptions` gains `enterprisePolicy: EnterprisePolicy` and optional `policyHash`. `AuditStore` constructor gains an optional `activePolicyHash` that filters persisted entries. Tarball responses set `x-sentinel-policy`.

- [ ] **Step 1: Write the failing tests**

In `packages/proxy/test/proxy.test.ts`, add to the imports:

```ts
import { DEFAULT_POLICY, type EnterprisePolicy } from "@sentinel/core";
```

In **both** `createServer({...})` calls (the two `before` hooks), add `enterprisePolicy: DEFAULT_POLICY,` to the options object.

Then append a new describe block at the end of the file:

```ts
describe("enterprise policy scoring (block policy, local fixtures)", () => {
  let server: Server;
  let base: string;

  function policy(over: Partial<EnterprisePolicy>): EnterprisePolicy {
    return { ...DEFAULT_POLICY, version: "test", ...over };
  }

  async function startWith(enterprisePolicy: EnterprisePolicy): Promise<void> {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals: new ApprovalStore(),
      enterprisePolicy,
      policy: "block",
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        resolve();
      });
    });
  }
  after(() => server?.close());

  test("a deny entry blocks an otherwise-clean package and stamps the policy header", async () => {
    await startWith(policy({ version: "denypol", deny: [{ package: "leftpad-lite", reason: "blocked" }] }));
    const res = await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.1.tgz`);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-sentinel-verdict"), "block");
    assert.equal(res.headers.get("x-sentinel-policy"), "denypol");
  });

  test("an allow waiver serves an otherwise-blocked package", async () => {
    await startWith(policy({
      allow: [{ package: "color-stream", rules: ["secret-exfil", "install-scripts", "network-egress", "obfuscation"], reason: "test" }],
    }));
    const res = await fetch(`${base}/color-stream/-/color-stream-1.4.1.tgz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-sentinel-verdict"), "allow");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/proxy/test/proxy.test.ts`
Expected: FAIL — `createServer` rejects `enterprisePolicy` / the new block fails to compile-run.

- [ ] **Step 3: Update the store guard**

In `packages/proxy/src/store.ts`, change the constructor signature and load filter. Replace lines 21-33 with:

```ts
  constructor(private readonly file?: string, private readonly activePolicyHash?: string) {
    if (file && existsSync(file)) {
      try {
        const rows = JSON.parse(readFileSync(file, "utf8")) as StoredAudit[];
        for (const r of rows) {
          if (r.report?.schema !== 3) continue; // re-audit anything older
          if (this.activePolicyHash && r.report.policy?.hash !== this.activePolicyHash) continue; // scored under a different policy
          this.index(r.report.meta.integrity ?? r.key, r);
        }
      } catch {
        /* start empty on a corrupt log */
      }
    }
  }
```

- [ ] **Step 4: Thread the policy through the server**

In `packages/proxy/src/server.ts`:

Add to the `@sentinel/core` import:

```ts
import {
  runAudit,
  score,
  policyHashOf,
  integrityOf,
  type AuditReport,
  type EnterprisePolicy,
  type PackageMeta,
} from "@sentinel/core";
```

(remove `auditTarball` from that import — the proxy no longer uses it.)

Add to `ServerOptions`:

```ts
  /** The signed scoring policy this proxy serves under. */
  enterprisePolicy: EnterprisePolicy;
  /** Hash of the active policy (raw-bytes for loaded, canonical for default). */
  policyHash?: string;
```

In `createServer`, after `const { upstream, store, approvals } = opts;` add:

```ts
  const enterprisePolicy = opts.enterprisePolicy;
  const policyHash = opts.policyHash ?? policyHashOf(enterprisePolicy);
```

In `auditVersion`, replace the audit call (lines 70-72) with:

```ts
    const audit = await runAudit({ meta, tarball, baselineTarball });
    const report = score(audit, enterprisePolicy, policyHash);
    store.put(report);
    return { report, tarball };
```

In the tarball route, after the existing `res.setHeader("x-sentinel-approval", rec.state);` line, add:

```ts
        res.setHeader("x-sentinel-policy", report.policy.version);
```

- [ ] **Step 5: Run to verify it passes**

Run: `npx tsc --build --force packages/proxy && node --import tsx --test packages/proxy/test/proxy.test.ts`
Expected: PASS — the original blocks (now passing `enterprisePolicy: DEFAULT_POLICY`) plus the two new policy tests.

- [ ] **Step 6: Commit**

```bash
git add packages/proxy/src/store.ts packages/proxy/src/server.ts packages/proxy/test/proxy.test.ts
git commit -m "feat(proxy): score audits under a configured EnterprisePolicy; policy-hash store guard + x-sentinel-policy header"
```

---

## Task 5: Proxy startup — load the signed policy from env, fail closed

**Files:**
- Modify: `packages/proxy/src/index.ts`, `scripts/demo.ts`
- Test: `packages/proxy/test/policy-startup.test.ts` (create)

**Interfaces:**
- Consumes: `loadPolicy`, `DEFAULT_POLICY`, `policyHashOf` from `@sentinel/core`.
- Produces: a `resolveEnterprisePolicy()` that returns `{ policy, hash }` from env, exits non-zero on a configured-but-invalid policy, and uses the default when none is configured. `scripts/demo.ts` passes `enterprisePolicy: DEFAULT_POLICY`.

- [ ] **Step 1: Write the failing test**

Create `packages/proxy/test/policy-startup.test.ts`:

```ts
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { DEFAULT_POLICY, generateKeypair, signPolicy } from "@sentinel/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const ENTRY = join(REPO_ROOT, "packages", "proxy", "src", "index.ts");

/** Boot the proxy with env, return { ok, output }. Exits fast: we only need startup. */
function boot(env: Record<string, string>): { ok: boolean; output: string } {
  try {
    const out = execFileSync("node", ["--import", "tsx", ENTRY], {
      cwd: REPO_ROOT,
      env: { ...process.env, ...env, SENTINEL_PORT: "0", SENTINEL_BOOT_EXIT: "1" },
      timeout: 15000,
      encoding: "utf8",
    });
    return { ok: true, output: out };
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string };
    return { ok: false, output: (err.stdout ?? "") + (err.stderr ?? "") };
  }
}

describe("proxy policy startup", () => {
  test("no policy configured → boots with the built-in default", () => {
    const r = boot({ SENTINEL_UPSTREAM: "fixtures" });
    assert.equal(r.ok, true);
    assert.match(r.output, /built-in default policy/i);
  });

  test("valid signed policy → boots and reports the version", () => {
    const { publicKey, privateKey } = generateKeypair();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-boot-"));
    const raw = Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, version: "acme-boot" }));
    writeFileSync(join(dir, "p.json"), raw);
    writeFileSync(join(dir, "p.json.sig"), signPolicy(raw, privateKey));
    writeFileSync(join(dir, "pub.pem"), publicKey);
    const r = boot({ SENTINEL_UPSTREAM: "fixtures",
      SENTINEL_POLICY_FILE: join(dir, "p.json"),
      SENTINEL_POLICY_PUBKEY: join(dir, "pub.pem") });
    assert.equal(r.ok, true);
    assert.match(r.output, /acme-boot/);
  });

  test("tampered policy → fails closed (non-zero exit)", () => {
    const { publicKey, privateKey } = generateKeypair();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-boot-"));
    const raw = Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, version: "acme-boot" }));
    writeFileSync(join(dir, "p.json"), raw);
    writeFileSync(join(dir, "p.json.sig"), signPolicy(raw, privateKey));
    writeFileSync(join(dir, "p.json"), Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, version: "tampered" }))); // mutate after signing
    writeFileSync(join(dir, "pub.pem"), publicKey);
    const r = boot({ SENTINEL_UPSTREAM: "fixtures",
      SENTINEL_POLICY_FILE: join(dir, "p.json"),
      SENTINEL_POLICY_PUBKEY: join(dir, "pub.pem") });
    assert.equal(r.ok, false, "must exit non-zero");
    assert.match(r.output, /signature|FATAL/i);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/proxy/test/policy-startup.test.ts`
Expected: FAIL — the proxy ignores `SENTINEL_POLICY_FILE` and never prints the policy line / never fails closed.

- [ ] **Step 3: Implement env-driven policy loading in `index.ts`**

In `packages/proxy/src/index.ts`:

Add imports:

```ts
import { readFileSync } from "node:fs";
import { loadPolicy, DEFAULT_POLICY, policyHashOf, type EnterprisePolicy } from "@sentinel/core";
```

Add a resolver function above `main`:

```ts
function resolveEnterprisePolicy(): { policy: EnterprisePolicy; hash: string } {
  const file = process.env.SENTINEL_POLICY_FILE;
  if (!file) {
    console.log("  scoring  : built-in default policy");
    return { policy: DEFAULT_POLICY, hash: policyHashOf(DEFAULT_POLICY) };
  }
  const sig = process.env.SENTINEL_POLICY_SIG ?? `${file}.sig`;
  const pub = process.env.SENTINEL_POLICY_PUBKEY;
  if (!pub) {
    console.error("FATAL: SENTINEL_POLICY_PUBKEY is required when SENTINEL_POLICY_FILE is set");
    process.exit(1);
  }
  try {
    const { policy, hash } = loadPolicy({ file, sig, publicKeyPem: readFileSync(pub, "utf8") });
    console.log(`  scoring  : signed policy ${policy.version} (${hash.slice(0, 22)}…)`);
    return { policy, hash };
  } catch (err) {
    console.error(`FATAL: ${(err as Error).message}`);
    process.exit(1);
  }
}
```

In `main()`, after building the upstream, resolve the policy and thread it through. Replace the `store`/`approvals`/`createServer` lines (34-39) with:

```ts
  const { policy: enterprisePolicy, hash: policyHash } = resolveEnterprisePolicy();
  const store = new AuditStore(process.env.SENTINEL_STORE, policyHash);
  const approvals = new ApprovalStore(process.env.SENTINEL_APPROVALS);
  const publicDir = env("SENTINEL_PUBLIC", join(here, "..", "public"));

  const app = createServer({ upstream, store, approvals, enterprisePolicy, policyHash, policy, publicDir });
```

To let the startup test exit fast after binding, add right after the `app.listen(port, () => {...})` callback body's last line, inside the callback:

```ts
    if (process.env.SENTINEL_BOOT_EXIT) process.exit(0);
```

(Place it as the final statement inside the existing `app.listen(port, () => { ... })` callback.)

- [ ] **Step 4: Fix `scripts/demo.ts`**

In `scripts/demo.ts`, add the import alongside the existing core import:

```ts
import { DEFAULT_POLICY } from "@sentinel/core";
```

and add `enterprisePolicy: DEFAULT_POLICY,` to its `createServer({...})` options object (near line 19).

- [ ] **Step 5: Run to verify it passes**

Run: `npx tsc --build --force packages/proxy && node --import tsx --test packages/proxy/test/policy-startup.test.ts`
Expected: PASS (default boots, valid signed boots, tampered fails closed). Then confirm the demo still runs:

Run: `npm run demo 2>&1 | grep -iE "HTTP 403|x-sentinel-verdict: block"`
Expected: shows the malicious tarball blocked (`HTTP 403 · verdict block`).

- [ ] **Step 6: Commit**

```bash
git add packages/proxy/src/index.ts scripts/demo.ts packages/proxy/test/policy-startup.test.ts
git commit -m "feat(proxy): load signed policy from env at startup (fail closed); demo passes DEFAULT_POLICY"
```

---

## Task 6: CLI — `sentinel policy` (verify / sign / keygen)

**Files:**
- Modify: `packages/cli/src/index.ts`
- Test: `packages/cli/test/policy.test.ts` (create)

**Interfaces:**
- Consumes: `loadPolicy`, `signPolicy`, `generateKeypair`, `verifyPolicyBytes`, `parsePolicy`, `policyHashOfBytes` from `@sentinel/core`.
- Produces: a `policy` command with `verify`/`sign`/`keygen` subcommands, and an exported pure helper `summarizePolicy(policy): string` used for the printed summary and unit-tested.

- [ ] **Step 1: Write the failing test**

Create `packages/cli/test/policy.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { DEFAULT_POLICY } from "@sentinel/core";
import { summarizePolicy } from "../src/index.js";

describe("summarizePolicy", () => {
  test("renders version, thresholds, and allow/deny counts", () => {
    const out = summarizePolicy({ ...DEFAULT_POLICY, version: "acme-9",
      rules: { disabled: ["obfuscation"] },
      allow: [{ package: "esbuild", rules: ["network-egress"] }],
      deny: [{ package: "evil-*" }] });
    assert.match(out, /acme-9/);
    assert.match(out, /allow 80/);
    assert.match(out, /disabled: obfuscation/);
    assert.match(out, /allow rules: 1/);
    assert.match(out, /deny rules: 1/);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/cli/test/policy.test.ts`
Expected: FAIL — `summarizePolicy` not exported.

- [ ] **Step 3: Implement the command + helper**

In `packages/cli/src/index.ts`:

Add to the core import:

```ts
import {
  loadPolicy, signPolicy, generateKeypair, verifyPolicyBytes, parsePolicy, policyHashOfBytes,
  type EnterprisePolicy,
} from "@sentinel/core";
```

Add `readFileSync, writeFileSync` to the existing `node:fs` import (it currently imports `readFileSync`):

```ts
import { readFileSync, writeFileSync } from "node:fs";
```

Add the exported helper (near `planApprovals`, before the `parseAsync` guard line):

```ts
export function summarizePolicy(p: EnterprisePolicy): string {
  const t = p.scoring.thresholds;
  return [
    `version    ${p.version}`,
    `thresholds allow ${t.allow} · warn ${t.warn} · hardBlock ${p.scoring.hardBlockSeverity}`,
    `diffMult   ${p.scoring.diffMultiplier}`,
    `disabled:  ${p.rules.disabled.length ? p.rules.disabled.join(", ") : "(none)"}`,
    `allow rules: ${p.allow.length}   deny rules: ${p.deny.length}`,
  ].join("\n  ");
}
```

Add the `policy` command with subcommands (place before the `parseAsync` guard line at 133):

```ts
const policyCmd = program.command("policy").description("Author, sign, and verify enterprise scoring policies.");

policyCmd
  .command("keygen")
  .description("Generate an Ed25519 keypair (PEM) for signing policies.")
  .option("--out <prefix>", "write <prefix>.pub.pem and <prefix>.key.pem instead of stdout")
  .action((opts: { out?: string }) => {
    const { publicKey, privateKey } = generateKeypair();
    if (opts.out) {
      writeFileSync(`${opts.out}.pub.pem`, publicKey);
      writeFileSync(`${opts.out}.key.pem`, privateKey);
      console.log(`wrote ${opts.out}.pub.pem and ${opts.out}.key.pem`);
    } else {
      console.log(publicKey + "\n" + privateKey);
    }
  });

policyCmd
  .command("sign")
  .description("Write a detached Ed25519 signature (<file>.sig) over a policy file.")
  .argument("<file>", "path to the policy JSON")
  .requiredOption("--key <privkey>", "path to the Ed25519 private key PEM")
  .action((file: string, opts: { key: string }) => {
    const raw = readFileSync(file);
    const sig = signPolicy(raw, readFileSync(opts.key, "utf8"));
    writeFileSync(`${file}.sig`, sig);
    console.log(`wrote ${file}.sig  (${policyHashOfBytes(raw)})`);
  });

policyCmd
  .command("verify")
  .description("Verify a policy's signature and print its summary.")
  .argument("<file>", "path to the policy JSON")
  .requiredOption("--pubkey <pubkey>", "path to the Ed25519 public key PEM")
  .option("--sig <sig>", "signature file (defaults to <file>.sig)")
  .action((file: string, opts: { pubkey: string; sig?: string }) => {
    const sig = opts.sig ?? `${file}.sig`;
    try {
      const { policy, hash } = loadPolicy({ file, sig, publicKeyPem: readFileSync(opts.pubkey, "utf8") });
      console.log(`✓ signature valid  ${hash}`);
      console.log("  " + summarizePolicy(policy));
    } catch (err) {
      console.error(`✗ ${(err as Error).message}`);
      process.exit(2);
    }
  });
```

(The `parsePolicy`/`verifyPolicyBytes` imports are used transitively via `loadPolicy`; if `tsc` flags them as unused, drop them from the import.)

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/cli/test/policy.test.ts`
Expected: PASS.

- [ ] **Step 5: Manual round-trip check (keygen → sign → verify)**

Run (single command — keeps temp files together):

```bash
node --import tsx packages/cli/src/index.ts policy keygen --out /tmp/sp && \
printf '%s' "$(node -e 'const {DEFAULT_POLICY}=require("./packages/core/dist/policy.js");console.log(JSON.stringify({...DEFAULT_POLICY,version:"acme-cli"}))' 2>/dev/null || node --import tsx -e 'import("@sentinel/core").then(m=>console.log(JSON.stringify({...m.DEFAULT_POLICY,version:"acme-cli"})))')" > /tmp/sp.json && \
node --import tsx packages/cli/src/index.ts policy sign /tmp/sp.json --key /tmp/sp.key.pem && \
node --import tsx packages/cli/src/index.ts policy verify /tmp/sp.json --pubkey /tmp/sp.pub.pem
```

Expected: `✓ signature valid  sha256-…` and a summary line with `version    acme-cli`.

- [ ] **Step 6: Commit**

```bash
npx tsc --build --force packages/cli
git add packages/cli/src/index.ts packages/cli/test/policy.test.ts
git commit -m "feat(cli): sentinel policy keygen/sign/verify"
```

---

## Task 7: Documentation

**Files:**
- Create: `docs/adr/0014-score-time-policy-and-raw-bytes-signing.md`
- Modify: `docs/adr/0012-per-enterprise-policy-as-signed-data.md`, `docs/adr/0008-diff-audit-weighting.md`, `ARCHITECTURE.md`, `CLAUDE.md`

**Interfaces:** none (docs only). Verified by a clean build + full test pass.

- [ ] **Step 1: Mark ADR-0012 Accepted**

In `docs/adr/0012-per-enterprise-policy-as-signed-data.md`, change `**Status:** Proposed` to:

```md
**Status:** Accepted
```

- [ ] **Step 2: Annotate ADR-0008**

In `docs/adr/0008-diff-audit-weighting.md`, add immediately under its `**Status:**` line:

```md
> **Amended (2026-06-25, ADR-0014):** the diff multiplier is now applied at **score
> time** in `score(audit, policy)`, not baked into the finding at creation. Findings
> carry `onChangedFile`; the multiplier value lives in the enterprise policy.
```

- [ ] **Step 3: Write ADR-0014**

Create `docs/adr/0014-score-time-policy-and-raw-bytes-signing.md`:

```md
# ADR-0014: Score-time policy application and raw-bytes Ed25519 signing

**Status:** Accepted
**Date:** 2026-06-25
**Phase:** 2 (refines ADR-0012; amends ADR-0002/0008)

## Context

ADR-0012 makes policy per-enterprise, versioned, and signed. Two mechanics were
unspecified: where scoring weight is computed, and how a policy is signed/verified.

## Decision

1. **Weight moves out of finding-creation into scoring.** `runAudit` produces
   policy-independent findings (`severity` + `onChangedFile`, no weight) cached by
   integrity. `score(audit, policy)` applies `severityWeight`, `diffMultiplier`,
   rule enable/disable, allow/deny waivers, thresholds, and the hard-block override,
   producing the verdict and per-finding weight. This is what makes "findings are
   policy-independent, re-scored per policy" actually true. `auditTarball` survives
   as `score(runAudit(...), DEFAULT_POLICY)` for the offline CLI and tests.
2. **A waiver excludes a finding from BOTH the penalty sum AND the hard-block
   severity check**, while keeping it visible (`waived` + `waivedBy`). `deny` forces
   `block`; `allow` cannot rescue a denied package.
3. **Sign the raw policy bytes** with Ed25519 (`node:crypto`); verify the file
   as-is (`crypto.verify(null, raw, pubKey, sig)`); `policyHash = sha256(raw bytes)`.
   The in-code `DEFAULT_POLICY` (no file) is hashed via canonical JSON. No JSON
   canonicalization on the verify path.
4. **Fail closed.** No policy configured → built-in default (logged). Configured but
   invalid (missing/parse/sig/pubkey/schema) → the proxy exits non-zero; it never
   silently degrades to the default.

## Consequences

- The determinism invariant (ADR-0002) becomes "same bytes + same policy ⇒ same
  verdict"; the existing determinism test pins the default policy.
- ADR-0008's diff multiplier is now a score-time, policy-owned value.
- Caching: findings are computed policy-independently; the proxy runs one policy per
  process, so the report scored under that policy is cached by integrity and persisted
  entries scored under a different `policy.hash` are dropped on load.
- One signed policy per process (ADR-0012 D-tenancy); per-request multi-tenant
  routing, key rotation, and multiple signers are deferred.
```

- [ ] **Step 4: Update ARCHITECTURE.md**

In `ARCHITECTURE.md` §4.2 (Scoring → verdict), add after the existing scoring description:

```md
Scoring is **policy-applied at score time** (ADR-0012/0014). `runAudit` produces
policy-independent findings (`severity` + `onChangedFile`); `score(audit, policy)`
applies the enterprise policy's weights, diff multiplier, rule toggles, allow/deny
waivers, thresholds, and hard-block. A waived finding is excluded from the penalty
sum and the hard-block check but stays visible.
```

In §5 (Data model), append to the code block:

```ts
// Findings are policy-independent (no weight); weight/waiver come from score():
interface Finding { ruleId; category; severity; message; onChangedFile: boolean; evidence }
interface ScoredFinding extends Finding { weight: number; waived: boolean; waivedBy?: string }
interface Audit { schema: 3; meta; findings: Finding[]; capabilities; capabilityDelta; engine; auditedAt; durationMs }
// AuditReport is schema 3: findings: ScoredFinding[], plus policy: { version, hash }.

interface EnterprisePolicy {           // signed, per-enterprise (ADR-0012/0014)
  schema: 1; version: string;
  scoring: { severityWeight; diffMultiplier; thresholds; hardBlockSeverity };
  rules: { disabled: string[] };
  allow: { package; rules; reason? }[];   // package: anchored glob; rules: ruleId|category
  deny:  { package; reason? }[];
}
```

Add a short subsection after §3.3:

```md
### 3.4 Policy loading (Phase 2.2, ADR-0012/0014)

The proxy loads one Ed25519-signed policy at startup from `SENTINEL_POLICY_FILE`
(+ `SENTINEL_POLICY_SIG`, `SENTINEL_POLICY_PUBKEY`), verifying the raw bytes. An
invalid policy fails closed (non-zero exit); no policy configured uses the built-in
default. Every report carries `policy: { version, hash }` and the tarball response
sets `x-sentinel-policy`. (Distinct from the `SENTINEL_POLICY` env var, which selects
the `observe`/`block` proxy mode.)
```

- [ ] **Step 5: Update CLAUDE.md**

In `CLAUDE.md`, update invariant #1 ("Scoring is deterministic") to read "deterministic **given a policy**": replace its first sentence with:

```md
1. **Scoring is deterministic given a policy.** The 0–100 score and verdict come
   *entirely* from the heuristic rules plus the active `EnterprisePolicy`. Same input
   + same policy ⇒ same score, always. The `scoring is deterministic across runs` test
   pins the default policy — keep it green.
```

Then run the suite and update the test count: `npm test 2>&1 | tail -4`, and change the `must be 47/47` references (the build/test block comment and the Definition-of-done line) to the observed `N/N`.

- [ ] **Step 6: Commit**

```bash
git add docs/adr ARCHITECTURE.md CLAUDE.md
git commit -m "docs: accept ADR-0012, add ADR-0014, amend ADR-0008, update ARCHITECTURE + CLAUDE for signed policy"
```

---

## Task 8: Full-suite verification

**Files:** none (verification only).

- [ ] **Step 1: Clean build**

Run: `npm run build`
Expected: no TypeScript errors.

- [ ] **Step 2: Full test suite**

Run: `npm test`
Expected: all pass — core (`audit`, `capabilities`, `score`, `policy`), proxy (`proxy`, `store`, `approvals`, `reconcile`, `policy-startup`), cli (`cli`, `policy`). Note the count for CLAUDE.md (Task 7 Step 5).

- [ ] **Step 3: Confirm the malware invariant under the default policy**

Run: `node --import tsx --test --test-name-pattern "default policy blocks the malicious fixture" packages/core/test/score.test.ts`
Expected: PASS — `color-stream@1.4.1` is `block`/score 0 under `DEFAULT_POLICY`.

- [ ] **Step 4: Offline demo**

Run: `npm run demo 2>&1 | grep -iE "HTTP 403|verdict: block"`
Expected: malicious tarball blocked.

- [ ] **Step 5: Commit any stragglers**

```bash
git status --short
# branch is ready for whole-branch review
```

---

## Self-review notes

- **Spec coverage:** one-policy-per-instance (Task 5); Ed25519 raw-bytes signing (Task 3); schema scope scoring+toggles+allow/deny (Tasks 1-2, 4); granular visible waiver (Tasks 1-2); audit/score split (Task 1); `auditTarball` survival (Task 1 Step 5); `EnterprisePolicy` naming (Global Constraints, used throughout); all four `createServer` callers — `proxy.test.ts` ×2 (Task 4), `index.ts` (Task 5), `demo.ts` (Task 5); default-policy hash (Task 1 `policyHashOf`); anchored glob (Task 1 `matchPackage` + Task 2 test); fail-closed loading (Tasks 3, 5); caching/headers (Task 4); CLI (Task 6); determinism superseded + ADRs (Task 7); store schema-3 + policy-hash guard (Task 4).
- **Caching note (spec §6 reconciliation):** the plan caches the report *scored under the single active policy*, keyed by integrity, dropping persisted entries whose `policy.hash` differs on load. This is observably identical to "cache the policy-independent audit and score live" because the proxy runs exactly one policy per process (D1); the findings are still computed policy-independently in `runAudit`. Stated here so the reviewer doesn't read it as a spec deviation.
- **Type consistency:** `Finding`(+`onChangedFile`,−`weight`), `ScoredFinding`, `Audit`, `AuditReport`(schema 3,+`policy`), `EnterprisePolicy`, `score(audit, policy, hash?)`, `runAudit`, `buildAudit`, `auditTarball`, `loadPolicy`, `policyHashOf`/`policyHashOfBytes`, `matchPackage`, `signPolicy`, `verifyPolicyBytes`, `generateKeypair`, `summarizePolicy` — names consistent across tasks.
- **Determinism:** `score` is pure; the determinism test pins the default policy; findings/capability extraction unchanged.
