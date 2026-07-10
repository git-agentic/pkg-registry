# Phase 16 — Maintainer & Release-Anomaly Signals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect a release that is anomalous relative to the package's own history — a changed maintainer set, dormancy resurrection, a first-version-with-install-script, or a newly-added dangerous capability — as deterministic, weighted, compounding findings.

**Architecture:** A new pure rule `release-anomaly.ts` (signals 1–3) reads a new optional `AuditInput.releaseContext`; signal 4 (capability novelty) is a pure helper called in `buildAudit` where `capabilityDelta` already exists. The proxy derives `releaseContext` from the already-fetched packument (immutable publish timestamps + per-version maintainer sets + version count) and threads it through `runAudit`.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; `node:test` via `tsx`. No new dependencies.

## Global Constraints

- **Determinism (invariant #1) is the binding constraint.** Every signal reads ONLY immutable inputs — two versions' maintainer sets, two immutable ISO publish timestamps, the version ordinal, `meta.hasInstallScripts`, a `capabilityDelta`. **No `Date.now()` / `new Date()` with no argument / wall-clock in the rule or the helper.** Parsing a GIVEN ISO timestamp (`Date.parse(releaseContext.currentPublishedAt)`) is deterministic and allowed; reading the current time is not. A test greps both new source files for `Date.now`/`new Date(` and asserts absence.
- **Weighted, never a standalone hard block.** All findings are `category: "metadata"`, built via `mkFinding(...)`, so POLICY prices them and the diff multiplier applies. No new hard-block verdict logic. Power comes from compounding (the engine sums penalties).
- **Inert by default.** No `releaseContext` (first-ever version, direct tarball audit, upstream without `time`) ⇒ the rule returns `[]` and the helper returns `[]`. Every existing test that provides no `releaseContext` is unaffected.
- **`ReleaseContext` shape (verbatim):** `{ previousVersion?: string; previousMaintainers?: string[]; previousPublishedAt?: string; currentPublishedAt?: string; versionCount?: number }` — all optional.
- **"Dangerous capability"** for signal 4 = a `Capability` whose `kind` is `"network"` or `"process"`.
- **Rule contract:** `(input: AuditInput) => Finding[]`, registered in `rules/index.ts`; `runRules` wraps it (fails open). The rule runs BEFORE capabilities are computed, so it must NOT read capabilities.
- **Fixtures:** malicious fixtures stay synthetic, `SYNTHETIC FIXTURE`-headed, RFC 5737 IPs (198.51.100.0/24, 203.0.113.0/24), scored as text, NEVER executed. Tests hermetic (`LocalFixtureUpstream`, no live npm). Re-run `npm run fixtures` after editing fixtures.
- ESM only, NodeNext: internal imports use `.js` specifiers even from `.ts`.
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/<pkg>`.
- Run all commands from repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.

---

### Task 1: `ReleaseContext` type + the `release-anomaly` rule (signals 1–3)

**Files:**
- Modify: `packages/core/src/types.ts` (`ReleaseContext` + `AuditInput.releaseContext?`)
- Create: `packages/core/src/rules/release-anomaly.ts`
- Modify: `packages/core/src/rules/index.ts` (register)
- Test: `packages/core/test/rules-release-anomaly.test.ts`

**Interfaces:**
- Consumes: `AuditInput`, `Finding`, `Rule` (types), `mkFinding` (rules/util).
- Produces (used by Tasks 2–4): `interface ReleaseContext { previousVersion?: string; previousMaintainers?: string[]; previousPublishedAt?: string; currentPublishedAt?: string; versionCount?: number }`; `AuditInput.releaseContext?: ReleaseContext`; `export const releaseAnomalyRule: Rule` (id `"release-anomaly"`).

- [ ] **Step 1: Write the failing test** (`packages/core/test/rules-release-anomaly.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { releaseAnomalyRule } from "../src/rules/release-anomaly.js";
import type { AuditInput, ReleaseContext, PackageMeta } from "../src/types.js";

function meta(over: Partial<PackageMeta> = {}): PackageMeta {
  return {
    name: "acme", version: "2.0.0", author: null, maintainers: ["alice"],
    license: "MIT", hasInstallScripts: false, integrity: "sha512-x",
    unpackedSize: 1, fileCount: 1, signature: "unsigned", provenance: "absent",
    ...over,
  } as PackageMeta;
}
function input(m: Partial<PackageMeta>, rc: ReleaseContext | undefined): AuditInput {
  return { meta: meta(m), files: [], mode: "full", releaseContext: rc };
}
const ids = (fs: { message: string }[]) => fs.map((f) => f.message);

describe("release-anomaly rule", () => {
  test("no releaseContext → inert (no findings)", () => {
    assert.deepEqual(releaseAnomalyRule.run(input({}, undefined)), []);
  });

  test("same maintainers, small time gap → no findings (false-positive guard)", () => {
    const rc: ReleaseContext = {
      previousVersion: "1.9.0", previousMaintainers: ["alice"],
      previousPublishedAt: "2026-06-01T00:00:00Z", currentPublishedAt: "2026-06-10T00:00:00Z",
      versionCount: 5,
    };
    assert.deepEqual(releaseAnomalyRule.run(input({ maintainers: ["alice"] }, rc)), []);
  });

  test("maintainer ADDED (superset) → a maintainer-change finding", () => {
    const rc: ReleaseContext = { previousVersion: "1.9.0", previousMaintainers: ["alice"], versionCount: 5 };
    const fs = releaseAnomalyRule.run(input({ maintainers: ["alice", "mallory"] }, rc));
    assert.equal(fs.length, 1);
    assert.match(fs[0]!.message, /new maintainer/i);
    assert.equal(fs[0]!.severity, "low");
  });

  test("maintainer TURNOVER (no prior maintainer remains) → higher-severity finding", () => {
    const rc: ReleaseContext = { previousVersion: "1.9.0", previousMaintainers: ["alice"], versionCount: 5 };
    const fs = releaseAnomalyRule.run(input({ maintainers: ["mallory"] }, rc));
    assert.equal(fs.length, 1);
    assert.match(fs[0]!.message, /ownership|took over|replaced/i);
    assert.equal(fs[0]!.severity, "high");
  });

  test("dormancy: prev→current gap ≥ 365 days → a dormancy finding", () => {
    const rc: ReleaseContext = {
      previousVersion: "1.9.0", previousMaintainers: ["alice"], versionCount: 5,
      previousPublishedAt: "2023-01-01T00:00:00Z", currentPublishedAt: "2026-01-01T00:00:00Z",
    };
    const fs = releaseAnomalyRule.run(input({ maintainers: ["alice"] }, rc));
    assert.equal(fs.length, 1);
    assert.match(fs[0]!.message, /dormant|dormancy/i);
  });

  test("new-package risk: first version + install scripts → a finding", () => {
    const rc: ReleaseContext = { versionCount: 1 };
    const fs = releaseAnomalyRule.run(input({ version: "1.0.0", hasInstallScripts: true }, rc));
    assert.equal(fs.length, 1);
    assert.match(fs[0]!.message, /first published version|new package/i);
  });

  test("first version WITHOUT install scripts → no finding", () => {
    assert.deepEqual(releaseAnomalyRule.run(input({ hasInstallScripts: false }, { versionCount: 1 })), []);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/core/test/rules-release-anomaly.test.ts
```

Expected: FAIL — `release-anomaly.js` not found.

- [ ] **Step 3a: Add `ReleaseContext` + `AuditInput.releaseContext` to `packages/core/src/types.ts`**

Add near `AuditInput`:

```ts
/** Immutable cross-version context for release-anomaly scoring (Phase 16). All optional;
 *  absent ⇒ the release-anomaly rule is inert. Derived from the packument, never the clock. */
export interface ReleaseContext {
  /** The immediately-previous published version, if any. */
  previousVersion?: string;
  /** Maintainer names on the previous version. */
  previousMaintainers?: string[];
  /** ISO publish timestamp of the previous version. */
  previousPublishedAt?: string;
  /** ISO publish timestamp of this version. */
  currentPublishedAt?: string;
  /** Total number of published versions of this package. */
  versionCount?: number;
}
```

And extend `AuditInput`:

```ts
export interface AuditInput {
  meta: PackageMeta;
  files: PackageFile[];
  mode: "full" | "diff";
  /** Cross-version context for the release-anomaly rule (Phase 16); absent ⇒ inert. */
  releaseContext?: ReleaseContext;
}
```

- [ ] **Step 3b: Implement `packages/core/src/rules/release-anomaly.ts`**

```ts
import type { AuditInput, Finding, Rule } from "../types.js";
import { mkFinding } from "./util.js";

const DORMANCY_DAYS = 365;
const DAY_MS = 86_400_000;

/** Days between two ISO timestamps, or null if either is missing/unparseable. Pure — parses
 *  GIVEN immutable timestamps, never reads the clock (invariant #1). */
function daysBetween(a?: string, b?: string): number | null {
  if (!a || !b) return null;
  const ta = Date.parse(a), tb = Date.parse(b);
  if (Number.isNaN(ta) || Number.isNaN(tb)) return null;
  return (tb - ta) / DAY_MS;
}

/**
 * Flags a release that is anomalous relative to the package's OWN history: a changed
 * maintainer set, dormancy resurrection, or a first-version package that already runs
 * install scripts. Pure, policy-blind, deterministic (immutable packument data only — no
 * wall-clock). Inert without a `releaseContext`. Weighted `metadata` findings that compound;
 * never a standalone hard block.
 */
export const releaseAnomalyRule: Rule = {
  id: "release-anomaly",
  category: "metadata",
  run(input: AuditInput): Finding[] {
    const rc = input.releaseContext;
    if (!rc) return [];
    const out: Finding[] = [];
    const mk = (severity: Finding["severity"], message: string): Finding =>
      mkFinding({ ruleId: this.id, category: this.category, severity, message, evidence: [], files: input.files });

    // Signal 1 — maintainer change (only when a predecessor's maintainers are known).
    if (rc.previousMaintainers && rc.previousMaintainers.length > 0) {
      const prev = new Set(rc.previousMaintainers);
      const cur = new Set(input.meta.maintainers);
      const anyPrevRemains = [...prev].some((m) => cur.has(m));
      const anyNew = [...cur].some((m) => !prev.has(m));
      if (!anyPrevRemains && cur.size > 0) {
        out.push(mk("high", `\`${input.meta.name}\` changed hands: none of the previous maintainers (${[...prev].join(", ")}) remain — possible account/ownership takeover.`));
      } else if (anyNew) {
        const added = [...cur].filter((m) => !prev.has(m));
        out.push(mk("low", `\`${input.meta.name}\` added a new maintainer (${added.join(", ")}) since ${rc.previousVersion ?? "the prior version"}.`));
      }
    }

    // Signal 2 — dormancy resurrection.
    const gap = daysBetween(rc.previousPublishedAt, rc.currentPublishedAt);
    if (gap !== null && gap >= DORMANCY_DAYS) {
      out.push(mk("low", `\`${input.meta.name}\` was dormant ~${Math.round(gap)} days before this release — a resurrected package is a supply-chain risk.`));
    }

    // Signal 3 — first-version package that already runs install scripts.
    if (rc.versionCount === 1 && input.meta.hasInstallScripts) {
      out.push(mk("medium", `\`${input.meta.name}\` is a first published version that already runs install scripts — throwaway/fresh-package risk.`));
    }

    return out;
  },
};
```

- [ ] **Step 3c: Register in `packages/core/src/rules/index.ts`**

Add the import and include it in `RULES` and the re-export block:

```ts
import { releaseAnomalyRule } from "./release-anomaly.js";
```
Add `releaseAnomalyRule,` to the `RULES` array and to the `export { ... }` list.

- [ ] **Step 4: Run the test + build**

```bash
npm run build
npx tsx --test packages/core/test/rules-release-anomaly.test.ts
```

Expected: PASS (7/7). Build clean.

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/types.ts packages/core/src/rules/release-anomaly.ts packages/core/src/rules/index.ts packages/core/test/rules-release-anomaly.test.ts
git commit -m "feat(phase16): release-anomaly rule (maintainer-change, dormancy, new-package) + ReleaseContext"
```

---

### Task 2: Capability-novelty helper (signal 4) + thread `releaseContext` through the audit

**Files:**
- Create: `packages/core/src/rules/capability-novelty.ts`
- Modify: `packages/core/src/audit.ts` (`buildAudit` accepts `releaseContext`, puts it on `input`, concats novelty findings; `runAudit`/`AuditTarballInput` thread it)
- Test: `packages/core/test/capability-novelty.test.ts`

**Interfaces:**
- Consumes: `CapabilityDelta`, `ReleaseContext`, `Finding` (types), `mkFinding`.
- Produces (used by Task 3): `capabilityNoveltyFindings(delta: CapabilityDelta | null, rc: ReleaseContext | undefined): Finding[]`; `AuditTarballInput.releaseContext?: ReleaseContext`; `buildAudit(..., opts: { ...; releaseContext?: ReleaseContext })`.

- [ ] **Step 1: Write the failing test** (`packages/core/test/capability-novelty.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { capabilityNoveltyFindings } from "../src/rules/capability-novelty.js";
import type { CapabilityDelta, ReleaseContext } from "../src/types.js";

const rc: ReleaseContext = { previousVersion: "1.0.0" };
const netCap = { kind: "network" as const, target: "203.0.113.9", evidence: [] };
const procCap = { kind: "process" as const, target: "sh", evidence: [] };
const fsCap = { kind: "filesystem" as const, target: "/tmp/x", evidence: [] };

describe("capabilityNoveltyFindings", () => {
  test("newly-added network capability (with a predecessor) → a finding", () => {
    const delta: CapabilityDelta = { added: [netCap], removed: [] };
    const fs = capabilityNoveltyFindings(delta, rc);
    assert.equal(fs.length, 1);
    assert.match(fs[0]!.message, /new(ly)?|did not|previously/i);
    assert.equal(fs[0]!.category, "metadata");
  });

  test("newly-added process capability → a finding", () => {
    assert.equal(capabilityNoveltyFindings({ added: [procCap], removed: [] }, rc).length, 1);
  });

  test("only a benign (filesystem) capability added → no finding", () => {
    assert.deepEqual(capabilityNoveltyFindings({ added: [fsCap], removed: [] }, rc), []);
  });

  test("no predecessor (first release) → no finding even with a dangerous add", () => {
    assert.deepEqual(capabilityNoveltyFindings({ added: [netCap], removed: [] }, { versionCount: 1 }), []);
  });

  test("null delta (no baseline) → no finding", () => {
    assert.deepEqual(capabilityNoveltyFindings(null, rc), []);
  });

  test("undefined releaseContext → no finding", () => {
    assert.deepEqual(capabilityNoveltyFindings({ added: [netCap], removed: [] }, undefined), []);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/core/test/capability-novelty.test.ts
```

Expected: FAIL — `capability-novelty.js` not found.

- [ ] **Step 3a: Implement `packages/core/src/rules/capability-novelty.ts`**

```ts
import type { CapabilityDelta, Finding, ReleaseContext } from "../types.js";
import { mkFinding } from "./util.js";

const DANGEROUS = new Set(["network", "process"]);

/**
 * Signal 4 (Phase 16): a dangerous capability (network/process) present in this release that
 * the PREVIOUS published version did not have. Sourced from the audit's already-computed
 * `capabilityDelta.added` — emitted in `buildAudit`, not the rule pipeline (the delta is
 * computed after `runRules`). Pure, total, deterministic. Inert without a predecessor or delta.
 * Weighted `metadata` finding; compounds with the release-anomaly rule.
 */
export function capabilityNoveltyFindings(delta: CapabilityDelta | null, rc: ReleaseContext | undefined): Finding[] {
  if (!delta || !rc?.previousVersion) return [];
  const novel = delta.added.filter((c) => DANGEROUS.has(c.kind));
  if (novel.length === 0) return [];
  const kinds = [...new Set(novel.map((c) => c.kind))].join(", ");
  return [mkFinding({
    ruleId: "capability-novelty",
    category: "metadata",
    severity: "medium",
    message: `\`(release)\` added a ${kinds} capability that version ${rc.previousVersion} did not have — a newly dangerous behavior.`,
    evidence: novel.flatMap((c) => c.evidence).slice(0, 3),
    files: [],
  })];
}
```

- [ ] **Step 3b: Thread `releaseContext` through `buildAudit` + `runAudit` in `packages/core/src/audit.ts`**

Add the import:

```ts
import { capabilityNoveltyFindings } from "./rules/capability-novelty.js";
import type { ReleaseContext } from "./types.js";
```

In `buildAudit`, add `releaseContext?: ReleaseContext` to the `opts` type, place it on `input`, and concat the novelty findings after `capabilityDelta` is computed:

```ts
export function buildAudit(
  meta: PackageMeta,
  files: PackageFile[],
  opts: {
    mode: "full" | "diff";
    durationMs: number;
    baselineCapabilities?: Capability[];
    releaseContext?: ReleaseContext;
  } = { mode: "full", durationMs: 0 },
): Audit {
  const input: AuditInput = { meta, files, mode: opts.mode, releaseContext: opts.releaseContext };
  const ruleFindings = runRules(input);
  const capabilities = extractCapabilities(input);
  const capabilityDelta = opts.baselineCapabilities
    ? diffCapabilities(capabilities, opts.baselineCapabilities)
    : null;
  const findings = [...ruleFindings, ...capabilityNoveltyFindings(capabilityDelta, opts.releaseContext)];
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

Add `releaseContext?: ReleaseContext;` to the `AuditTarballInput` interface, and pass it into the `buildAudit` call inside `runAudit`:

```ts
  const audit = buildAudit(meta, extracted.files, { mode, durationMs: Date.now() - started, baselineCapabilities, releaseContext: input.releaseContext });
```

- [ ] **Step 4: Build + run the helper test + the existing audit suite**

```bash
npm run build
npx tsx --test packages/core/test/capability-novelty.test.ts
npx tsx --test packages/core/test/audit.test.ts
```

Expected: PASS. (If the existing audit test filename differs, run `ls packages/core/test | grep -i audit`.)

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/rules/capability-novelty.ts packages/core/src/audit.ts packages/core/test/capability-novelty.test.ts
git commit -m "feat(phase16): capability-novelty helper (signal 4) + thread releaseContext through buildAudit/runAudit"
```

---

### Task 3: Plumb packument `time` + build `releaseContext` in the proxy

**Files:**
- Modify: `packages/proxy/src/upstream.ts` (`UpstreamPackument.time`; map it in `NpmUpstream` + `LocalFixtureUpstream`)
- Modify: `packages/proxy/src/server.ts` (build `releaseContext`, pass into `runAudit`)
- Test: `packages/proxy/test/release-context.test.ts`

**Interfaces:**
- Consumes: `UpstreamPackument`, `previousVersion` (already imported in server.ts), `ReleaseContext`, `runAudit`.
- Produces: `UpstreamPackument.time?: Record<string, string>`; server passes `releaseContext` into `runAudit`.

- [ ] **Step 1: Write the failing test** (`packages/proxy/test/release-context.test.ts`)

A focused unit test for a pure `buildReleaseContext(pm, version)` helper you will add to `server.ts` and export (so it's testable without booting the proxy):

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { buildReleaseContext } from "../src/server.js";
import type { UpstreamPackument } from "../src/upstream.js";

function pm(): UpstreamPackument {
  return {
    doc: { name: "acme", versions: {} } as never,
    time: { "1.0.0": "2023-01-01T00:00:00Z", "2.0.0": "2026-01-01T00:00:00Z" },
    versions: {
      "1.0.0": { version: "1.0.0", author: null, maintainers: ["alice"], license: "MIT", signatures: null, hasProvenance: false, integrity: null, hasInstallScripts: false },
      "2.0.0": { version: "2.0.0", author: null, maintainers: ["mallory"], license: "MIT", signatures: null, hasProvenance: false, integrity: null, hasInstallScripts: false },
    },
  };
}

describe("buildReleaseContext", () => {
  test("derives previous version, its maintainers, both publish times, and version count", () => {
    const rc = buildReleaseContext(pm(), "2.0.0");
    assert.equal(rc.previousVersion, "1.0.0");
    assert.deepEqual(rc.previousMaintainers, ["alice"]);
    assert.equal(rc.previousPublishedAt, "2023-01-01T00:00:00Z");
    assert.equal(rc.currentPublishedAt, "2026-01-01T00:00:00Z");
    assert.equal(rc.versionCount, 2);
  });

  test("first version → no previous fields, versionCount 1", () => {
    const p = pm(); p.versions = { "1.0.0": p.versions["1.0.0"]! }; p.time = { "1.0.0": "2023-01-01T00:00:00Z" };
    const rc = buildReleaseContext(p, "1.0.0");
    assert.equal(rc.previousVersion, undefined);
    assert.equal(rc.versionCount, 1);
    assert.equal(rc.currentPublishedAt, "2023-01-01T00:00:00Z");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/release-context.test.ts
```

Expected: FAIL — `buildReleaseContext` not exported.

- [ ] **Step 3a: Add `time` to `UpstreamPackument` + map it (`packages/proxy/src/upstream.ts`)**

Extend the interface:

```ts
export interface UpstreamPackument {
  doc: PackumentDoc;
  versions: Record<string, UpstreamVersion>;
  /** Per-version publish timestamps from the packument `time` object (Phase 16). */
  time?: Record<string, string>;
}
```

In `NpmUpstream.getPackument` (where it builds the `UpstreamPackument` from `doc`), extract the packument's `time`:

```ts
    const time = (doc.time && typeof doc.time === "object")
      ? Object.fromEntries(Object.entries(doc.time as Record<string, unknown>).filter(([, v]) => typeof v === "string") as [string, string][])
      : undefined;
```
and include `time` in the returned `UpstreamPackument`.

In `LocalFixtureUpstream.getPackument`, read `time` from the fixture registry package entry (the registry gains a `time` map in Task 4) and include it the same way. If the registry has no `time`, leave it `undefined`.

- [ ] **Step 3b: Add + export `buildReleaseContext` and wire it in `packages/proxy/src/server.ts`**

Add the type import (`ReleaseContext` from `@sentinel/core`) and a pure exported helper:

```ts
export function buildReleaseContext(pm: UpstreamPackument, version: string): ReleaseContext {
  const prev = previousVersion(Object.keys(pm.versions), version);
  const rc: ReleaseContext = { versionCount: Object.keys(pm.versions).length };
  if (pm.time?.[version]) rc.currentPublishedAt = pm.time[version];
  if (prev) {
    rc.previousVersion = prev;
    rc.previousMaintainers = pm.versions[prev]?.maintainers;
    if (pm.time?.[prev]) rc.previousPublishedAt = pm.time[prev];
  }
  return rc;
}
```

In `auditVersion` (the public-npm path, where `prev`/`baselineTarball` are computed), build the context and pass it into `runAudit`:

```ts
    const releaseContext = buildReleaseContext(pm, version);
    const audit = await runAudit({
      meta, tarball, baselineTarball,
      signatures: vmeta.signatures, hasProvenance: vmeta.hasProvenance,
      attestations, signingKeys, trustMaterial: opts.trustMaterial,
      releaseContext,
    });
```

(Ensure `UpstreamPackument` and `ReleaseContext` are imported. `previousVersion` is already imported.)

- [ ] **Step 4: Build + run the test + existing proxy audit/tree suites**

```bash
npm run build
npx tsx --test packages/proxy/test/release-context.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS; record counts. (Existing tests unaffected — `releaseContext` is optional and additive.)

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/upstream.ts packages/proxy/src/server.ts packages/proxy/test/release-context.test.ts
git commit -m "feat(phase16): plumb packument time + buildReleaseContext; pass releaseContext into runAudit"
```

---

### Task 4: Multi-version fixtures + end-to-end proof

**Files:**
- Create: `fixtures/benign/steady-lib/{1.0.0,2.0.0}/package/...` (same-maintainer update — no anomaly)
- Create: `fixtures/malicious/hijacked-lib/{1.0.0,2.0.0}/package/...` (v2 = takeover: new maintainer + new install script)
- Create: `fixtures/malicious/freshdrop/1.0.0/package/...` (first-version + install script)
- Modify: `scripts/make-fixtures.ts` (emit per-package `time` + per-version `maintainers` into `registry.json`)
- Modify: `packages/proxy/src/upstream.ts` (`LocalFixtureUpstream` reads `time` + per-version `maintainers` from the registry — if not already covered in Task 3b)
- Test: `packages/proxy/test/release-anomaly-e2e.test.ts`

**Interfaces:**
- Consumes: `LocalFixtureUpstream`, the audit path (Tasks 1–3).
- Produces: fixtures + registry `time`/`maintainers`; an e2e proving the signals fire end-to-end.

- [ ] **Step 1: Inspect the current fixture + generator format** so the new fields match:

```bash
sed -n '1,60p' scripts/make-fixtures.ts
python3 -c "import json;d=json.load(open('fixtures/registry.json'));k=list(d['packages']);print(k);import pprint;pprint.pprint({v:list(d['packages'][k[0]]['versions'][v].keys()) for v in d['packages'][k[0]]['versions']})"
ls fixtures/benign fixtures/malicious
```

- [ ] **Step 2: Write the failing e2e** (`packages/proxy/test/release-anomaly-e2e.test.ts`)

Boot the in-process proxy with `LocalFixtureUpstream` (model on `packages/proxy/test/audit-tree-integrity-e2e.test.ts`). Audit each fixture version via `GET /-/audit/<pkg>/<version>` (or the manifest route) and assert:
- `steady-lib@2.0.0` (same maintainer, small gap): **no** `release-anomaly`/`capability-novelty` finding.
- `hijacked-lib@2.0.0` (new maintainer + new install script vs `1.0.0`): a maintainer-change finding **and** a capability-novelty (or new-install-script) finding are present, and its verdict is worse than `hijacked-lib@1.0.0` (elevated — `warn` or `block`).
- `freshdrop@1.0.0` (first version + install script): a new-package-risk finding present.
- The pre-existing malicious fixture still **blocks** (assert its verdict is `block`).

(Use the audit endpoint that returns `findings` + `verdict`; assert on `findings[].ruleId` containing `"release-anomaly"`/`"capability-novelty"` and on `verdict`.)

- [ ] **Step 3: Create the fixtures.** Each malicious `index.js`/`package.json` carries the `SYNTHETIC FIXTURE` header, uses RFC 5737 IPs, and is inert (scored as text, never executed):
  - `steady-lib` v1 + v2: benign, both maintained by the same maintainer; v2 a trivial change.
  - `hijacked-lib` v1: benign, maintainer `alice`, no install script. v2: maintainer `mallory`, a `postinstall` that (synthetically) beacons to `203.0.113.9` — the takeover shape.
  - `freshdrop` v1: a first/only version with a `postinstall` install script.

  Declare per-version `maintainers` and per-package `time` in whatever input format `make-fixtures.ts` consumes (Step 1 shows it) — e.g. a `fixture.json`/front-matter or a convention the generator reads. Update `make-fixtures.ts` to emit `time` (a map of `version → ISO`, with a large gap for `hijacked-lib` to also trip dormancy) and per-version `maintainers` into `registry.json`.

- [ ] **Step 4: Regenerate fixtures + build + run the e2e + full suite**

```bash
npm run fixtures
npm run build
npx tsx --test packages/proxy/test/release-anomaly-e2e.test.ts
npm test 2>&1 | tail -8
```

Expected: PASS; the malicious fixture still blocks; record counts.

- [ ] **Step 5: Commit**

```bash
git add fixtures scripts/make-fixtures.ts packages/proxy/src/upstream.ts packages/proxy/test/release-anomaly-e2e.test.ts
git commit -m "feat(phase16): multi-version anomaly fixtures (takeover/fresh-drop/steady) + time/maintainers in registry + e2e"
```

---

### Task 5: Docs, ADR-0029, final verification

**Files:**
- Create: `docs/adr/0029-release-anomaly-signals.md`
- Modify: `ARCHITECTURE.md` (the new rule + `releaseContext` plumbing + capability-novelty helper)
- Modify: `CLAUDE.md` (What-this-is phase list; rule count → 7; test-count line)
- Modify: `README.md` (the release-anomaly signals)

- [ ] **Step 1: Write ADR-0029** — follow the style of `docs/adr/0026-supply-chain-identity-heuristics.md`. Required content: **Context** (scoring was per-release-in-isolation; the account-takeover / dormant-resurrection / fresh-malware classes were invisible; ADR-0026 deferred maintainer-anomaly; Phase 15 added history). **Decision** (a pure `release-anomaly` rule for maintainer-change/dormancy/new-package fed by an immutable `releaseContext`; a `capability-novelty` helper emitted in `buildAudit` from the existing `capabilityDelta`; all `metadata`-category weighted findings that compound; inert by default). **Determinism** (immutable packument data only — maintainer sets, publish timestamps, version ordinal; NO wall-clock; "fresh" is intrinsic not time-relative; the grep guard; invariant #1 intact). **Consequences** (server derives `releaseContext` from the already-fetched packument — no new network; weighted-not-hard-block, so a benign version bump can't be over-blocked by any single signal). **Deferred** (per-enterprise dormancy threshold; version-cadence/semver-jump; maintainer-reputation graph; `HistoryDb`-backed comparison; `_npmUser`). **Rejected** (a `Date.now()`-based freshness signal — would break determinism; a standalone hard-block for maintainer change — too false-positive-prone on legitimate ownership transfers). **Verify and cite the exact baseline/diff ADR** with `head -1 docs/adr/00*.md | grep -i "diff\|baseline\|capability"` before referencing it; extends ADR-0026.

- [ ] **Step 2: ARCHITECTURE.md** — document the release-anomaly rule (four signals), the `ReleaseContext` plumbing (packument `time` → `buildReleaseContext` → `runAudit` → `AuditInput`), and the capability-novelty helper (emitted in `buildAudit` from `capabilityDelta`). Note determinism (no wall-clock) and inert-by-default.

- [ ] **Step 3: CLAUDE.md** — add the Phase 16 sentence to "What this is" (mirror Phase 13/15 density). Update the registered-rule count to **7** (install-scripts, secret-exfil, network-egress, obfuscation, provenance, typosquat, release-anomaly). Update the `npm test` count to the ACTUAL number from Step 5 (preserve darwin-skip caveats).

- [ ] **Step 4: README.md** — document the release-anomaly signals (maintainer change, dormancy, new-package, capability novelty) as part of the detection surface.

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
git commit -m "docs(phase16): ADR-0029 release-anomaly signals; ARCHITECTURE/CLAUDE/README"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 architecture/determinism → Task 1 (rule + `ReleaseContext`, no-clock) + Task 2 (helper); §2 four signals → Task 1 (signals 1–3) + Task 2 (signal 4); §3 plumbing + capability-novelty sourcing → Task 2 (buildAudit wiring) + Task 3 (packument `time`, `buildReleaseContext`, server); §4 testing/fixtures/DoD → each task's tests + Task 4 (multi-version fixtures + e2e) + Task 5. Determinism guard (grep for `Date.now`/`new Date(`) is in Task 1/2 tests and reaffirmed in Task 5.
- **Type consistency:** `ReleaseContext` (Task 1) consumed by `capabilityNoveltyFindings` (Task 2), `AuditTarballInput.releaseContext`/`buildAudit` opts (Task 2), and `buildReleaseContext` (Task 3); `AuditInput.releaseContext?` (Task 1) read by the rule (Task 1) and set by `buildAudit` (Task 2); `UpstreamPackument.time?` (Task 3) read by `buildReleaseContext` (Task 3) and fed by fixtures (Task 4). Severities: maintainer-turnover `high`, maintainer-added `low`, dormancy `low`, new-package `medium`, capability-novelty `medium` — pinned in Task 1/2 code and tests.
- **Known judgment calls:** signal 3 uses `meta.hasInstallScripts` (intrinsic, available pre-capability-extraction) rather than a network check the rule can't cleanly get — network-newness is covered by signal 4's `capabilityDelta`. Signal 4 lives in `buildAudit` (not the rule) because `capabilityDelta` is computed after `runRules`. `daysBetween` parses GIVEN immutable timestamps (deterministic), never the clock. `buildReleaseContext` is exported from `server.ts` purely so it's unit-testable without booting the proxy.
