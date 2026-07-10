# Permission Manifest & Approval — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic *capability inventory* to the audit engine and a proxy-enforced *approval gate*, so a human or agent must approve what a package is allowed to do before it installs (ADR-0011, stage B).

**Architecture:** `@sentinel/core` gains a pure capability-extraction pass beside the rules (findings/scoring untouched) that attaches a complete `capabilities` inventory + `capabilityDelta` to `AuditReport` (schema `1 → 2`). `@sentinel/proxy` gains an `ApprovalStore`, a pure `reconcileApproval` function, an approval API, and a gate folded into the existing `block` policy: under `block` it `403`s on `verdict==='block'` **or** an unapproved capability delta. Approval is mutable proxy state, never part of the deterministic report.

**Tech Stack:** Node 24 (≥22), TypeScript (NodeNext, ESM, `.js` import specifiers), Express 5, `tar` 7, `commander` 15, tests on `node:test` + `tsx`.

## Global Constraints

- ESM only (`"type": "module"`). Internal imports use `.js` specifiers even from `.ts` sources.
- Determinism invariant: same bytes ⇒ same report. Capabilities are pure functions of files. Add a determinism test for them; never make them depend on time/network/LLM.
- Findings and scoring (`packages/core/src/rules/`, `score.ts`) MUST NOT change behavior. The existing tests `scoring is deterministic across runs` and the malware-blocked tests stay green.
- Rules/detectors fail open individually: wrap each capability detector so one throwing detector cannot crash the audit (mirror `runRules`).
- The malicious `color-stream@1.4.1` fixture must stay **blocked for the verdict reason** (`verdict==='block'`), not merely because approval is required.
- Approval API authentication is explicitly OUT OF SCOPE (trusted single-tenant context); do not add auth, but do not pretend it exists.
- Build with `npx tsc --build --force <pkg>` if `rm` of `dist/` fails with EPERM on this mount.
- Fixtures must be synthetic, inert, header-marked `SYNTHETIC FIXTURE`, and use RFC 5737 IPs only. Re-run `npm run fixtures` after editing fixtures.

**Commands:**
- Build: `npm run build`
- Full test suite: `npm test`  (runs `node --import tsx --test packages/**/test/*.test.ts`)
- Single test file: `node --import tsx --test packages/core/test/capabilities.test.ts`
- Single test by name: `node --import tsx --test --test-name-pattern "<name>" packages/core/test/capabilities.test.ts`
- Rebuild fixtures: `npm run fixtures`

---

## File structure

**Create:**
- `packages/core/src/detect/patterns.ts` — capability matcher definitions + capture scanner + target normalization + atom key. The shared low-level detection layer.
- `packages/core/src/capabilities.ts` — `extractCapabilities()` and `diffCapabilities()`.
- `packages/core/test/capabilities.test.ts` — capability extraction + diff + determinism tests.
- `packages/proxy/src/approvals.ts` — `Approval` type + `ApprovalStore`.
- `packages/proxy/src/reconcile.ts` — `reconcileApproval()` pure gate logic + `ApprovalState`.
- `packages/proxy/test/reconcile.test.ts` — gate-logic unit tests.
- `fixtures/benign/net-fetch-lite/1.0.0/package/{package.json,index.js}` — benign, network-capable fixture (for gate tests independent of verdict).
- `fixtures/benign/net-fetch-lite/1.0.1/package/{package.json,index.js}` — same capabilities (inheritance test).
- `fixtures/benign/net-fetch-lite/1.0.2/package/{package.json,index.js}` — adds a host (re-gate test).
- `docs/adr/0013-approval-gate-via-block-and-capability-delta-trigger.md` — records the two refinements.

**Modify:**
- `packages/core/src/types.ts` — capability types + `AuditReport` schema 2 fields.
- `packages/core/src/audit.ts` — compute capabilities + delta in `buildReport`/`auditTarball`.
- `packages/core/src/index.ts` — export capability API + types.
- `packages/proxy/src/store.ts` — treat schema-1 audits as cache misses.
- `packages/proxy/src/server.ts` — approval store wiring, manifest + approval endpoints, gate, headers.
- `packages/proxy/src/index.ts` — instantiate + export `ApprovalStore`.
- `packages/proxy/test/proxy.test.ts` — end-to-end gate + approval tests.
- `packages/cli/src/format.ts` — `formatManifest()`.
- `packages/cli/src/index.ts` — `manifest`, `approve`, `preflight` commands + `planApprovals()` helper.
- `packages/cli/test/cli.test.ts` — *create* — `planApprovals` + `formatManifest` unit tests.
- `packages/proxy/public/index.html` — approvals panel.
- `fixtures/index.json` — register `net-fetch-lite`.
- `ARCHITECTURE.md` — capability pass, schema 2, gate, approval API, CLI.
- `CLAUDE.md` — update the test-count line.
- `docs/adr/0011-install-time-permission-manifest.md` — status Proposed → Accepted.

---

## Task 1: Capability types

**Files:**
- Modify: `packages/core/src/types.ts`

**Interfaces:**
- Produces: `CapabilityKind`, `Capability` (`{ kind, target, evidence }`), `CapabilityDelta` (`{ added, removed }`); `AuditReport.schema` becomes `2` with new `capabilities: Capability[]` and `capabilityDelta: CapabilityDelta | null` fields.

- [ ] **Step 1: Add the capability types and extend `AuditReport`**

In `packages/core/src/types.ts`, after the `Finding` interface (around line 37) add:

```ts
export type CapabilityKind = "network" | "filesystem" | "process" | "native";

/**
 * One concrete thing a package can do. The (kind, target) pair is the "atom"
 * diffed across versions. `target` is normalized; "*" means the target is
 * dynamic/uncomputable (so it can't churn the delta).
 */
export interface Capability {
  kind: CapabilityKind;
  target: string;
  evidence: Evidence[];
}

export interface CapabilityDelta {
  /** Atoms present in this version, absent in the prior published version. */
  added: Capability[];
  /** Atoms present in the prior published version, gone now (informational). */
  removed: Capability[];
}
```

Then change the `AuditReport` interface: replace `schema: 1;` with `schema: 2;` and add the two fields after `findings: Finding[];`:

```ts
  schema: 2;
  meta: PackageMeta;
  score: number;
  verdict: Verdict;
  findings: Finding[];
  /** Complete requested-capability inventory (NOT risk-thresholded). */
  capabilities: Capability[];
  /** Atoms added/removed vs the prior published version; null in 'full' mode. */
  capabilityDelta: CapabilityDelta | null;
```

- [ ] **Step 2: Verify it type-checks (expected to fail to build elsewhere)**

Run: `npx tsc --build --force packages/core`
Expected: errors in `audit.ts` ("missing properties `capabilities`, `capabilityDelta`" / `schema` type) — this is expected; Task 3 fixes them. The `types.ts` file itself must have no syntax errors.

- [ ] **Step 3: Commit**

```bash
git add packages/core/src/types.ts
git commit -m "feat(core): add Capability/CapabilityDelta types, bump AuditReport to schema 2"
```

---

## Task 2: Capability matchers + capture scanner (`detect/patterns.ts`)

**Files:**
- Create: `packages/core/src/detect/patterns.ts`
- Test: covered by Task 3's `capabilities.test.ts` (this module is exercised through `extractCapabilities`; no separate test file)

**Interfaces:**
- Consumes: `Capability`, `CapabilityKind`, `Evidence`, `PackageFile` from `../types.js`; `codeFiles` from `../rules/util.js`.
- Produces:
  - `CAPABILITY_MATCHERS: CapMatcher[]` where `CapMatcher = { kind: CapabilityKind; re: RegExp; group?: number }` (global regex; `group` is the capture index for the target, omitted ⇒ target `"*"`).
  - `scanForCapabilities(file: PackageFile): Capability[]` — one Capability per match (target + single Evidence).
  - `normalizeTarget(kind: CapabilityKind, raw: string): string`
  - `capabilityAtom(c: { kind: CapabilityKind; target: string }): string` → `"kind:target"`.

- [ ] **Step 1: Write the module**

Create `packages/core/src/detect/patterns.ts`:

```ts
import type { Capability, CapabilityKind, Evidence, PackageFile } from "../types.js";
import { truncate } from "../rules/util.js";

export interface CapMatcher {
  kind: CapabilityKind;
  /** Global regex scanned line-by-line. */
  re: RegExp;
  /** Capture-group index holding the concrete target; omit for a dynamic "*". */
  group?: number;
}

/**
 * Capability detectors. These CAPTURE the target (host/path/command) where the
 * rules only flag risk. Shared low-level layer for the capability pass; the
 * rules keep their own risk patterns untouched.
 */
export const CAPABILITY_MATCHERS: CapMatcher[] = [
  // network — concrete targets
  { kind: "network", re: /\bhttps?:\/\/([a-z0-9.\-]+)/gi, group: 1 },
  { kind: "network", re: /hostname\s*:\s*['"]([^'"]+)['"]/gi, group: 1 },
  // network — dynamic
  { kind: "network", re: /\b(?:fetch|axios)\s*\(/gi },
  { kind: "network", re: /\bnew\s+WebSocket\b|navigator\.sendBeacon/gi },
  { kind: "network", re: /require\(\s*['"](?:node:)?(?:https?|net|dgram|dns|tls)['"]\s*\)/gi },
  { kind: "network", re: /from\s+['"](?:node:)?(?:https?|net|dgram|dns|tls)['"]/gi },

  // filesystem — concrete sensitive targets
  { kind: "filesystem", re: /(\.npmrc)\b/gi, group: 1 },
  { kind: "filesystem", re: /(\.aws[\\/]credentials)\b/gi, group: 1 },
  { kind: "filesystem", re: /(\.ssh[\\/](?:id_rsa|id_ed25519|id_\w+))\b/gi, group: 1 },
  { kind: "filesystem", re: /(\/etc\/(?:passwd|shadow))\b/gi, group: 1 },
  // filesystem — dynamic
  { kind: "filesystem", re: /\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\b/gi },

  // process — concrete command
  { kind: "process", re: /\b(?:execSync|execFileSync|exec|execFile|spawnSync|spawn)\s*\(\s*['"]([a-z0-9_./-]+)/gi, group: 1 },
  { kind: "process", re: /\b(curl|wget)\b/gi, group: 1 },
  // process — dynamic
  { kind: "process", re: /require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]/gi },

  // native
  { kind: "native", re: /require\(\s*['"]([^'"]+\.node)['"]\s*\)/gi, group: 1 },
];

export function normalizeTarget(kind: CapabilityKind, raw: string): string {
  const t = raw.trim();
  if (kind === "network") return t.toLowerCase().replace(/:\d+$/, "");
  return t.replace(/\\/g, "/");
}

export function capabilityAtom(c: { kind: CapabilityKind; target: string }): string {
  return `${c.kind}:${c.target}`;
}

/** Scan a single file, emitting one Capability per regex match (target + evidence). */
export function scanForCapabilities(file: PackageFile): Capability[] {
  const out: Capability[] = [];
  const lines = file.content.split(/\r?\n/);
  for (const m of CAPABILITY_MATCHERS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      m.re.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = m.re.exec(line)) !== null) {
        const raw = m.group ? match[m.group] : undefined;
        const target = raw ? normalizeTarget(m.kind, raw) : "*";
        const ev: Evidence = { file: file.path, line: i + 1, snippet: truncate(line.trim(), 160) };
        out.push({ kind: m.kind, target, evidence: [ev] });
        if (!m.re.global) break;
      }
    }
  }
  return out;
}
```

- [ ] **Step 2: Verify it type-checks**

Run: `npx tsc --build --force packages/core`
Expected: still fails only in `audit.ts` (Task 3). No new errors originate in `detect/patterns.ts`.

- [ ] **Step 3: Commit**

```bash
git add packages/core/src/detect/patterns.ts
git commit -m "feat(core): add capability matchers and capture scanner"
```

---

## Task 3: `extractCapabilities` + `diffCapabilities`, wired into the audit

**Files:**
- Create: `packages/core/src/capabilities.ts`
- Modify: `packages/core/src/audit.ts`, `packages/core/src/index.ts`
- Test: `packages/core/test/capabilities.test.ts`

**Interfaces:**
- Consumes: `AuditInput`, `Capability`, `CapabilityDelta` from `./types.js`; `scanForCapabilities`, `capabilityAtom` from `./detect/patterns.js`; `codeFiles` from `./rules/util.js`.
- Produces:
  - `extractCapabilities(input: AuditInput): Capability[]` — deduped by atom (merged evidence, ≤3 per atom), sorted by `kind` then `target`. Wrapped per-file in try/catch (fail open).
  - `diffCapabilities(current: Capability[], baseline: Capability[]): CapabilityDelta`
  - `buildReport(...)` gains `opts.baselineCapabilities?: Capability[]`; sets `report.capabilities`/`report.capabilityDelta`.
  - `auditTarball` computes baseline capabilities when a baseline tarball is present.

- [ ] **Step 1: Write the failing test**

Create `packages/core/test/capabilities.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { extractCapabilities, diffCapabilities } from "../src/capabilities.js";
import { capabilityAtom } from "../src/detect/patterns.js";
import type { AuditInput, Capability, PackageFile } from "../src/types.js";

function file(path: string, content: string): PackageFile {
  return { path, content, size: content.length, changed: false };
}
function input(...files: PackageFile[]): AuditInput {
  return { meta: {} as never, files, mode: "full" };
}
const atoms = (caps: Capability[]) => caps.map(capabilityAtom);

describe("extractCapabilities", () => {
  test("captures a concrete network host from a URL", () => {
    const caps = extractCapabilities(input(file("package/a.js", 'fetch("https://api.example.com/data")')));
    assert.ok(atoms(caps).includes("network:api.example.com"));
  });

  test("captures a hardcoded IP and the curl command and credential reads", () => {
    const src = [
      'const https = require("https");',
      'https.request({ hostname: "198.51.100.23" });',
      'fs.readFileSync(os.homedir() + "/.npmrc");',
      'execSync("curl -s https://198.51.100.23/beacon");',
    ].join("\n");
    const a = atoms(extractCapabilities(input(file("package/lib/build.js", src))));
    assert.ok(a.includes("network:198.51.100.23"));
    assert.ok(a.includes("filesystem:.npmrc"));
    assert.ok(a.includes("process:curl"));
  });

  test("emits a dynamic '*' target when none is computable", () => {
    const caps = extractCapabilities(input(file("package/a.js", "const cp = require('child_process')")));
    assert.ok(atoms(caps).includes("process:*"));
  });

  test("ignores non-code files", () => {
    const caps = extractCapabilities(input(file("package/readme.md", "https://example.com")));
    assert.equal(caps.length, 0);
  });

  test("is deterministic across runs and deduped/sorted", () => {
    const src = 'fetch("https://api.example.com");fetch("https://api.example.com")';
    const a = extractCapabilities(input(file("package/a.js", src)));
    const b = extractCapabilities(input(file("package/a.js", src)));
    assert.deepEqual(atoms(a), atoms(b));
    assert.equal(atoms(a).filter((x) => x === "network:api.example.com").length, 1, "deduped");
  });
});

describe("diffCapabilities", () => {
  const net = (t: string): Capability => ({ kind: "network", target: t, evidence: [] });
  test("added = atoms present now but not in baseline", () => {
    const d = diffCapabilities([net("a.example.com"), net("b.example.com")], [net("a.example.com")]);
    assert.deepEqual(d.added.map(capabilityAtom), ["network:b.example.com"]);
    assert.deepEqual(d.removed.map(capabilityAtom), []);
  });
  test("removed = atoms in baseline but gone now", () => {
    const d = diffCapabilities([net("a.example.com")], [net("a.example.com"), net("c.example.com")]);
    assert.deepEqual(d.removed.map(capabilityAtom), ["network:c.example.com"]);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --import tsx --test packages/core/test/capabilities.test.ts`
Expected: FAIL — cannot find module `../src/capabilities.js`.

- [ ] **Step 3: Write `capabilities.ts`**

Create `packages/core/src/capabilities.ts`:

```ts
import type { AuditInput, Capability, CapabilityDelta } from "./types.js";
import { capabilityAtom, scanForCapabilities } from "./detect/patterns.js";
import { codeFiles } from "./rules/util.js";

const MAX_EVIDENCE_PER_ATOM = 3;

/**
 * Deterministic, complete requested-capability inventory for a package. A
 * superset of what trips findings — records benign-but-real capabilities too.
 * Each file is scanned under try/catch so one bad file fails open.
 */
export function extractCapabilities(input: AuditInput): Capability[] {
  const byAtom = new Map<string, Capability>();
  for (const file of codeFiles(input)) {
    let found: Capability[] = [];
    try {
      found = scanForCapabilities(file);
    } catch {
      found = [];
    }
    for (const cap of found) {
      const key = capabilityAtom(cap);
      const existing = byAtom.get(key);
      if (existing) {
        if (existing.evidence.length < MAX_EVIDENCE_PER_ATOM) {
          existing.evidence.push(...cap.evidence.slice(0, MAX_EVIDENCE_PER_ATOM - existing.evidence.length));
        }
      } else {
        byAtom.set(key, { kind: cap.kind, target: cap.target, evidence: cap.evidence.slice(0, MAX_EVIDENCE_PER_ATOM) });
      }
    }
  }
  return [...byAtom.values()].sort((a, b) =>
    a.kind === b.kind ? a.target.localeCompare(b.target) : a.kind.localeCompare(b.kind),
  );
}

/** Atom-set difference between a current and baseline inventory. */
export function diffCapabilities(current: Capability[], baseline: Capability[]): CapabilityDelta {
  const baseAtoms = new Set(baseline.map(capabilityAtom));
  const curAtoms = new Set(current.map(capabilityAtom));
  return {
    added: current.filter((c) => !baseAtoms.has(capabilityAtom(c))),
    removed: baseline.filter((c) => !curAtoms.has(capabilityAtom(c))),
  };
}
```

- [ ] **Step 4: Run the capability test to verify it passes**

Run: `node --import tsx --test packages/core/test/capabilities.test.ts`
Expected: PASS (all cases).

- [ ] **Step 5: Wire capabilities into `buildReport` and `auditTarball`**

In `packages/core/src/audit.ts`:

Add to the imports at the top:

```ts
import { extractCapabilities, diffCapabilities } from "./capabilities.js";
import type { Capability } from "./types.js";
```

Change the `buildReport` signature options to include `baselineCapabilities`, and set the new report fields. Replace the body of `buildReport` (lines ~28-55) with:

```ts
export function buildReport(
  meta: PackageMeta,
  files: PackageFile[],
  opts: {
    mode: "full" | "diff";
    durationMs: number;
    llmSummary?: string | null;
    baselineCapabilities?: Capability[];
  } = { mode: "full", durationMs: 0 },
): AuditReport {
  const input: AuditInput = { meta, files, mode: opts.mode };
  const findings = runRules(input);
  const score = scoreFindings(findings);
  const verdict = verdictFor(score, findings);
  const capabilities = extractCapabilities(input);
  const capabilityDelta = opts.baselineCapabilities
    ? diffCapabilities(capabilities, opts.baselineCapabilities)
    : null;
  return {
    schema: 2,
    meta,
    score,
    verdict,
    findings: findings.sort((a, b) => b.weight - a.weight),
    capabilities,
    capabilityDelta,
    engine: {
      version: ENGINE_VERSION,
      rules: RULES.map((r) => r.id),
      llm: null,
      mode: opts.mode,
    },
    llmSummary: opts.llmSummary ?? null,
    auditedAt: new Date().toISOString(),
    durationMs: opts.durationMs,
  };
}
```

In `auditTarball`, capture the baseline files and compute their capabilities. Replace the baseline block and the final `buildReport` call (lines ~75-93) with:

```ts
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

  return buildReport(meta, extracted.files, {
    mode,
    durationMs: Date.now() - started,
    baselineCapabilities,
  });
```

Add `AuditInput` to the existing type import block from `./types.js` (it already imports several types — add `AuditInput` if not present).

- [ ] **Step 6: Export the capability API**

In `packages/core/src/index.ts`, add after the `extractTarball` export block:

```ts
export { extractCapabilities, diffCapabilities } from "./capabilities.js";
export { capabilityAtom, scanForCapabilities, normalizeTarget } from "./detect/patterns.js";
```

(`Capability`, `CapabilityKind`, `CapabilityDelta` are already re-exported via `export * from "./types.js"`.)

- [ ] **Step 7: Add the fixture-grounded delta + determinism test**

Append to `packages/core/test/capabilities.test.ts`:

```ts
import { auditTarball } from "../src/index.js";
import { ensureFixtures, tarball } from "./helpers.js";

const baseMeta = {
  author: null, maintainers: [] as string[], license: null,
  hasInstallScripts: false, signatureStatus: "unknown" as const,
};

describe("capabilities in the audit report (color-stream fixture)", () => {
  test("malicious release surfaces network/filesystem/process capabilities as a delta", async () => {
    ensureFixtures();
    const r = await auditTarball({
      meta: { name: "color-stream", version: "1.4.1", ...baseMeta },
      tarball: tarball("color-stream", "1.4.1"),
      baselineTarball: tarball("color-stream", "1.4.0"),
    });
    assert.equal(r.schema, 2);
    const kinds = new Set(r.capabilities.map((c) => c.kind));
    assert.ok(kinds.has("network") && kinds.has("filesystem") && kinds.has("process"));
    assert.ok(r.capabilityDelta);
    assert.ok(r.capabilityDelta.added.length > 0, "new caps appear as a delta vs 1.4.0");
  });

  test("capabilities are deterministic across runs", async () => {
    ensureFixtures();
    const a = await auditTarball({ meta: { name: "color-stream", version: "1.4.1", ...baseMeta }, tarball: tarball("color-stream", "1.4.1") });
    const b = await auditTarball({ meta: { name: "color-stream", version: "1.4.1", ...baseMeta }, tarball: tarball("color-stream", "1.4.1") });
    assert.deepEqual(a.capabilities.map(capabilityAtom), b.capabilities.map(capabilityAtom));
  });
});
```

- [ ] **Step 8: Build and run the full core suite**

Run: `npx tsc --build --force packages/core && node --import tsx --test packages/core/test/*.test.ts`
Expected: PASS for both `audit.test.ts` (unchanged behavior — scoring/determinism still green) and `capabilities.test.ts`.

- [ ] **Step 9: Commit**

```bash
git add packages/core/src/capabilities.ts packages/core/src/audit.ts packages/core/src/index.ts packages/core/test/capabilities.test.ts
git commit -m "feat(core): compute capability inventory + delta in the audit report"
```

---

## Task 4: AuditStore treats schema-1 entries as cache misses

**Files:**
- Modify: `packages/proxy/src/store.ts`

**Interfaces:**
- Consumes: `AuditReport` (now schema 2).
- Produces: no signature change; `AuditStore` silently drops persisted schema-1 rows on load so a stale JSON log can't return a report without `capabilities`.

- [ ] **Step 1: Write the failing test**

Create `packages/proxy/test/store.test.ts`:

```ts
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { AuditStore } from "../src/store.js";

describe("AuditStore schema handling", () => {
  test("drops persisted schema-1 audits on load", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-store-"));
    const file = join(dir, "audits.json");
    const legacy = [{
      key: "old@1.0.0", name: "old", version: "1.0.0",
      report: { schema: 1, meta: { integrity: "sha512-legacy" }, verdict: "allow", score: 100, findings: [] },
    }];
    writeFileSync(file, JSON.stringify(legacy));
    const store = new AuditStore(file);
    assert.equal(store.get("sha512-legacy"), undefined, "schema-1 entry is not served from cache");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/proxy/test/store.test.ts`
Expected: FAIL — `store.get("sha512-legacy")` returns the legacy row.

- [ ] **Step 3: Implement the guard**

In `packages/proxy/src/store.ts`, in the constructor loop (around line 26), skip non-schema-2 rows:

```ts
        const rows = JSON.parse(readFileSync(file, "utf8")) as StoredAudit[];
        for (const r of rows) {
          if (r.report?.schema !== 2) continue; // re-audit anything older
          this.index(r.report.meta.integrity ?? r.key, r);
        }
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/proxy/test/store.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/store.ts packages/proxy/test/store.test.ts
git commit -m "fix(proxy): treat persisted schema-1 audits as cache misses"
```

---

## Task 5: ApprovalStore

**Files:**
- Create: `packages/proxy/src/approvals.ts`
- Test: `packages/proxy/test/approvals.test.ts`

**Interfaces:**
- Consumes: `Capability` from `@sentinel/core`; `cmpSemver` from `./upstream.js`.
- Produces:
  - `type ApprovalDecision = "approved" | "denied"`
  - `interface Approval { name; version; integrity; decision: ApprovalDecision; approvedCapabilities: Capability[]; actor: { type: "human" | "agent"; id: string }; reason?: string; decidedAt: string }`
  - `class ApprovalStore` with `get(integrity)`, `put(approval): Approval`, `remove(integrity): boolean`, `latestApprovedFor(name): Approval | undefined` (highest semver with `decision==="approved"`), `recent(limit=50): Approval[]`.

- [ ] **Step 1: Write the failing test**

Create `packages/proxy/test/approvals.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { ApprovalStore, type Approval } from "../src/approvals.js";

function approval(over: Partial<Approval> = {}): Approval {
  return {
    name: "pkg", version: "1.0.0", integrity: "sha512-a", decision: "approved",
    approvedCapabilities: [], actor: { type: "agent", id: "ci" }, decidedAt: "2026-06-24T00:00:00.000Z",
    ...over,
  };
}

describe("ApprovalStore", () => {
  test("put/get by integrity", () => {
    const s = new ApprovalStore();
    s.put(approval({ integrity: "sha512-x" }));
    assert.equal(s.get("sha512-x")?.decision, "approved");
    assert.equal(s.get("sha512-missing"), undefined);
  });

  test("remove revokes", () => {
    const s = new ApprovalStore();
    s.put(approval({ integrity: "sha512-x" }));
    assert.equal(s.remove("sha512-x"), true);
    assert.equal(s.get("sha512-x"), undefined);
  });

  test("latestApprovedFor returns the highest approved semver, ignoring denials", () => {
    const s = new ApprovalStore();
    s.put(approval({ version: "1.0.0", integrity: "a", decision: "approved" }));
    s.put(approval({ version: "1.2.0", integrity: "b", decision: "approved" }));
    s.put(approval({ version: "1.3.0", integrity: "c", decision: "denied" }));
    assert.equal(s.latestApprovedFor("pkg")?.version, "1.2.0");
    assert.equal(s.latestApprovedFor("other"), undefined);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/proxy/test/approvals.test.ts`
Expected: FAIL — cannot find module `../src/approvals.js`.

- [ ] **Step 3: Implement `ApprovalStore`**

Create `packages/proxy/src/approvals.ts`:

```ts
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { Capability } from "@sentinel/core";
import { cmpSemver } from "./upstream.js";

export type ApprovalDecision = "approved" | "denied";

export interface Approval {
  name: string;
  version: string;
  integrity: string;
  decision: ApprovalDecision;
  /** Server-recorded snapshot of the audited capabilities at decision time. */
  approvedCapabilities: Capability[];
  actor: { type: "human" | "agent"; id: string };
  reason?: string;
  decidedAt: string; // ISO-8601
}

/**
 * Mutable approval state, keyed by the immutable integrity hash. Mirrors
 * AuditStore (in-memory + optional JSON-file). Never part of the audit report.
 */
export class ApprovalStore {
  private byIntegrity = new Map<string, Approval>();
  private order: string[] = [];

  constructor(private readonly file?: string) {
    if (file && existsSync(file)) {
      try {
        const rows = JSON.parse(readFileSync(file, "utf8")) as Approval[];
        for (const a of rows) this.index(a);
      } catch {
        /* start empty on a corrupt log */
      }
    }
  }

  get(integrity: string | null | undefined): Approval | undefined {
    return integrity ? this.byIntegrity.get(integrity) : undefined;
  }

  put(approval: Approval): Approval {
    this.index(approval);
    this.persist();
    return approval;
  }

  remove(integrity: string): boolean {
    const had = this.byIntegrity.delete(integrity);
    if (had) {
      this.order = this.order.filter((k) => k !== integrity);
      this.persist();
    }
    return had;
  }

  /** Highest-semver approval with decision 'approved' for a package name. */
  latestApprovedFor(name: string): Approval | undefined {
    let best: Approval | undefined;
    for (const a of this.byIntegrity.values()) {
      if (a.name !== name || a.decision !== "approved") continue;
      if (!best || cmpSemver(a.version, best.version) > 0) best = a;
    }
    return best;
  }

  recent(limit = 50): Approval[] {
    return this.order
      .slice(-limit)
      .reverse()
      .map((k) => this.byIntegrity.get(k))
      .filter((x): x is Approval => Boolean(x));
  }

  private index(a: Approval): void {
    if (!this.byIntegrity.has(a.integrity)) this.order.push(a.integrity);
    this.byIntegrity.set(a.integrity, a);
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

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/proxy/test/approvals.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/approvals.ts packages/proxy/test/approvals.test.ts
git commit -m "feat(proxy): add ApprovalStore keyed by integrity"
```

---

## Task 6: `reconcileApproval` gate logic

**Files:**
- Create: `packages/proxy/src/reconcile.ts`
- Test: `packages/proxy/test/reconcile.test.ts`

**Interfaces:**
- Consumes: `Capability`, `capabilityAtom` from `@sentinel/core`; `Approval` from `./approvals.js`.
- Produces:
  - `type ApprovalState = "approved" | "inherited" | "required" | "denied" | "n-a"`
  - `interface Reconciliation { state: ApprovalState; approvalRequired: Capability[]; inheritedFrom: string | null }`
  - `function reconcileApproval(input: { capabilities: Capability[]; explicit?: Approval; priorApproved?: Approval }): Reconciliation`

- [ ] **Step 1: Write the failing test**

Create `packages/proxy/test/reconcile.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Capability } from "@sentinel/core";
import { reconcileApproval } from "../src/reconcile.js";
import type { Approval } from "../src/approvals.js";

const net = (t: string): Capability => ({ kind: "network", target: t, evidence: [] });
function approval(caps: Capability[], over: Partial<Approval> = {}): Approval {
  return { name: "pkg", version: "1.0.0", integrity: "x", decision: "approved",
    approvedCapabilities: caps, actor: { type: "agent", id: "ci" }, decidedAt: "t", ...over };
}

describe("reconcileApproval", () => {
  test("n-a when there are no capabilities", () => {
    assert.equal(reconcileApproval({ capabilities: [] }).state, "n-a");
  });
  test("approved when an explicit approval exists for this integrity", () => {
    const r = reconcileApproval({ capabilities: [net("a")], explicit: approval([net("a")]) });
    assert.equal(r.state, "approved");
  });
  test("denied when an explicit denial exists", () => {
    const r = reconcileApproval({ capabilities: [net("a")], explicit: approval([], { decision: "denied" }) });
    assert.equal(r.state, "denied");
  });
  test("required at first sight (no prior approval)", () => {
    const r = reconcileApproval({ capabilities: [net("a")] });
    assert.equal(r.state, "required");
    assert.deepEqual(r.approvalRequired.map((c) => c.target), ["a"]);
  });
  test("inherited when caps are a subset of a prior approved version", () => {
    const r = reconcileApproval({ capabilities: [net("a")], priorApproved: approval([net("a")], { version: "1.0.0" }) });
    assert.equal(r.state, "inherited");
    assert.equal(r.inheritedFrom, "1.0.0");
    assert.equal(r.approvalRequired.length, 0);
  });
  test("required when a NEW atom appears vs the prior approved version", () => {
    const r = reconcileApproval({ capabilities: [net("a"), net("b")], priorApproved: approval([net("a")], { version: "1.0.0" }) });
    assert.equal(r.state, "required");
    assert.deepEqual(r.approvalRequired.map((c) => c.target), ["b"]);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/proxy/test/reconcile.test.ts`
Expected: FAIL — cannot find module `../src/reconcile.js`.

- [ ] **Step 3: Implement `reconcileApproval`**

Create `packages/proxy/src/reconcile.ts`:

```ts
import { capabilityAtom, type Capability } from "@sentinel/core";
import type { Approval } from "./approvals.js";

export type ApprovalState = "approved" | "inherited" | "required" | "denied" | "n-a";

export interface Reconciliation {
  state: ApprovalState;
  /** Atoms not covered by an explicit or inherited approval — what must be approved. */
  approvalRequired: Capability[];
  /** Version whose approval covers this one (inherited state), else null. */
  inheritedFrom: string | null;
}

/**
 * Pure gate decision. `explicit` is the approval recorded for THIS integrity;
 * `priorApproved` is the latest approved record for a prior version (its atoms
 * are inherited). First sight of any capability requires approval; thereafter
 * only a NEW atom re-triggers.
 */
export function reconcileApproval(input: {
  capabilities: Capability[];
  explicit?: Approval;
  priorApproved?: Approval;
}): Reconciliation {
  const { capabilities, explicit, priorApproved } = input;
  if (capabilities.length === 0) return { state: "n-a", approvalRequired: [], inheritedFrom: null };
  if (explicit?.decision === "approved") return { state: "approved", approvalRequired: [], inheritedFrom: null };
  if (explicit?.decision === "denied") return { state: "denied", approvalRequired: [], inheritedFrom: null };

  const inherited = new Set((priorApproved?.approvedCapabilities ?? []).map(capabilityAtom));
  const approvalRequired = capabilities.filter((c) => !inherited.has(capabilityAtom(c)));
  if (approvalRequired.length === 0 && priorApproved) {
    return { state: "inherited", approvalRequired: [], inheritedFrom: priorApproved.version };
  }
  return { state: "required", approvalRequired, inheritedFrom: null };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `node --import tsx --test packages/proxy/test/reconcile.test.ts`
Expected: PASS (all six cases).

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/reconcile.ts packages/proxy/test/reconcile.test.ts
git commit -m "feat(proxy): add pure reconcileApproval gate logic"
```

---

## Task 7: Benign network-capable fixture

**Files:**
- Create: `fixtures/benign/net-fetch-lite/1.0.0/package/package.json`, `.../1.0.0/package/index.js`
- Create: `fixtures/benign/net-fetch-lite/1.0.1/package/package.json`, `.../1.0.1/package/index.js`
- Create: `fixtures/benign/net-fetch-lite/1.0.2/package/package.json`, `.../1.0.2/package/index.js`
- Modify: `fixtures/index.json`

**Interfaces:**
- Produces: a benign package that scores `allow` but carries a `network` capability — needed to test the approval gate independent of a `block` verdict. 1.0.0 and 1.0.1 share the same capability atom (`network:api.example.com`); 1.0.2 adds `network:telemetry.example.com`.

- [ ] **Step 1: Create version 1.0.0**

`fixtures/benign/net-fetch-lite/1.0.0/package/package.json`:

```json
{
  "name": "net-fetch-lite",
  "version": "1.0.0",
  "description": "Tiny helper that fetches a config blob.",
  "main": "index.js",
  "license": "MIT",
  "author": "nfl-maintainer <nfl@example.com>"
}
```

`fixtures/benign/net-fetch-lite/1.0.0/package/index.js`:

```js
/*
 * ============================ SYNTHETIC FIXTURE ============================
 * Inert benign test data for Sentinel. Uses example.com (no real egress).
 * Demonstrates a legitimate network capability that still scores `allow`.
 * ==========================================================================
 */
"use strict";
async function getConfig() {
  const res = await fetch("https://api.example.com/config");
  return res.json();
}
module.exports = { getConfig };
```

- [ ] **Step 2: Create version 1.0.1 (identical capabilities, different bytes)**

`fixtures/benign/net-fetch-lite/1.0.1/package/package.json`: same as 1.0.0 but `"version": "1.0.1"`.

`fixtures/benign/net-fetch-lite/1.0.1/package/index.js`: same header, then:

```js
"use strict";
// 1.0.1: identical capability surface (api.example.com), refactored body.
async function getConfig() {
  const url = "https://api.example.com/config";
  const res = await fetch(url);
  return res.json();
}
module.exports = { getConfig };
```

- [ ] **Step 3: Create version 1.0.2 (adds a host → new atom)**

`fixtures/benign/net-fetch-lite/1.0.2/package/package.json`: same but `"version": "1.0.2"`.

`fixtures/benign/net-fetch-lite/1.0.2/package/index.js`: same header, then:

```js
"use strict";
// 1.0.2: ADDS a telemetry host — a new network capability atom vs 1.0.x.
async function getConfig() {
  const res = await fetch("https://api.example.com/config");
  await fetch("https://telemetry.example.com/event", { method: "POST" });
  return res.json();
}
module.exports = { getConfig };
```

- [ ] **Step 4: Register the fixture**

In `fixtures/index.json`, add inside `"packages"` (after `leftpad-lite`):

```json
    "net-fetch-lite": {
      "class": "benign",
      "expect": { "verdict": "allow" },
      "versions": {
        "1.0.0": { "signatureStatus": "signed" },
        "1.0.1": { "signatureStatus": "signed" },
        "1.0.2": { "signatureStatus": "signed" }
      }
    },
```

- [ ] **Step 5: Pack the fixtures and verify**

Run: `npm run fixtures`
Expected: output includes `packed net-fetch-lite@1.0.0`, `@1.0.1`, `@1.0.2`, and `wrote fixtures/registry.json`.

Then sanity-check the capability + verdict:

Run: `node --import tsx -e "import('@sentinel/core').then(async c => { const {readFileSync}=await import('node:fs'); const t=(v)=>readFileSync('fixtures/.tarballs/net-fetch-lite-'+v+'.tgz'); const r=await c.auditTarball({meta:{name:'net-fetch-lite',version:'1.0.0',author:null,maintainers:[],license:null,hasInstallScripts:false,signatureStatus:'signed'},tarball:t('1.0.0')}); console.log(r.verdict, r.capabilities.map(x=>x.kind+':'+x.target)); })"`
Expected: `allow` and a list including `network:api.example.com`.

- [ ] **Step 6: Commit**

```bash
git add fixtures/benign/net-fetch-lite fixtures/index.json fixtures/registry.json fixtures/.tarballs
git commit -m "test(fixtures): add benign net-fetch-lite (network-capable, allow verdict)"
```

---

## Task 8: Wire the gate, manifest, and approval API into the server

**Files:**
- Modify: `packages/proxy/src/server.ts`, `packages/proxy/src/index.ts`
- Test: `packages/proxy/test/proxy.test.ts`

**Interfaces:**
- Consumes: `ApprovalStore`, `Approval` from `./approvals.js`; `reconcileApproval`, `ApprovalState` from `./reconcile.js`; `AuditStore`.
- Produces:
  - `ServerOptions` gains `approvals: ApprovalStore`.
  - `GET /-/manifest/:pkg/:version` → `{ meta, score, verdict, findings, capabilities, capabilityDelta, approvalRequired, approvalState, inheritedFrom }`.
  - `POST /-/approvals` (single object or array of `{ name, version, integrity, decision, actor, reason? }`) → `{ approvals: Approval[] }`.
  - `GET /-/approvals` → `{ approvals: Approval[] }`.
  - `DELETE /-/approvals/:integrity` → `{ revoked: boolean }`.
  - Tarball route sets `x-sentinel-capabilities` + `x-sentinel-approval` headers always; under `block`, `403`s on `verdict==='block'`, `approval required`, or `approval denied`.

- [ ] **Step 1: Write the failing end-to-end tests**

In `packages/proxy/test/proxy.test.ts`, add `ApprovalStore` to the imports:

```ts
import { ApprovalStore } from "../src/approvals.js";
```

In the `before` hook, pass an approval store to `createServer` and keep a reference. Replace the `createServer({...})` call with:

```ts
    approvals = new ApprovalStore();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals,
      policy: "block",
    });
```

and declare `let approvals: ApprovalStore;` alongside `let server`/`let base`.

Then add a new `describe` block at the end of the file:

```ts
describe("approval gate (block policy, local fixtures)", () => {
  let server: Server;
  let base: string;
  let approvals: ApprovalStore;

  before(async () => {
    ensureFixtures();
    approvals = new ApprovalStore();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals,
      policy: "block",
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        resolve();
      });
    });
  });
  after(() => server?.close());

  async function manifest(pkg: string, version: string) {
    return (await fetch(`${base}/-/manifest/${pkg}/${version}`)).json();
  }
  async function approve(m: { name: string; version: string; integrity: string }) {
    return fetch(`${base}/-/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...m, decision: "approved", actor: { type: "agent", id: "test" } }),
    });
  }

  test("manifest reports capabilities and 'required' at first sight", async () => {
    const m = await manifest("net-fetch-lite", "1.0.0");
    assert.equal(m.verdict, "allow");
    assert.equal(m.approvalState, "required");
    assert.ok(m.approvalRequired.some((c: { target: string }) => c.target === "api.example.com"));
  });

  test("tarball is gated with 403 'approval required' before approval", async () => {
    const res = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.0.tgz`);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-sentinel-approval"), "required");
    assert.match((await res.json()).error, /approval required/i);
  });

  test("after approval the tarball serves", async () => {
    const m = await manifest("net-fetch-lite", "1.0.0");
    const r = await approve({ name: "net-fetch-lite", version: "1.0.0", integrity: m.meta.integrity });
    assert.equal(r.status, 200);
    const res = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.0.tgz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-sentinel-approval"), "approved");
  });

  test("a later version with the same capabilities is inherited (served, no prompt)", async () => {
    const m = await manifest("net-fetch-lite", "1.0.1");
    assert.equal(m.approvalState, "inherited");
    const res = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.1.tgz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-sentinel-approval"), "inherited");
  });

  test("a new capability atom re-gates the install", async () => {
    const m = await manifest("net-fetch-lite", "1.0.2");
    assert.equal(m.approvalState, "required");
    assert.ok(m.approvalRequired.some((c: { target: string }) => c.target === "telemetry.example.com"));
    const res = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.2.tgz`);
    assert.equal(res.status, 403);
  });

  test("revoke removes the approval", async () => {
    const m = await manifest("net-fetch-lite", "1.0.0");
    const del = await fetch(`${base}/-/approvals/${encodeURIComponent(m.meta.integrity)}`, { method: "DELETE" });
    assert.equal((await del.json()).revoked, true);
    const res = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.0.tgz`);
    assert.equal(res.status, 403);
  });

  test("malicious color-stream is blocked for the VERDICT reason, not approval", async () => {
    // Pre-approve its capabilities so an approval-required 403 cannot mask the verdict.
    const m = await manifest("color-stream", "1.4.1");
    await fetch(`${base}/-/approvals`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "color-stream", version: "1.4.1", integrity: m.meta.integrity, decision: "approved", actor: { type: "agent", id: "test" } }),
    });
    const res = await fetch(`${base}/color-stream/-/color-stream-1.4.1.tgz`);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-sentinel-verdict"), "block");
    assert.match((await res.json()).error, /blocked by Sentinel/i);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/proxy/test/proxy.test.ts`
Expected: FAIL — `createServer` rejects the `approvals` option / `/-/manifest` 404s.

- [ ] **Step 3: Implement the server changes**

In `packages/proxy/src/server.ts`:

Add imports:

```ts
import { ApprovalStore, type Approval } from "./approvals.js";
import { reconcileApproval, type ApprovalState } from "./reconcile.js";
```

Extend `ServerOptions` with:

```ts
  approvals: ApprovalStore;
```

In `createServer`, destructure it and add JSON body parsing right after `app.disable("x-powered-by");`:

```ts
  const { upstream, store, approvals } = opts;
  const policy: ProxyPolicy = opts.policy ?? "observe";
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "1mb" }));
```

Add a reconciliation helper after `auditVersion`:

```ts
  function reconcile(report: AuditReport) {
    const explicit = approvals.get(report.meta.integrity);
    const priorApproved = approvals.latestApprovedFor(report.meta.name);
    return reconcileApproval({ capabilities: report.capabilities, explicit, priorApproved });
  }
```

Add the manifest route (after the existing `/-/audit` route):

```ts
  app.get(/^\/-\/manifest\/(.+)\/([^/]+)$/, async (req, res) => {
    const pkg = decodeURIComponent(req.params[0] ?? "");
    const version = req.params[1] ?? "";
    try {
      const { report } = await auditVersion(pkg, version);
      const rec = reconcile(report);
      res.json({
        meta: report.meta, score: report.score, verdict: report.verdict,
        findings: report.findings, capabilities: report.capabilities,
        capabilityDelta: report.capabilityDelta,
        approvalRequired: rec.approvalRequired, approvalState: rec.state,
        inheritedFrom: rec.inheritedFrom,
      });
    } catch (err) {
      sendError(res, err);
    }
  });
```

Add the approval routes:

```ts
  app.post("/-/approvals", (req, res) => {
    const body = Array.isArray(req.body) ? req.body : [req.body];
    const recorded: Approval[] = [];
    try {
      for (const d of body) {
        if (!d?.name || !d?.version || !d?.integrity || (d.decision !== "approved" && d.decision !== "denied")) {
          return res.status(400).json({ error: "each approval needs name, version, integrity, decision(approved|denied)" });
        }
        const audited = store.get(d.integrity);
        if (!audited) {
          return res.status(400).json({ error: `audit ${d.name}@${d.version} first (no report for that integrity)` });
        }
        recorded.push(approvals.put({
          name: d.name, version: d.version, integrity: d.integrity, decision: d.decision,
          approvedCapabilities: audited.report.capabilities,
          actor: d.actor ?? { type: "human", id: "unknown" },
          reason: d.reason,
          decidedAt: new Date().toISOString(),
        }));
      }
    } catch (err) {
      return sendError(res, err);
    }
    res.json({ approvals: recorded });
  });

  app.get("/-/approvals", (_req, res) => {
    res.json({ approvals: approvals.recent(50) });
  });

  app.delete(/^\/-\/approvals\/(.+)$/, (req, res) => {
    const integrity = decodeURIComponent(req.params[0] ?? "");
    res.json({ revoked: approvals.remove(integrity) });
  });
```

In the tarball branch of the catch-all route, replace the header/policy block (currently lines ~111-124) with:

```ts
        const { report, tarball } = await auditVersion(pkg, version);
        const rec = reconcile(report);
        res.setHeader("x-sentinel-score", String(report.score));
        res.setHeader("x-sentinel-verdict", report.verdict);
        res.setHeader("x-sentinel-findings", String(report.findings.length));
        res.setHeader("x-sentinel-capabilities", String(report.capabilities.length));
        res.setHeader("x-sentinel-approval", rec.state);
        if (policy === "block") {
          if (report.verdict === "block") {
            return res.status(403).json({
              error: "blocked by Sentinel policy",
              package: `${pkg}@${version}`,
              score: report.score, verdict: report.verdict,
              findings: report.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })),
            });
          }
          if (rec.state === "denied") {
            return res.status(403).json({ error: "approval denied by Sentinel policy", package: `${pkg}@${version}` });
          }
          if (rec.state === "required") {
            return res.status(403).json({
              error: "approval required by Sentinel policy",
              package: `${pkg}@${version}`,
              approvalRequired: rec.approvalRequired,
              findings: report.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })),
            });
          }
        }
        res.setHeader("content-type", "application/octet-stream");
        return res.send(tarball);
```

In `packages/proxy/src/index.ts`:

Add the export and instantiation. Add to the export block:

```ts
export { ApprovalStore } from "./approvals.js";
```

In `main()`, create the store and pass it:

```ts
  const store = new AuditStore(process.env.SENTINEL_STORE);
  const approvals = new ApprovalStore(process.env.SENTINEL_APPROVALS);
  ...
  const app = createServer({ upstream, store, approvals, policy, publicDir });
```

- [ ] **Step 4: Run the proxy suite to verify it passes**

Run: `npx tsc --build --force packages/proxy && node --import tsx --test packages/proxy/test/*.test.ts`
Expected: PASS — the original proxy tests plus the new gate/approval block. (The original "malicious tarball is BLOCKED" test still passes: color-stream has no prior approval, but `verdict==='block'` short-circuits first.)

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/src/index.ts packages/proxy/test/proxy.test.ts
git commit -m "feat(proxy): approval gate, manifest endpoint, and approval API"
```

---

## Task 9: CLI — manifest, approve, preflight

**Files:**
- Modify: `packages/cli/src/format.ts`, `packages/cli/src/index.ts`
- Test: `packages/cli/test/cli.test.ts` (create)

**Interfaces:**
- Consumes: `Capability`, `CapabilityKind` from `@sentinel/core`.
- Produces:
  - `format.ts`: `interface Manifest { meta: { name: string; version: string; integrity: string }; verdict: string; approvalState: string; capabilities: Capability[]; approvalRequired: Capability[]; inheritedFrom: string | null }` and `formatManifest(m: Manifest): string`.
  - `index.ts`: `planApprovals(manifests: Manifest[]): { name: string; version: string; integrity: string }[]` (returns the subset whose `approvalState === "required"`), plus `manifest`, `approve`, `preflight` commands.

- [ ] **Step 1: Write the failing test**

Create `packages/cli/test/cli.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { formatManifest, type Manifest } from "../src/format.js";
import { planApprovals } from "../src/index.js";

const base: Manifest = {
  meta: { name: "net-fetch-lite", version: "1.0.0", integrity: "sha512-x" },
  verdict: "allow", approvalState: "required", inheritedFrom: null,
  capabilities: [{ kind: "network", target: "api.example.com", evidence: [] }],
  approvalRequired: [{ kind: "network", target: "api.example.com", evidence: [] }],
};

describe("CLI manifest formatting", () => {
  test("formatManifest renders the package, state, and required atoms", () => {
    const out = formatManifest(base);
    assert.match(out, /net-fetch-lite@1\.0\.0/);
    assert.match(out, /network/);
    assert.match(out, /api\.example\.com/);
    assert.match(out, /required/i);
  });
});

describe("planApprovals", () => {
  test("selects only manifests whose state is 'required'", () => {
    const inherited: Manifest = { ...base, meta: { ...base.meta, version: "1.0.1", integrity: "sha512-y" }, approvalState: "inherited", approvalRequired: [] };
    const plan = planApprovals([base, inherited]);
    assert.deepEqual(plan, [{ name: "net-fetch-lite", version: "1.0.0", integrity: "sha512-x" }]);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/cli/test/cli.test.ts`
Expected: FAIL — `formatManifest`/`planApprovals` not exported.

- [ ] **Step 3: Implement `formatManifest`**

In `packages/cli/src/format.ts`, add the import and the new export:

```ts
import type { AuditReport, Capability, CapabilityKind, Severity, Verdict } from "@sentinel/core";
```

Append:

```ts
export interface Manifest {
  meta: { name: string; version: string; integrity: string };
  verdict: string;
  approvalState: string;
  capabilities: Capability[];
  approvalRequired: Capability[];
  inheritedFrom: string | null;
}

const stateColor: Record<string, string> = {
  approved: C.green, inherited: C.green, required: C.yellow, denied: C.red, "n-a": C.gray,
};

export function formatManifest(m: Manifest): string {
  const L: string[] = [];
  L.push("");
  L.push(c(C.bold, `  ${m.meta.name}@${m.meta.version}`));
  L.push(c(C.gray, `  ${"─".repeat(56)}`));
  L.push(`  verdict    ${c(C.bold + (verdictColor[m.verdict as Verdict] ?? C.gray), m.verdict.toUpperCase())}`);
  L.push(`  approval   ${c(C.bold + (stateColor[m.approvalState] ?? C.gray), m.approvalState.toUpperCase())}` +
    (m.inheritedFrom ? c(C.gray, ` (inherited from ${m.inheritedFrom})`) : ""));
  const byKind = new Map<CapabilityKind, string[]>();
  for (const cap of m.capabilities) {
    const list = byKind.get(cap.kind) ?? [];
    list.push(cap.target);
    byKind.set(cap.kind, list);
  }
  L.push("");
  L.push(c(C.bold, `  capabilities (${m.capabilities.length})`));
  if (m.capabilities.length === 0) L.push(c(C.gray, "  none"));
  for (const [kind, targets] of byKind) {
    L.push(`  ${kind.padEnd(11)}${c(C.gray, [...new Set(targets)].join(", "))}`);
  }
  if (m.approvalRequired.length) {
    L.push("");
    L.push(c(C.yellow, `  requires approval (${m.approvalRequired.length} new):`));
    for (const cap of m.approvalRequired) L.push(`  ${c(C.yellow, "›")} ${cap.kind}: ${cap.target}`);
  }
  L.push("");
  return L.join("\n");
}
```

- [ ] **Step 4: Implement the CLI commands + `planApprovals`**

In `packages/cli/src/index.ts`:

Add to the format import:

```ts
import { formatReport, formatManifest, verdictExitCode, type Manifest } from "./format.js";
```

Add the exported helper near the bottom (before the helper functions):

```ts
export function planApprovals(manifests: Manifest[]): { name: string; version: string; integrity: string }[] {
  return manifests
    .filter((m) => m.approvalState === "required")
    .map((m) => ({ name: m.meta.name, version: m.meta.version, integrity: m.meta.integrity }));
}

async function fetchManifest(proxy: string, pkg: string, version: string): Promise<Manifest> {
  const res = await fetch(`${proxy}/-/manifest/${encodeURIComponent(pkg)}/${encodeURIComponent(version)}`);
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? `manifest failed: ${res.status}`);
  }
  return (await res.json()) as Manifest;
}

async function postApproval(
  proxy: string,
  decision: { name: string; version: string; integrity: string }[],
  approved: boolean,
  reason?: string,
): Promise<void> {
  const res = await fetch(`${proxy}/-/approvals`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(decision.map((d) => ({
      ...d, decision: approved ? "approved" : "denied",
      actor: { type: "agent", id: process.env.USER ?? "cli" }, reason,
    }))),
  });
  if (!res.ok) throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? `approval failed: ${res.status}`);
}
```

Add the three commands before `program.parseAsync();`:

```ts
program
  .command("manifest")
  .description("Show a package's requested capabilities and approval state (no install).")
  .argument("<package>")
  .argument("[version]")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--json", "emit raw JSON", false)
  .action(async (pkg: string, version: string | undefined, opts: { proxy: string; json: boolean }) => {
    try {
      const v = version ?? (await resolveLatest(opts.proxy, pkg));
      const m = await fetchManifest(opts.proxy, pkg, v);
      console.log(opts.json ? JSON.stringify(m, null, 2) : formatManifest(m));
    } catch (err) {
      fail(err, opts.proxy);
    }
  });

program
  .command("approve")
  .description("Record an approval (or denial) for a package version's capabilities.")
  .argument("<package>")
  .argument("<version>")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--deny", "record a denial instead of an approval", false)
  .option("--reason <reason>", "optional rationale recorded with the decision")
  .action(async (pkg: string, version: string, opts: { proxy: string; deny: boolean; reason?: string }) => {
    try {
      const m = await fetchManifest(opts.proxy, pkg, version);
      await postApproval(opts.proxy, [{ name: m.meta.name, version: m.meta.version, integrity: m.meta.integrity }], !opts.deny, opts.reason);
      console.log(`${opts.deny ? "denied" : "approved"} ${pkg}@${version}`);
    } catch (err) {
      fail(err, opts.proxy);
    }
  });

program
  .command("preflight")
  .description("Resolve a package's tree, show capabilities needing approval, and optionally approve them.")
  .argument("<package>")
  .argument("[version]")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--approve", "approve every capability the tree requires", false)
  .action(async (pkg: string, version: string | undefined, opts: { proxy: string; approve: boolean }) => {
    try {
      const v = version ?? (await resolveLatest(opts.proxy, pkg));
      // Stage B: preflight the named package. (Full dependency-tree resolution
      // via `npm install --package-lock-only` is the documented extension; this
      // command preflights the requested package and is structured to accept a
      // resolved set.)
      const manifests = [await fetchManifest(opts.proxy, pkg, v)];
      for (const m of manifests) console.log(formatManifest(m));
      const plan = planApprovals(manifests);
      if (plan.length === 0) {
        console.log("Nothing to approve — all capabilities are inherited or already approved.");
        return;
      }
      if (opts.approve) {
        await postApproval(opts.proxy, plan, true);
        console.log(`approved ${plan.length} package version(s).`);
      } else {
        console.log(`\n${plan.length} package version(s) need approval. Re-run with --approve, or use \`sentinel approve\`.`);
      }
    } catch (err) {
      fail(err, opts.proxy);
    }
  });
```

Note: `program.parseAsync()` runs on import. The test imports `planApprovals` from this module, which triggers `parseAsync` with the test-runner's argv. This is already how the module behaves; commander treats unknown argv as a no-op command and does not throw. If the test run prints commander noise, guard the parse: wrap the final line as `if (process.argv[1]?.endsWith("index.ts") || process.argv[1]?.endsWith("index.js")) program.parseAsync();`. Apply that guard.

- [ ] **Step 5: Run to verify it passes**

Run: `node --import tsx --test packages/cli/test/cli.test.ts`
Expected: PASS for both describes.

- [ ] **Step 6: Build and commit**

```bash
npx tsc --build --force packages/cli
git add packages/cli/src/format.ts packages/cli/src/index.ts packages/cli/test/cli.test.ts
git commit -m "feat(cli): add manifest, approve, and preflight commands"
```

---

## Task 10: Dashboard approvals panel

**Files:**
- Modify: `packages/proxy/public/index.html`

**Interfaces:**
- Consumes: `GET /-/approvals` and `POST /-/approvals` (Task 8). No automated test (no DOM harness in the repo); verified manually.

- [ ] **Step 1: Add the approvals table markup**

In `packages/proxy/public/index.html`, after the closing `</table>` of the audits table (line ~78) and before `</div>` (the `.wrap` close, line ~79), insert:

```html
    <h2 style="font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:28px 0 8px">Approvals</h2>
    <table>
      <thead><tr><th>Package</th><th>Decision</th><th>Actor</th><th>Capabilities</th><th></th></tr></thead>
      <tbody id="approval-rows"><tr><td colspan="5" class="empty">No approvals recorded.</td></tr></tbody>
    </table>
```

- [ ] **Step 2: Add the render + revoke logic**

In the `<script>` block, after the `load()` function (line ~114), add:

```js
function approvalRow(a) {
  const caps = (a.approvedCapabilities || []).map((c) => `${c.kind}:${c.target}`).join(", ") || "none";
  return `<tr>
    <td><div class="pkg">${esc(a.name)}</div><div class="meta">v${esc(a.version)}</div></td>
    <td><span class="badge ${a.decision === "approved" ? "allow" : "block"}">${esc(a.decision)}</span></td>
    <td class="meta">${esc(a.actor ? a.actor.type + ":" + a.actor.id : "—")}</td>
    <td class="meta">${esc(caps)}</td>
    <td><button class="ghost" data-revoke="${esc(a.integrity)}">Revoke</button></td>
  </tr>`;
}

async function loadApprovals() {
  const data = await (await fetch("/-/approvals")).json();
  const rows = data.approvals || [];
  $("approval-rows").innerHTML = rows.length ? rows.map(approvalRow).join("")
    : '<tr><td colspan="5" class="empty">No approvals recorded.</td></tr>';
  for (const btn of document.querySelectorAll("[data-revoke]")) {
    btn.addEventListener("click", async () => {
      await fetch(`/-/approvals/${encodeURIComponent(btn.getAttribute("data-revoke"))}`, { method: "DELETE" });
      await loadApprovals();
    });
  }
}
```

Change the bottom calls (lines ~140-142) from:

```js
health();
load();
setInterval(load, 5000);
```

to:

```js
health();
load();
loadApprovals();
setInterval(() => { load(); loadApprovals(); }, 5000);
```

- [ ] **Step 3: Manually verify**

Run (in one shell, since background processes don't persist here):

```bash
SENTINEL_UPSTREAM=fixtures SENTINEL_POLICY=block npm run proxy &
sleep 1
curl -s localhost:4873/-/manifest/net-fetch-lite/1.0.0 >/dev/null
curl -s -XPOST localhost:4873/-/approvals -H 'content-type: application/json' \
  -d "$(curl -s localhost:4873/-/manifest/net-fetch-lite/1.0.0 | node -e 'process.stdin.on("data",d=>{const m=JSON.parse(d);console.log(JSON.stringify({name:m.meta.name,version:m.meta.version,integrity:m.meta.integrity,decision:"approved",actor:{type:"human",id:"me"}}))})')"
curl -s localhost:4873/-/approvals
kill %1
```

Expected: the final `curl` shows the recorded approval JSON. Open `http://localhost:4873/` in a browser to see the Approvals panel with a Revoke button.

- [ ] **Step 4: Commit**

```bash
git add packages/proxy/public/index.html
git commit -m "feat(dashboard): add approvals panel with revoke"
```

---

## Task 11: Documentation — ADRs, ARCHITECTURE, CLAUDE

**Files:**
- Create: `docs/adr/0013-approval-gate-via-block-and-capability-delta-trigger.md`
- Modify: `docs/adr/0011-install-time-permission-manifest.md`, `ARCHITECTURE.md`, `CLAUDE.md`

**Interfaces:** none (docs only). Verified by a clean build + full test pass.

- [ ] **Step 1: Mark ADR-0011 Accepted**

In `docs/adr/0011-install-time-permission-manifest.md`, change `**Status:** Proposed` to:

```md
**Status:** Accepted (stage B) — superseded options A/C deferred
```

- [ ] **Step 2: Write ADR-0013**

Create `docs/adr/0013-approval-gate-via-block-and-capability-delta-trigger.md`:

```md
# ADR-0013: Approval gate via the block path; capability-delta-vs-prior-approved trigger

**Status:** Accepted
**Date:** 2026-06-24
**Phase:** 2 (refines ADR-0011 stage B)

## Context

ADR-0011 stage B adds an install-time approval flow without a sandbox. Two
concrete mechanics were left open: how an approval gates an install, and what
re-triggers approval across versions.

## Decision

1. **Gate via the existing `block` policy**, not a new policy mode. Under `block`
   the proxy `403`s on `verdict==='block'` OR an unapproved capability delta
   (`approval required` / `approval denied`). Under `observe` the manifest is
   advisory (headers only). This reuses the Phase 1 `403` path and keeps the
   policy surface a single knob.
2. **Re-approval triggers on a capability delta vs the prior _approved_ version.**
   First sight of any capability requires approving the full set; later versions
   only re-prompt when a NEW (kind, target) atom appears. Capabilities are a
   complete, deterministic inventory in `@sentinel/core` (schema 2); approval is
   mutable proxy state keyed by integrity.

## Consequences

- Because gating folds into `block`, *every* first-sight capable package `403`s
  under enforcement. npm aborts on the first `403`, so a dependency tree must be
  cleared via a **preflight → batch-approve → install** workflow (documented in
  the design + `sentinel preflight`), not per-package retry.
- Two diffs coexist: `capabilityDelta` (vs prior published version, in the report)
  is informational; `approvalRequired` (vs prior approved version, at the gate) is
  the set a user/agent acts on.
- **Approval API authentication is out of scope** for stage B (trusted
  single-tenant context); it is a prerequisite for multi-tenant/untrusted
  deployment and is deferred to the ADR-0012 era.
- Determinism invariant holds for capabilities (pure function of files); approval
  state is deliberately excluded from the deterministic report.
```

- [ ] **Step 3: Update ARCHITECTURE.md**

In `ARCHITECTURE.md`, in §4.1 (Rules) add a sentence after the rule list noting the parallel capability pass; in §5 (Data model) add the `Capability`/`CapabilityDelta` types and the schema bump to 2; in §3 (Proxy design) add the approval gate + manifest/approval endpoints. Concretely, append to the §5 data-model code block:

```ts
type CapabilityKind = 'network' | 'filesystem' | 'process' | 'native';
interface Capability { kind: CapabilityKind; target: string; evidence: Evidence[]; }
interface CapabilityDelta { added: Capability[]; removed: Capability[]; }
// AuditReport is schema 2: adds `capabilities: Capability[]` and
// `capabilityDelta: CapabilityDelta | null`. Approval state is NOT in the report —
// it is mutable proxy state in ApprovalStore, keyed by integrity (see ADR-0011/0013).
```

And add a short subsection after §3.2:

```md
### 3.3 Approval gate (Phase 2.1, ADR-0011/0013)

Under the `block` policy the proxy also gates on capability approval: a tarball
with unapproved new capability atoms returns `403 approval required`. Approval is
recorded per `(name, version, integrity)` in `ApprovalStore` and inherited across
versions whose capability set is unchanged. Endpoints: `GET /-/manifest/:pkg/:ver`,
`POST /-/approvals` (single or batch), `GET /-/approvals`, `DELETE /-/approvals/:integrity`.
A dependency tree is cleared via `sentinel preflight` (resolve → preflight → batch
approve → install), because npm aborts on the first `403`.
```

- [ ] **Step 4: Update CLAUDE.md test count**

Run the full suite first to get the count:

Run: `npm test 2>&1 | tail -5`
Expected: a `# pass <N>` / `# tests <N>` summary. Note the passing count `N`.

In `CLAUDE.md`, update the build/test block comment and the definition-of-done line: change both `must be 15/15` references to `must be N/N` using the observed `N`.

- [ ] **Step 5: Commit**

```bash
git add docs/adr/0011-install-time-permission-manifest.md docs/adr/0013-approval-gate-via-block-and-capability-delta-trigger.md ARCHITECTURE.md CLAUDE.md
git commit -m "docs: accept ADR-0011, add ADR-0013, document capability/approval in ARCHITECTURE + CLAUDE"
```

---

## Task 12: Full-suite verification

**Files:** none (verification only).

- [ ] **Step 1: Clean build**

Run: `npm run build`
Expected: no TypeScript errors. (If `rm` of `dist/` fails with EPERM, use `npx tsc --build --force`.)

- [ ] **Step 2: Full test suite**

Run: `npm test`
Expected: all tests pass — core (`audit.test.ts`, `capabilities.test.ts`), proxy (`proxy.test.ts`, `store.test.ts`, `approvals.test.ts`, `reconcile.test.ts`), cli (`cli.test.ts`). The count matches the `N/N` written into CLAUDE.md.

- [ ] **Step 3: Confirm the malware invariant explicitly**

Run: `node --import tsx --test --test-name-pattern "blocked for the VERDICT reason" packages/proxy/test/proxy.test.ts`
Expected: PASS — color-stream@1.4.1 is `403` with `x-sentinel-verdict: block` even after its capabilities are pre-approved.

- [ ] **Step 4: Offline demo still runs**

Run: `npm run demo`
Expected: completes without error (the demo walkthrough is unaffected by the additive changes).

- [ ] **Step 5: Final commit if anything was adjusted**

```bash
git status --short
# commit any stragglers with an appropriate message; otherwise the branch is ready
```

---

## Self-review notes

- **Spec coverage:** capability inventory (Tasks 1-3), gate via block (Task 8), capability-delta-vs-prior-approved trigger (Tasks 6/8), specific targets (Task 2), ApprovalStore + revoke (Task 5), manifest + approval API (Task 8), tree preflight (Task 9), two baselines stated (`capabilityDelta` in report vs `approvalRequired` at gate, Tasks 3/6/8), no-write-on-serve inheritance (reconcile is read-only — Task 6), teeth-preserving regression test (Task 8 Step 1 last test), schema-2 migration (Task 4), auth deferred (ADR-0013, Task 11), dashboard (Task 10), docs (Task 11). All covered.
- **Determinism:** capabilities are pure; the determinism test is in Task 3 Step 7. Findings/scoring code is never modified.
- **Type consistency:** `Capability { kind, target, evidence }`, `capabilityAtom`, `ApprovalState`, `reconcileApproval` signatures match across core → proxy → cli tasks.
