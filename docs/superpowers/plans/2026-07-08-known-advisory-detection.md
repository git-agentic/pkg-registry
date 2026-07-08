# Phase 21 — Known-Malicious Advisory Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the known-bad detection dimension: a bundled static corpus of known-malicious npm package versions plus a pure `known-advisory` rule that hard-blocks an exact `(name, version)` match, operator-overridable via `SENTINEL_ADVISORIES`.

**Architecture:** A bundled `advisory-corpus.ts` (like `typosquat-corpus.ts`) + a pure `known-advisory` rule that checks `(meta.name, meta.version)` against the bundled corpus ∪ an optional operator-supplied `AuditInput.advisories`; the proxy loads `SENTINEL_ADVISORIES` once at startup and threads it in. Deterministic, offline, critical hard-block. The scoring path is untouched — this is a new rule.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; reuses the pure-`Rule` + `mkFinding` + bundled-corpus patterns; `node:test` via `tsx`. No new dependencies.

## Global Constraints

- **The corpus is a STATIC bundled input, offline (invariant #3)** — `KNOWN_ADVISORIES` is compiled into core, never fetched at audit time (exactly like `NPM_SIGNING_KEYS` / `POPULAR_NPM_NAMES`). The rule is pure and deterministic: same `(name, version)` + same corpus ⇒ same finding.
- **The corpus is METADATA, never malware code** — each entry is `{ name, version, id, severity?, reference? }` (identifiers + an advisory id/URL). No package payloads. This is not a code fixture; the "no live malware" fixture rule does not apply, but the entries must be REAL, publicly-documented advisories with VERIFIABLE ids (osv.dev / GitHub advisories).
- **Exact `(name, version)` match** — version-range matching is deferred. A match ⇒ a `critical` (default) `metadata` finding via `mkFinding`, which hard-blocks under the default policy (`hardBlockSeverity: "critical"`). A per-advisory `severity` is honored.
- **Operator override, fail-closed** — bundled ∪ `AuditInput.advisories`; the proxy loads `SENTINEL_ADVISORIES` (JSON `Advisory[]`) ONCE at startup, FATAL-exits on an unreadable/non-JSON file (like the `SENTINEL_AUTH_PUBKEY` validation), drops a malformed *entry* with a warning. Unset ⇒ bundled-only (unchanged behavior). Read once at startup, never per-audit (invariant #3).
- **`Advisory` (verbatim):** `interface Advisory { name: string; version: string; id: string; severity?: "critical" | "high"; reference?: string }`.
- **Rule id `"known-advisory"`, category `"metadata"`.** Registered in `rules/index.ts` (rule count → 8). Wrapped by `runRules` (fails open). `AuditInput.advisories?: Advisory[]` is optional everywhere (absent ⇒ existing tests unaffected).
- **Invariant #1 untouched** — a new pure rule; scoring math unchanged; the determinism test stays green.
- ESM only, NodeNext: internal imports use `.js` specifiers; cross-package imports use the package name.
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/<pkg>`.
- Run all commands from repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.

---

### Task 1: Core — advisory corpus + `known-advisory` rule + `AuditInput.advisories` threading

**Files:**
- Create: `packages/core/src/advisory-corpus.ts`
- Create: `packages/core/src/rules/known-advisory.ts`
- Modify: `packages/core/src/types.ts` (`AuditInput.advisories?`), `packages/core/src/audit.ts` (thread `advisories`), `packages/core/src/rules/index.ts` (register), `packages/core/src/remediation.ts` (REMEDIATIONS entry), `packages/core/src/index.ts` (exports)
- Test: `packages/core/test/known-advisory.test.ts`

**Interfaces:**
- Consumes: `AuditInput`, `Finding`, `Rule`, `Category` (types), `mkFinding` (rules/util).
- Produces (used by Task 2): `interface Advisory { name, version, id, severity?, reference? }`; `KNOWN_ADVISORIES: readonly Advisory[]`; `parseAdvisories(raw: string): Advisory[]`; `knownAdvisoryRule: Rule`; `AuditInput.advisories?: Advisory[]`; `buildAudit`/`runAudit` accept `advisories?`.

- [ ] **Step 1: Write the failing test** (`packages/core/test/known-advisory.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { knownAdvisoryRule } from "../src/rules/known-advisory.js";
import { KNOWN_ADVISORIES, parseAdvisories, type Advisory } from "../src/advisory-corpus.js";
import type { AuditInput, PackageMeta } from "../src/types.js";

function input(name: string, version: string, advisories?: Advisory[]): AuditInput {
  return { meta: { name, version } as PackageMeta, files: [], mode: "full", advisories };
}
const A = (over: Partial<Advisory> = {}): Advisory => ({ name: "evil-pkg", version: "1.0.0", id: "MAL-TEST-0001", ...over });

describe("known-advisory rule", () => {
  test("an operator-supplied advisory match → a critical metadata finding naming the id", () => {
    const fs = knownAdvisoryRule.run(input("evil-pkg", "1.0.0", [A()]));
    assert.equal(fs.length, 1);
    assert.equal(fs[0]!.severity, "critical");
    assert.equal(fs[0]!.category, "metadata");
    assert.match(fs[0]!.message, /MAL-TEST-0001/);
  });

  test("a non-matching version → no finding", () => {
    assert.deepEqual(knownAdvisoryRule.run(input("evil-pkg", "2.0.0", [A()])), []);
  });

  test("a per-advisory severity is honored", () => {
    assert.equal(knownAdvisoryRule.run(input("evil-pkg", "1.0.0", [A({ severity: "high" })]))[0]!.severity, "high");
  });

  test("operator advisories MERGE with the bundled corpus (both fire)", () => {
    const bundled = KNOWN_ADVISORIES[0]!;
    assert.equal(knownAdvisoryRule.run(input(bundled.name, bundled.version)).length, 1); // bundled alone
    assert.equal(knownAdvisoryRule.run(input("evil-pkg", "1.0.0", [A()])).length, 1);    // operator alone
  });

  test("no advisories + clean package → inert", () => {
    assert.deepEqual(knownAdvisoryRule.run(input("totally-fine", "9.9.9")), []);
  });
});

describe("KNOWN_ADVISORIES corpus hygiene", () => {
  test("non-empty; every entry has name+version+id; no duplicate (name,version)", () => {
    assert.ok(KNOWN_ADVISORIES.length > 0);
    const seen = new Set<string>();
    for (const a of KNOWN_ADVISORIES) {
      assert.ok(a.name && a.version && a.id, `malformed entry: ${JSON.stringify(a)}`);
      const key = `${a.name}@${a.version}`;
      assert.equal(seen.has(key), false, `duplicate ${key}`);
      seen.add(key);
    }
  });
});

describe("parseAdvisories", () => {
  test("well-formed → parsed; malformed entry dropped; garbage → []", () => {
    const raw = JSON.stringify([{ name: "a", version: "1", id: "X" }, { name: "b" }, { version: "2", id: "Y" }]);
    assert.deepEqual(parseAdvisories(raw), [{ name: "a", version: "1", id: "X" }]);
    assert.deepEqual(parseAdvisories("not json"), []);
    assert.deepEqual(parseAdvisories(JSON.stringify({ not: "an array" })), []);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/core/test/known-advisory.test.ts
```

Expected: FAIL — modules not found.

- [ ] **Step 3a: Implement `packages/core/src/advisory-corpus.ts`**

```ts
/**
 * Bundled corpus of KNOWN-MALICIOUS npm package versions. Curated snapshot (2026-07);
 * a STATIC input — never fetched at audit time (invariant #3). Metadata only (advisory
 * identifiers), never malware code. Entries are publicly-documented incidents with real
 * osv.dev / GitHub advisory ids. Regenerate via `scripts/make-advisories.ts`.
 */
export interface Advisory {
  name: string;
  version: string;
  id: string;                       // advisory id, e.g. "GHSA-…" / "MAL-…"
  severity?: "critical" | "high";   // default critical
  reference?: string;               // advisory URL
}

// NOTE for the implementer: populate with ~6-10 well-documented, VERIFIABLE incidents.
// The (name, version) pairs below are historically-confirmed compromised releases; VERIFY each
// `id` against osv.dev (use the OSV `MAL-…` id or the GHSA id) and set `reference` to the advisory
// URL before committing. Keep it small, accurate, and de-duplicated. Do NOT invent ids.
export const KNOWN_ADVISORIES: readonly Advisory[] = [
  { name: "event-stream", version: "3.3.6", id: "GHSA-mh6f-8j2x-4483", reference: "https://github.com/advisories/GHSA-mh6f-8j2x-4483" },
  { name: "flatmap-stream", version: "0.1.1", id: "GHSA-2xhc-4x4f-8vfj", reference: "https://osv.dev/vulnerability/GHSA-2xhc-4x4f-8vfj" },
  { name: "ua-parser-js", version: "0.7.29", id: "GHSA-pjwm-rvh2-c87w", reference: "https://github.com/advisories/GHSA-pjwm-rvh2-c87w" },
  { name: "ua-parser-js", version: "0.8.0", id: "GHSA-pjwm-rvh2-c87w", reference: "https://github.com/advisories/GHSA-pjwm-rvh2-c87w" },
  { name: "ua-parser-js", version: "1.0.0", id: "GHSA-pjwm-rvh2-c87w", reference: "https://github.com/advisories/GHSA-pjwm-rvh2-c87w" },
  { name: "node-ipc", version: "10.1.1", id: "GHSA-97m3-w2cp-4xx6", reference: "https://github.com/advisories/GHSA-97m3-w2cp-4xx6" },
  { name: "coa", version: "2.0.3", id: "GHSA-73qr-pfmq-6rp8", reference: "https://github.com/advisories/GHSA-73qr-pfmq-6rp8" },
  { name: "rc", version: "1.2.9", id: "GHSA-g2q5-5433-rhrf", reference: "https://github.com/advisories/GHSA-g2q5-5433-rhrf" },
];
// The implementer MUST verify each id/version against osv.dev and correct any that don't resolve,
// rather than shipping a wrong id. Tests do not assert specific ids (they use synthetic advisories),
// so correcting the bundled list here won't break the suite.

/** name → its known-bad advisories. Built once over the bundled corpus. */
export function buildAdvisoryIndex(advisories: readonly Advisory[]): Map<string, Advisory[]> {
  const m = new Map<string, Advisory[]>();
  for (const a of advisories) {
    const list = m.get(a.name) ?? [];
    list.push(a);
    m.set(a.name, list);
  }
  return m;
}

/** Parse an operator-supplied advisory JSON array. Pure, total: drops malformed entries; [] on garbage. */
export function parseAdvisories(raw: string): Advisory[] {
  let doc: unknown;
  try { doc = JSON.parse(raw); } catch { return []; }
  if (!Array.isArray(doc)) return [];
  const out: Advisory[] = [];
  for (const e of doc) {
    if (e && typeof e === "object" && typeof (e as Advisory).name === "string" && typeof (e as Advisory).version === "string" && typeof (e as Advisory).id === "string") {
      const a = e as Advisory;
      const adv: Advisory = { name: a.name, version: a.version, id: a.id };
      if (a.severity === "critical" || a.severity === "high") adv.severity = a.severity;
      if (typeof a.reference === "string") adv.reference = a.reference;
      out.push(adv);
    }
  }
  return out;
}
```

- [ ] **Step 3b: Implement `packages/core/src/rules/known-advisory.ts`**

```ts
import type { AuditInput, Finding, Rule } from "../types.js";
import { mkFinding } from "./util.js";
import { KNOWN_ADVISORIES, buildAdvisoryIndex, type Advisory } from "../advisory-corpus.js";

// Prebuilt index over the bundled corpus (built once). Operator advisories are merged per-call.
const BUNDLED_INDEX = buildAdvisoryIndex(KNOWN_ADVISORIES);

/**
 * Flags a package version listed as KNOWN-MALICIOUS in a bundled advisory corpus (∪ operator-supplied
 * `input.advisories`). Pure, deterministic, offline (static corpus, never fetched). An exact
 * (name, version) match ⇒ a critical `metadata` finding (hard-blocks under the default policy).
 */
export const knownAdvisoryRule: Rule = {
  id: "known-advisory",
  category: "metadata",
  run(input: AuditInput): Finding[] {
    const { name, version } = input.meta;
    const candidates: Advisory[] = [
      ...(BUNDLED_INDEX.get(name) ?? []),
      ...((input.advisories ?? []).filter((a) => a.name === name)),
    ];
    const hit = candidates.find((a) => a.version === version);
    if (!hit) return [];
    return [mkFinding({
      ruleId: this.id, category: this.category, severity: hit.severity ?? "critical",
      message: `\`${hit.name}@${hit.version}\` is listed as known-malicious in advisory ${hit.id}${hit.reference ? ` (${hit.reference})` : ""} — do not install this version.`,
      evidence: [], files: input.files,
    })];
  },
};
```

- [ ] **Step 3c: Add `AuditInput.advisories?` in `types.ts` + thread through `audit.ts`**

In `types.ts` `AuditInput`:
```ts
  /** Operator-supplied known-malicious advisories, merged with the bundled corpus (Phase 21). */
  advisories?: Advisory[];
```
(import `Advisory` type — `import type { Advisory } from "./advisory-corpus.js";`).

In `audit.ts` `buildAudit` opts + the `input` construction + `runAudit`/`AuditTarballInput` (mirror `releaseContext`):
```ts
// buildAudit opts: add `advisories?: Advisory[];`
// input construction: { meta, files, mode: opts.mode, releaseContext: opts.releaseContext, advisories: opts.advisories }
// AuditTarballInput: add `advisories?: Advisory[];`
// runAudit's buildAudit call: pass `advisories: input.advisories`
```

- [ ] **Step 3d: Register + REMEDIATIONS + exports**

`rules/index.ts`: import `knownAdvisoryRule`, add to `RULES` + the re-export.
`remediation.ts` REMEDIATIONS map: add
```ts
  "known-advisory": { summary: "Listed as known-malicious in a security advisory.", action: "This exact version is publicly documented as malicious — remove it and pin to a version published BEFORE the compromise (or a patched later release); do not waive." },
```
`index.ts`: `export { KNOWN_ADVISORIES, parseAdvisories, buildAdvisoryIndex, type Advisory } from "./advisory-corpus.js";` and `export { knownAdvisoryRule } from "./rules/known-advisory.js";`.

- [ ] **Step 4: Run the test + build**

```bash
npm run build
npx tsx --test packages/core/test/known-advisory.test.ts
```

Expected: PASS. Then a quick full `npm test` (the new rule is inert without a corpus match, so existing fixtures/tests should be unaffected — BUT verify no existing fixture's (name,version) collides with a bundled advisory entry; if one does, that fixture's verdict changes — pick corpus entries that don't collide with fixtures, or adjust).

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/advisory-corpus.ts packages/core/src/rules/known-advisory.ts packages/core/src/types.ts packages/core/src/audit.ts packages/core/src/rules/index.ts packages/core/src/remediation.ts packages/core/src/index.ts packages/core/test/known-advisory.test.ts
git commit -m "feat(phase21): known-advisory rule + bundled advisory corpus + AuditInput.advisories threading"
```

---

### Task 2: Proxy — `SENTINEL_ADVISORIES` startup load + thread into the audit

**Files:**
- Modify: `packages/proxy/src/index.ts` (`resolveAdvisories`, wire into `createServer`)
- Modify: `packages/proxy/src/server.ts` (`ServerOptions.advisories`; pass into `auditVersion`'s `runAudit`)
- Test: `packages/proxy/test/known-advisory-e2e.test.ts`

**Interfaces:**
- Consumes: `parseAdvisories` + `type Advisory` (`@sentinel/core`), the audit path.
- Produces: `ServerOptions.advisories?: Advisory[]`; a fatal-on-unreadable startup loader; the rule receives operator advisories on the audit path.

- [ ] **Step 1: Write the failing e2e** (`packages/proxy/test/known-advisory-e2e.test.ts`) — boot the in-process proxy with `LocalFixtureUpstream` and an `advisories` option listing a BENIGN fixture's `(name, version)`:

```ts
// Model boot on packages/proxy/test/audit-tree-integrity-e2e.test.ts.
// boot(advisories?: Advisory[]) → createServer({ ..., advisories })
// test 1: boot with advisories=[{name:"leftpad-lite",version:"1.0.0",id:"MAL-TEST-9",reference:"http://example.test"}];
//   GET /-/audit/leftpad-lite/1.0.0 → report.verdict === "block", a finding with ruleId "known-advisory" naming MAL-TEST-9.
//   (leftpad-lite is benign — proves the known-bad list blocks by IDENTITY, not code.)
// test 2: boot WITHOUT advisories → GET /-/audit/leftpad-lite/1.0.0 → verdict "allow" (inert by default).
// test 3: the pre-existing malicious fixture still blocks (unchanged).
```

(Use the `GET /-/audit/:pkg/:version` route; it returns the full report. Assert `report.verdict` + `report.findings.some(f => f.ruleId === "known-advisory")`.)

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/known-advisory-e2e.test.ts
```

Expected: FAIL — `advisories` not accepted / not threaded.

- [ ] **Step 3a: `ServerOptions.advisories` + thread into `auditVersion`** (`packages/proxy/src/server.ts`)

Add `advisories?: Advisory[];` to `ServerOptions` (import `type Advisory` from `@sentinel/core`). Expose `const advisories = opts.advisories;` where the other opts are read. In `auditVersion`'s `runAudit({...})` call, add `advisories,`.

- [ ] **Step 3b: `resolveAdvisories` + wire in `main()`** (`packages/proxy/src/index.ts`, mirror `resolveAuthPublicKey`)

```ts
function resolveAdvisories(): Advisory[] | undefined {
  const path = process.env.SENTINEL_ADVISORIES;
  if (!path) return undefined;
  let raw: string;
  try { raw = readFileSync(path, "utf8"); }
  catch (err) { console.error(`FATAL: cannot read SENTINEL_ADVISORIES: ${(err as Error).message}`); process.exit(1); }
  const advisories = parseAdvisories(raw);
  console.log(`  advisories: ${advisories.length} operator-supplied (+ bundled)`);
  return advisories;
}
```
(import `parseAdvisories`, `type Advisory` from `@sentinel/core`; `readFileSync` already imported.) In `main()`, `const advisories = resolveAdvisories();` and add `advisories` to the `createServer({...})` call. A non-JSON/unreadable file FATAL-exits; a valid-but-empty/all-malformed file yields `[]` (bundled-only) — that's acceptable (the operator gets a clear count log).

- [ ] **Step 4: Build + run the e2e + full suite**

```bash
npm run build
npx tsx --test packages/proxy/test/known-advisory-e2e.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS; record counts.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/index.ts packages/proxy/src/server.ts packages/proxy/test/known-advisory-e2e.test.ts
git commit -m "feat(phase21): SENTINEL_ADVISORIES startup load (fatal-on-unreadable) + thread operator advisories into the audit"
```

---

### Task 3: Refresh script, docs, ADR-0034, final verification

**Files:**
- Create: `scripts/make-advisories.ts` (documented regenerator)
- Modify: `package.json` (an `npm run advisories` script — optional; the file documents the process)
- Create: `docs/adr/0034-known-advisory-detection.md`
- Modify: `ARCHITECTURE.md`, `CLAUDE.md`, `README.md`

- [ ] **Step 1: `scripts/make-advisories.ts`** — a documented, runnable regenerator: it reads an OSV/GHSA "malicious-packages" export (a local JSON path via an arg/env, NOT a live fetch in the script's default path — keep it offline-friendly), filters to npm ecosystem + specific-version advisories, dedupes by `(name, version)`, and prints a ready-to-paste `KNOWN_ADVISORIES` array (or writes `advisory-corpus.ts`). A header comment documents the source (osv.dev malicious-packages / GitHub advisory database, `type: malware`) and how to run it. Keep it simple + honest — it does NOT need to auto-fetch; it documents the reproducible process and transforms a provided export.

- [ ] **Step 2: Write ADR-0034** — follow the style of `docs/adr/0026-supply-chain-identity-heuristics.md`. **Context** (all 7 rules are heuristic/behavioral; Sentinel had NO known-bad signal — no advisory/OSV/known-malicious database check). **Decision** (a bundled static `advisory-corpus.ts` of known-malicious npm `(name, version)` + a pure `known-advisory` rule that critical-hard-blocks an exact match; metadata-only corpus, offline (invariant #3), operator-overridable via `SENTINEL_ADVISORIES` merged into the bundled set; a `known-advisory` remediation entry). **Determinism** (static corpus + pure rule ⇒ deterministic; invariant #1 untouched; offline — never fetched at audit time). **Consequences** (adds the industry-standard known-bad dimension; the bundled snapshot goes stale — hence operator override + a refresh script; exact-match only (ranges deferred); the corpus is metadata not code). **Deferred** (semver-range advisory matching; live OSV fetch/sync; a full CVE/vuln (non-malware) feed; auto-refresh). **Rejected** (fetching OSV at audit time — breaks invariant #3; a `severity`-below-critical default — a known-malicious version should hard-block). **VERIFY** any rule/corpus ADR number cited with `head -1 docs/adr/00*.md | grep -iE "identity|typosquat|signature|corpus"` before citing; extends ADR-0002.

- [ ] **Step 3: ARCHITECTURE.md** — document the `known-advisory` rule (8th rule), the bundled `advisory-corpus.ts` (static, offline, metadata-only), the exact-match critical hard-block, and the `SENTINEL_ADVISORIES` operator override (loaded once at startup, merged). READ the rules/detection section + numbering first.

- [ ] **Step 4: CLAUDE.md + README.md** — CLAUDE.md: Phase 21 sentence in "What this is" (mirror recent-phase density); update the registered-rule count to **8** (install-scripts, secret-exfil, network-egress, obfuscation, provenance, typosquat, release-anomaly, known-advisory); note `SENTINEL_ADVISORIES` in the env list; update the `npm test` count to the ACTUAL number from Step 5. README.md: document known-advisory detection + supplying a fresher advisory file via `SENTINEL_ADVISORIES` (+ the `make-advisories` regen note).

- [ ] **Step 5: Full Definition-of-Done run**

```bash
npm run build
npm run fixtures
npm test 2>&1 | tail -8
npm run demo 2>&1 | tail -3
```

Expected: build clean; ALL tests pass (record exact count for CLAUDE.md); the malicious fixture still blocks. If the count differs from CLAUDE.md, update the doc to reality.

- [ ] **Step 6: Commit**

```bash
git add scripts/make-advisories.ts package.json docs ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs(phase21): ADR-0034 known-advisory detection; make-advisories regen; ARCHITECTURE/CLAUDE/README"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 architecture → Task 1 (corpus + rule + threading); §2 corpus/rule/finding/remediation → Task 1 (rule, corpus, REMEDIATIONS) + Task 3 (make-advisories); §3 operator override → Task 1 (`AuditInput.advisories` + thread) + Task 2 (`SENTINEL_ADVISORIES` load + server thread); §4 testing/DoD → each task's tests + Task 3. The critical-hard-block + inert-by-default is Task 1's unit tests + Task 2's e2e (block with advisory / allow without).
- **Type consistency:** `Advisory`/`KNOWN_ADVISORIES`/`parseAdvisories`/`buildAdvisoryIndex` + `knownAdvisoryRule` (Task 1) consumed by the proxy loader (Task 2); `AuditInput.advisories?` (Task 1) threaded via `buildAudit`/`runAudit`/`AuditTarballInput` (Task 1) and set by the server from `ServerOptions.advisories` (Task 2). Rule id `"known-advisory"` + category `"metadata"` consistent between the rule (Task 1), the REMEDIATIONS entry (Task 1), and the e2e assertion (Task 2).
- **Known judgment calls:** the corpus is metadata-only (real advisory ids the implementer VERIFIES against osv.dev — tests use synthetic advisories so they don't depend on the exact list); exact `(name, version)` match only (ranges deferred); `critical` default severity so a known-malicious version hard-blocks; operator override threaded via `AuditInput.advisories` (mirrors `releaseContext`/`signingKeys`), loaded once at startup fail-closed (FATAL on an unreadable file, like `SENTINEL_AUTH_PUBKEY`); the e2e proves block-by-identity using a BENIGN fixture on a synthetic advisory list (no new malware code); Task 1 must confirm no existing fixture `(name,version)` collides with a bundled advisory entry (which would change that fixture's verdict).
