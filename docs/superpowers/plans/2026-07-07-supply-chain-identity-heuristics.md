# Phase 13 — Supply-Chain Identity Heuristics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect the social-engineering supply-chain attack class Sentinel is currently blind to — typosquatting (a pure rule vs a bundled popular-name corpus) and dependency confusion (a score-time gate vs the policy's claimed private namespaces).

**Architecture:** Shared `name-distance.ts` helpers (normalize + Damerau-Levenshtein + a `typosquatMatch` predicate) feed two consumers: a pure `typosquat` Rule (policy-blind, name vs a bundled static corpus) and a score-time `dependency-confusion` check in `score.ts` (needs the policy's namespaces, which rules can't see). Both emit `metadata`-category weighted findings — deterministic, no new gate mechanism, no hard-block.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; NO new dependencies.

## Global Constraints

- **Deterministic (invariant #1):** both signals are pure functions of (name, corpus, policy). The `scoring is deterministic across runs` test must stay green. The default policy has no `privateNamespaces`, so the dependency-confusion check is inert by default — the pinned default-policy score is unchanged.
- **Weighted findings, not hard-blocks:** typosquat = `medium`; dependency-confusion = `high`. Neither forces a block; both are normally-weighted findings (via `mkFinding` / the score.ts weight path). Under the default policy: medium −12 → 88 (allow), high −25 → 75 (warn). They compound with code findings; operators escalate via policy weights or waive per-package.
- **Category:** both findings use the EXISTING `metadata` `Category` (already in `types.ts`) — no new category.
- **Corpus is a static input (invariant #3):** a bundled, committed asset in `packages/core`, never fetched at audit time. Ships with a source + snapshot-date header comment.
- **False-positive controls (typosquat rule):** never flag a name that IS in the corpus; the matched target must be distinct; skip names < 4 chars.
- **Dependency-confusion must NOT flag the legitimate private package:** a name that legitimately matches a claim via `matchPackage` (i.e. it IS the claimed private package) is never flagged.
- **Rules fail open (invariant #6):** the typosquat rule is wrapped by `runRules`'s per-rule try/catch; the score.ts check is guarded against a malformed name.
- ESM only, NodeNext: internal imports use `.js` specifiers even from `.ts`.
- Tests hermetic: unit tests + `LocalFixtureUpstream`; never hit live npm.
- After editing anything under `fixtures/`, re-run `npm run fixtures`.
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/<pkg>`.
- Run all commands from repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.

---

### Task 1: `name-distance.ts` — shared normalization + distance + match helpers

**Files:**
- Create: `packages/core/src/name-distance.ts`
- Test: `packages/core/test/name-distance.test.ts`

**Interfaces:**
- Produces (used by Tasks 2–3):
  - `normalizeName(s: string): string` — strip a leading `@`, take the part before the first `/`, drop `*`, remove `-`/`_`, lowercase. (For a full package name like `@types/node` this yields `types`; used only where scope-flattening is intended — the rule/gate call it deliberately, see below.)
  - `canonical(s: string): string` — `deHomoglyph(normalizeSeparators(s))`: lowercase, strip `@`, collapse `/`,`-`,`_` to empty, then map confusables (`1→l`, `0→o`, `5→s`, `|→l`, and the digraph `rn→m`).
  - `damerauLevenshtein(a: string, b: string): number` — optimal-string-alignment distance (adjacent transposition counts as 1).
  - `typosquatMatch(name: string, target: string): boolean` — true iff `name` is a likely squat of `target` (canonical equality after separator/homoglyph folding, or Damerau distance within a length-scaled threshold), and `name !== target`.

- [ ] **Step 1: Write the failing test** (`packages/core/test/name-distance.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { canonical, damerauLevenshtein, typosquatMatch, normalizeName } from "../src/name-distance.js";

describe("damerauLevenshtein", () => {
  test("identical → 0", () => assert.equal(damerauLevenshtein("express", "express"), 0));
  test("single substitution → 1", () => assert.equal(damerauLevenshtein("express", "ekpress"), 1));
  test("single insertion → 1", () => assert.equal(damerauLevenshtein("expres", "express"), 1));
  test("single deletion → 1", () => assert.equal(damerauLevenshtein("expresss", "express"), 1));
  test("transposition → 1", () => assert.equal(damerauLevenshtein("exrpess", "express"), 1));
  test("two edits → 2", () => assert.equal(damerauLevenshtein("abcd", "abxy"), 2));
});

describe("canonical", () => {
  test("folds separators and scope", () => {
    assert.equal(canonical("node-fetch"), canonical("node_fetch"));
    assert.equal(canonical("node-fetch"), canonical("nodefetch"));
  });
  test("folds homoglyphs", () => {
    assert.equal(canonical("l0dash"), canonical("lodash"));   // 0→o
    assert.equal(canonical("1odash"), canonical("lodash"));   // 1→l
    assert.equal(canonical("moment"), canonical("rnoment"));  // rn→m
  });
});

describe("typosquatMatch", () => {
  test("transposition is a match", () => assert.equal(typosquatMatch("exrpess", "express"), true));
  test("doubling is a match", () => assert.equal(typosquatMatch("expresss", "express"), true));
  test("homoglyph is a match", () => assert.equal(typosquatMatch("l0dash", "lodash"), true));
  test("separator trick is a match", () => assert.equal(typosquatMatch("node_fetch", "node-fetch"), true));
  test("identical is NOT a match", () => assert.equal(typosquatMatch("express", "express"), false));
  test("clearly different is NOT a match", () => assert.equal(typosquatMatch("react", "express"), false));
  test("distance 2 on a long name is a match", () => assert.equal(typosquatMatch("expryss", "express"), true));
  test("distance 2 on a SHORT name is NOT a match", () => assert.equal(typosquatMatch("abcd", "wxyz"), false));
});

describe("normalizeName", () => {
  test("flattens @scope/name to the scope", () => assert.equal(normalizeName("@acme/utils"), "acme"));
  test("bare hyphenated name folds", () => assert.equal(normalizeName("acme-internal"), "acmeinternal"));
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/core/test/name-distance.test.ts
```

Expected: FAIL — cannot find module `../src/name-distance.js`.

- [ ] **Step 3: Implement `packages/core/src/name-distance.ts`**

```ts
/** Lowercase, strip a leading @, drop separators. */
function stripSeparators(s: string): string {
  return s.toLowerCase().replace(/^@/, "").replace(/[/_-]/g, "");
}

/** Map visually-confusable characters to a canonical form. */
function deHomoglyph(s: string): string {
  return s
    .replace(/rn/g, "m") // digraph confusable first
    .replace(/[0]/g, "o")
    .replace(/[1|]/g, "l")
    .replace(/[5]/g, "s");
}

/** Separator- and homoglyph-folded canonical form for squat comparison. */
export function canonical(s: string): string {
  return deHomoglyph(stripSeparators(s));
}

/**
 * Flatten a package (or namespace) name to its scope-or-base for dependency-confusion
 * comparison: `@acme/utils` → `acme`, `@acme/*` → `acme`, `acme-internal` → `acmeinternal`.
 */
export function normalizeName(s: string): string {
  const noScope = s.replace(/^@/, "");
  const base = noScope.includes("/") ? noScope.split("/")[0]! : noScope;
  return base.replace(/[*]/g, "").replace(/[/_-]/g, "").toLowerCase();
}

/** Optimal-string-alignment (Damerau-Levenshtein with adjacent transpositions). */
export function damerauLevenshtein(a: string, b: string): number {
  const al = a.length, bl = b.length;
  if (al === 0) return bl;
  if (bl === 0) return al;
  const d: number[][] = Array.from({ length: al + 1 }, () => new Array<number>(bl + 1).fill(0));
  for (let i = 0; i <= al; i++) d[i]![0] = i;
  for (let j = 0; j <= bl; j++) d[0]![j] = j;
  for (let i = 1; i <= al; i++) {
    for (let j = 1; j <= bl; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i]![j] = Math.min(d[i]![j]!, d[i - 2]![j - 2]! + 1);
      }
    }
  }
  return d[al]![bl]!;
}

/** True iff `name` is a likely typosquat of the distinct `target`. */
export function typosquatMatch(name: string, target: string): boolean {
  if (name === target) return false;
  const a = canonical(name), b = canonical(target);
  if (a.length === 0 || b.length === 0) return false;
  if (a === b) return true; // separator / scope / homoglyph collision
  const threshold = b.length >= 7 ? 2 : 1;
  const d = damerauLevenshtein(a, b);
  return d >= 1 && d <= threshold;
}
```

- [ ] **Step 4: Run the test + build**

```bash
npm run build
npx tsx --test packages/core/test/name-distance.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/name-distance.ts packages/core/test/name-distance.test.ts
git commit -m "feat(phase13): name-distance helpers (canonical fold, Damerau-Levenshtein, typosquatMatch)"
```

---

### Task 2: Corpus asset + typosquat rule

**Files:**
- Create: `packages/core/src/typosquat-corpus.ts`
- Create: `packages/core/src/rules/typosquat.ts`
- Modify: `packages/core/src/rules/index.ts` (register + export)
- Test: `packages/core/test/typosquat-rule.test.ts`

**Interfaces:**
- Consumes: `typosquatMatch`, `canonical` (Task 1); `mkFinding` from `rules/util.ts`; the `Rule`/`AuditInput`/`Finding` types.
- Produces: `POPULAR_NPM_NAMES: readonly string[]` (bundled corpus) and `typosquatRule: Rule` (id `"typosquat"`, category `"metadata"`), registered in `RULES`.

- [ ] **Step 1: Create the corpus** `packages/core/src/typosquat-corpus.ts`

```ts
/**
 * Bundled corpus of popular / frequently-typosquatted npm package names.
 * Curated snapshot (2026-07); a STATIC input — never fetched at audit time
 * (invariant #3). Expand as needed; keep entries lowercase and de-duplicated.
 */
export const POPULAR_NPM_NAMES: readonly string[] = [
  "express", "lodash", "react", "react-dom", "chalk", "axios", "commander",
  "request", "debug", "async", "bluebird", "underscore", "moment", "webpack",
  "babel-core", "typescript", "eslint", "prettier", "jest", "mocha", "chai",
  "vue", "angular", "rxjs", "redux", "next", "nuxt", "vite", "rollup", "esbuild",
  "dotenv", "cors", "body-parser", "socket.io", "ws", "node-fetch", "cross-env",
  "rimraf", "glob", "minimist", "yargs", "inquirer", "ora", "boxen", "figlet",
  "colors", "cli-table", "semver", "uuid", "nanoid", "classnames", "prop-types",
  "styled-components", "tailwindcss", "postcss", "autoprefixer", "sass", "less",
  "jquery", "bootstrap", "d3", "three", "chart.js", "leaflet", "mapbox-gl",
  "graphql", "apollo-client", "prisma", "sequelize", "mongoose", "typeorm", "knex",
  "pg", "mysql", "mysql2", "redis", "ioredis", "node-cron", "nodemailer", "passport",
  "jsonwebtoken", "bcrypt", "bcryptjs", "helmet", "morgan", "winston", "pino",
  "dayjs", "date-fns", "luxon", "validator", "joi", "zod", "yup", "ajv", "immer",
  "ramda", "rxdb", "fastify", "koa", "hapi", "nestjs", "@nestjs/core", "electron",
  "puppeteer", "playwright", "cheerio", "jsdom", "sharp", "jimp", "canvas",
  "form-data", "qs", "query-string", "cookie", "cookie-parser", "express-session",
  "multer", "concurrently", "nodemon", "ts-node", "tsx", "husky", "lint-staged",
  "typedoc", "jsonwebtoken", "aws-sdk", "@aws-sdk/client-s3", "firebase", "stripe",
  "twilio", "openai", "@anthropic-ai/sdk", "googleapis", "octokit", "simple-git",
  "fs-extra", "chokidar", "execa", "shelljs", "tar", "archiver", "adm-zip",
  "handlebars", "ejs", "pug", "marked", "markdown-it", "highlight.js", "prismjs",
  "core-js", "regenerator-runtime", "tslib", "@babel/core", "@babel/preset-env",
];
```

- [ ] **Step 2: Write the failing test** (`packages/core/test/typosquat-rule.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { typosquatRule } from "../src/rules/typosquat.js";
import type { AuditInput, PackageMeta } from "../src/types.js";

function input(name: string): AuditInput {
  const meta = { name, version: "1.0.0", author: null, maintainers: [], license: null,
    hasInstallScripts: false, signature: "unsigned", provenance: "absent", integrity: null,
    unpackedSize: 0, fileCount: 0 } as unknown as PackageMeta;
  return { meta, files: [], mode: "full" };
}

describe("typosquat rule", () => {
  test("a near-miss of a popular name is flagged medium, naming the target", () => {
    const f = typosquatRule.run(input("expres"));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.severity, "medium");
    assert.equal(f[0]!.category, "metadata");
    assert.match(f[0]!.message, /express/);
  });

  test("a name that IS in the corpus is NOT flagged (FP control)", () => {
    assert.deepEqual(typosquatRule.run(input("express")), []);
  });

  test("a clearly-unrelated name is not flagged", () => {
    assert.deepEqual(typosquatRule.run(input("my-unique-app-9000")), []);
  });

  test("a very short name (<4 chars) is not flagged (FP control)", () => {
    assert.deepEqual(typosquatRule.run(input("axi")), []);
  });

  test("a homoglyph squat is flagged", () => {
    const f = typosquatRule.run(input("l0dash"));
    assert.equal(f.length, 1);
    assert.match(f[0]!.message, /lodash/);
  });
});
```

- [ ] **Step 3: Run to verify it fails**

```bash
npx tsx --test packages/core/test/typosquat-rule.test.ts
```

Expected: FAIL — cannot find module `../src/rules/typosquat.js`.

- [ ] **Step 4: Implement `packages/core/src/rules/typosquat.ts`**

```ts
import type { AuditInput, Finding, Rule } from "../types.js";
import { mkFinding } from "./util.js";
import { canonical, typosquatMatch } from "../name-distance.js";
import { POPULAR_NPM_NAMES } from "../typosquat-corpus.js";

// Length-bucketed corpus (by canonical length) so a lookup only compares against
// nearby-length names — bounded, cheap (invariant #3). Built once at module load.
const CORPUS = POPULAR_NPM_NAMES.map((n) => n.toLowerCase());
const CORPUS_SET = new Set(CORPUS);
const BY_LEN = new Map<number, string[]>();
for (const n of CORPUS) {
  const len = canonical(n).length;
  for (const l of [len - 2, len - 1, len, len + 1, len + 2]) {
    (BY_LEN.get(l) ?? BY_LEN.set(l, []).get(l)!).push(n);
  }
}

/**
 * Flags a package whose name is a likely typosquat of a popular package. Pure and
 * policy-blind: name vs a bundled static corpus. FP controls: never flag a name that
 * IS in the corpus; skip names < 4 chars; the matched target must be distinct.
 */
export const typosquatRule: Rule = {
  id: "typosquat",
  category: "metadata",
  run(input: AuditInput): Finding[] {
    const name = input.meta.name.toLowerCase();
    if (name.length < 4 || CORPUS_SET.has(name)) return [];
    const candidates = BY_LEN.get(canonical(name).length) ?? [];
    for (const target of candidates) {
      if (typosquatMatch(name, target)) {
        return [mkFinding({
          ruleId: this.id, category: this.category, severity: "medium",
          message: `\`${input.meta.name}\` resembles the popular package \`${target}\` — possible typosquat.`,
          evidence: [], files: input.files,
        })];
      }
    }
    return [];
  },
};
```

- [ ] **Step 5: Register in `packages/core/src/rules/index.ts`** — import, add to `RULES`, and re-export:

```ts
import { typosquatRule } from "./typosquat.js";
// … add typosquatRule to the RULES array …
// … add typosquatRule to the export block …
```

- [ ] **Step 6: Run the test + build + full core suite**

```bash
npm run build
npx tsx --test packages/core/test/typosquat-rule.test.ts
npm test 2>&1 | tail -6
```

Expected: typosquat-rule PASS. The full suite should stay green — BUT the new rule now runs on every audit, so if a fixture's name happens to be a near-miss of a corpus entry, its score shifts. Check the determinism test + fixture-verdict tests; if a benign fixture name accidentally trips the rule, that is a real signal to note (adjust the fixture name is NOT allowed here — report it; most fixture names like `leftpad-lite`/`net-fetch-lite` are not corpus near-misses). The `scoring is deterministic across runs` test pins the DEFAULT policy on a fixed audit — it stays green because the rule is deterministic.

- [ ] **Step 7: Commit**

```bash
git add packages/core/src/typosquat-corpus.ts packages/core/src/rules/typosquat.ts packages/core/src/rules/index.ts packages/core/test/typosquat-rule.test.ts
git commit -m "feat(phase13): typosquat rule + bundled popular-name corpus (metadata category, medium)"
```

---

### Task 3: Dependency-confusion score-time check

**Files:**
- Modify: `packages/core/src/score.ts`
- Test: `packages/core/test/score.test.ts` (extend)

**Interfaces:**
- Consumes: `canonical`, `typosquatMatch`, `normalizeName` (Task 1); `matchPackage`, `EnterprisePolicy` (policy.js); `Finding` (types.js).
- Produces: a `dependencyConfusion(name, privateNamespaces): Finding | null` helper in `score.ts`; the returned finding is injected into the scored set as a normally-weighted `high` `metadata` finding (`ruleId: "dependency-confusion"`) — it contributes to the score but does NOT force a block.

- [ ] **Step 1: Write the failing tests** — add to `packages/core/test/score.test.ts` (it already has an `auditWith(...)` helper and imports `score`, `DEFAULT_POLICY`, `EnterprisePolicy`; if the existing helper can't set an arbitrary `meta.name`, build the audit inline as below):

```ts
import { score, DEFAULT_POLICY } from "../src/score.js";
import type { Audit, PackageMeta } from "../src/types.js";
import type { EnterprisePolicy } from "../src/policy.js";

function auditNamed(name: string): Audit {
  const meta = { name, version: "1.0.0", author: null, maintainers: [], license: null,
    hasInstallScripts: false, signature: "unsigned", provenance: "absent", integrity: "sha512-x",
    unpackedSize: 10, fileCount: 1 } as unknown as PackageMeta;
  return { schema: 3, meta, findings: [], capabilities: [], capabilityDelta: null,
    engine: { version: "0.1.0", rules: [], mode: "full" }, auditedAt: "t", durationMs: 0 };
}
const withClaim = (ns: string[]): EnterprisePolicy => ({ ...DEFAULT_POLICY, privateNamespaces: ns });

describe("dependency-confusion gate", () => {
  test("a public look-alike of a claimed scope is flagged high", () => {
    const r = score(auditNamed("acme-internal"), withClaim(["@acme/*"]));
    const f = r.findings.find((x) => x.ruleId === "dependency-confusion");
    assert.ok(f, "expected a dependency-confusion finding");
    assert.equal(f!.severity, "high");
    assert.equal(f!.category, "metadata");
    assert.match(f!.message, /@acme/);
  });

  test("the legitimate claimed package itself is NOT flagged", () => {
    const r = score(auditNamed("@acme/utils"), withClaim(["@acme/*"]));
    assert.equal(r.findings.find((x) => x.ruleId === "dependency-confusion"), undefined);
  });

  test("an unrelated public package is NOT flagged", () => {
    const r = score(auditNamed("lodash"), withClaim(["@acme/*"]));
    assert.equal(r.findings.find((x) => x.ruleId === "dependency-confusion"), undefined);
  });

  test("no claimed namespaces (default policy) → gate inert", () => {
    const r = score(auditNamed("acme-internal"), DEFAULT_POLICY);
    assert.equal(r.findings.find((x) => x.ruleId === "dependency-confusion"), undefined);
  });

  test("the finding is weighted (contributes to the score), not a forced block", () => {
    const r = score(auditNamed("acme-internal"), withClaim(["@acme/*"]));
    assert.ok(r.score < 100, "the high finding must lower the score");
    // high (-25) alone → 75 → warn, not block:
    assert.equal(r.verdict, "warn");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/core/test/score.test.ts
```

Expected: FAIL — no `dependency-confusion` finding produced.

- [ ] **Step 3: Implement the check in `score.ts`**

Add imports at the top:

```ts
import { canonical, typosquatMatch, normalizeName } from "./name-distance.js";
import type { Finding } from "./types.js";
```

Add the helper near `identityViolation` (bottom of the file):

```ts
/**
 * Dependency-confusion detection (ADR-0026): a PUBLIC package whose name is a
 * confusable look-alike of a namespace the operator explicitly claimed
 * (policy.privateNamespaces). Never flags the legitimate claimed package itself
 * (it matches the claim via matchPackage). Pure; guarded against a malformed name.
 */
function dependencyConfusion(name: string, privateNamespaces: string[]): Finding | null {
  if (!name || privateNamespaces.length === 0) return null;
  // The real private package legitimately matches its own claim — never flag it.
  if (privateNamespaces.some((c) => matchPackage(c, name))) return null;
  const nc = canonical(name);
  for (const claim of privateNamespaces) {
    const scope = normalizeName(claim); // "@acme/*" → "acme"; "internal-tool" → "internaltool"
    if (scope.length < 3) continue;
    if (nc === scope || nc.startsWith(scope) || typosquatMatch(nc, scope)) {
      return {
        ruleId: "dependency-confusion", category: "metadata", severity: "high",
        message: `\`${name}\` resembles your claimed private namespace \`${claim}\` — possible dependency confusion.`,
        onChangedFile: false, evidence: [],
      };
    }
  }
  return null;
}
```

Wire it into `score()` — replace the `audit.findings.map(...)` source so the injected finding gets the SAME waiver + weight treatment. Change:

```ts
  const disabled = new Set(policy.rules.disabled);
  const dcFinding = dependencyConfusion(audit.meta.name, policy.privateNamespaces ?? []);
  const rawFindings = dcFinding ? [...audit.findings, dcFinding] : audit.findings;
  const scored: ScoredFinding[] = rawFindings.map((f) => {
    // … unchanged body …
  });
```

(Everything else — penalty, verdict, the existing gates — is unchanged. The dependency-confusion finding contributes its `high` weight to `penalty` and appears in `findings`, but adds NO term to the `verdict` block-forcing condition, so it is not a categorical hard-block.)

- [ ] **Step 4: Run the tests + build**

```bash
npm run build
npx tsx --test packages/core/test/score.test.ts
```

Expected: PASS (including the existing `scoring is deterministic across runs` test — the default policy has no `privateNamespaces`, so `dcFinding` is null and the pinned score is unchanged).

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/score.ts packages/core/test/score.test.ts
git commit -m "feat(phase13): dependency-confusion score-time check vs claimed private namespaces (high, weighted)"
```

---

### Task 4: Fixtures + end-to-end proof

**Files:**
- Create: `fixtures/benign/expres/1.0.0/package/{package.json,index.js}`
- Create: `fixtures/benign/express/1.0.0/package/{package.json,index.js}` (negative control)
- Modify: `fixtures/index.json`
- Test: `packages/proxy/test/typosquat-e2e.test.ts`

**Interfaces:**
- Consumes: the typosquat rule (Task 2) + the dependency-confusion check (Task 3) through the proxy audit path.

- [ ] **Step 1: Create the typosquat fixture** — `fixtures/benign/expres/1.0.0/package/package.json`:

```json
{ "name": "expres", "version": "1.0.0", "description": "SYNTHETIC BENIGN FIXTURE — a typosquat-shaped NAME (near-miss of `express`) with entirely benign content. Detection fires on the name, not the bytes.", "license": "MIT", "main": "index.js" }
```

`fixtures/benign/expres/1.0.0/package/index.js`:

```js
module.exports = { ok: true };
```

- [ ] **Step 2: Create the negative-control fixture** — `fixtures/benign/express/1.0.0/package/package.json`:

```json
{ "name": "express", "version": "1.0.0", "description": "SYNTHETIC BENIGN FIXTURE — a name that IS in the corpus; must NOT be flagged as a typosquat (proves the name-in-corpus FP control).", "license": "MIT", "main": "index.js" }
```

`fixtures/benign/express/1.0.0/package/index.js`:

```js
module.exports = { ok: true };
```

- [ ] **Step 3: Register both in `fixtures/index.json`** (benign class, minimal entries):

```json
    "expres": {
      "class": "benign",
      "versions": { "1.0.0": { "signature": "valid", "provenance": false } }
    },
    "express": {
      "class": "benign",
      "versions": { "1.0.0": { "signature": "valid", "provenance": false } }
    }
```

- [ ] **Step 4: Rebuild fixtures**

```bash
npm run fixtures
node -e "const r=require('./fixtures/registry.json'); for (const n of ['expres','express']) if(!r.packages[n]) throw new Error('missing '+n); console.log('fixtures OK')"
```

Expected: `fixtures OK`.

- [ ] **Step 5: Write the e2e** (`packages/proxy/test/typosquat-e2e.test.ts`) — model the boot on the existing proxy e2e suites (in-process `createServer` + `LocalFixtureUpstream` + all stores incl. `violations`/`approvalRequests`; a private-namespace policy for the dependency-confusion assertion):

```ts
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type AuditReport, type EnterprisePolicy } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}
function boot(policy: EnterprisePolicy): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: policy,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(),
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` })); });
}
const report = async (base: string, pkg: string, v: string): Promise<AuditReport> =>
  (await (await fetch(`${base}/-/audit/${pkg}/${v}`)).json()) as AuditReport;

describe("typosquat + dependency-confusion (e2e)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot({ ...DEFAULT_POLICY, privateNamespaces: ["@acme/*"] })); });
  after(() => server?.close());

  test("the typosquat fixture `expres` is flagged (resembles express)", async () => {
    const r = await report(base, "expres", "1.0.0");
    const f = r.findings.find((x) => x.ruleId === "typosquat");
    assert.ok(f, "expected a typosquat finding");
    assert.match(f!.message, /express/);
  });

  test("the negative-control `express` (in corpus) is NOT flagged", async () => {
    const r = await report(base, "express", "1.0.0");
    assert.equal(r.findings.find((x) => x.ruleId === "typosquat"), undefined);
  });
});
```

(The dependency-confusion e2e against a served fixture would require a benign `acme-internal` fixture; the score-time check is already covered by Task 3's unit tests, so this e2e focuses on the typosquat path + the FP control. If you want the dependency-confusion e2e too, add an `acme-internal` benign fixture and assert its report carries a `dependency-confusion` finding under the `@acme/*` policy — optional, not required for this task.)

- [ ] **Step 6: Build + run the e2e + full suite**

```bash
npm run build
npx tsx --test packages/proxy/test/typosquat-e2e.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS; record the full-suite counts.

- [ ] **Step 7: Commit**

```bash
git add fixtures/benign/expres fixtures/benign/express fixtures/index.json packages/proxy/test/typosquat-e2e.test.ts
git commit -m "feat(phase13): benign typosquat + negative-control fixtures + e2e"
```

---

### Task 5: Docs, ADR-0026, final verification

**Files:**
- Create: `docs/adr/0026-supply-chain-identity-heuristics.md`
- Modify: `ARCHITECTURE.md` (rules list + the score-time gates section)
- Modify: `CLAUDE.md` (What-this-is phase list; test-count line)
- Modify: `README.md` (the two new signals + the corpus note)

- [ ] **Step 1: Write ADR-0026** — follow the house style of `docs/adr/0025-control-plane-auth.md`. Required content: **Context** (six rules detect code / verify crypto identity, but the social-engineering naming attack class — typosquat, dependency confusion — is undetected; Sentinel uniquely holds the private-namespace claims). **Decision** (a pure typosquat rule vs a bundled static corpus + a score-time dependency-confusion check vs `privateNamespaces`; shared `name-distance` helpers; both `metadata`-category weighted findings; the pure-rule/score-time split mirrors ADR-0014). **Determinism** (both pure; default policy has no claims so the confusion check is inert by default — invariant #1 untouched; corpus is a static input). **Weighted-not-hard-block** (typosquat medium, confusion high; the arithmetic: medium −12 → 88 allow, high −25 → 75 warn; they compound; operators escalate/waive). **False-positive controls** (name-in-corpus, <4 chars, distinct target; the confusion check never flags the legitimate claimed package). **Consequences** (catches the event-stream / ua-parser-js / typosquat attack class; the corpus is curated + operator-updatable). **Deferred** (`protectedNamespaces` field; metadata-novelty/age signals; maintainer-change anomalies; download-weighted ranking; corpus auto-update). **Rejected** (dynamic detonation — non-deterministic, platform-heavy; typosquat-only — leaves dependency confusion on the table). Extends ADR-0002/0008/0010/0014.

- [ ] **Step 2: ARCHITECTURE.md** — add `typosquat` to the rules list (metadata category) and document the dependency-confusion score-time check beside the signature/provenance gates; note both are deterministic weighted findings and the corpus is a static bundled input.

- [ ] **Step 3: CLAUDE.md** — add the Phase 13 sentence to "What this is" (mirror Phase 12's density: typosquat rule vs a bundled corpus + dependency-confusion score-time check vs claimed namespaces, both `metadata` weighted findings, deterministic). Update the `npm test` count line with the ACTUAL number from Step 5 (preserve the darwin-skip caveats).

- [ ] **Step 4: README.md** — a short "Supply-chain identity signals" note: typosquat detection (bundled popular-name corpus, edit-distance + patterns) and dependency-confusion detection (public look-alikes of your claimed `privateNamespaces`), both weighted findings that raise the score.

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
git commit -m "docs(phase13): ADR-0026 supply-chain identity heuristics; ARCHITECTURE rules + gates; CLAUDE/README"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 architecture (name-distance split, pure rule + score-time gate) → Tasks 1/2/3; §2 typosquat rule (corpus, Damerau + patterns, FP controls, medium) → Tasks 1/2; §3 dependency-confusion gate (name-vs-claim, never-flag-legit-claim, high, weighted, reuses privateNamespaces) → Task 3; §4 fixtures/tests/determinism/DoD → Tasks 4/5. Invariant #1 (inert-by-default gate + pure rule) proven by Task 3's default-policy test + the pinned determinism test.
- **Type consistency:** `canonical`/`normalizeName`/`damerauLevenshtein`/`typosquatMatch` (Task 1) consumed by name in Tasks 2/3; `POPULAR_NPM_NAMES`/`typosquatRule` (Task 2) registered in RULES; `dependency-confusion` ruleId + `metadata` category consistent between Task 3's gate and Task 4's e2e assertions; both findings use the existing `metadata` `Category`.
- **Known judgment calls:** the dependency-confusion finding is injected via `[...audit.findings, dcFinding]` BEFORE the score-map so it gets normal waiver + weight treatment (contributes to the score, respects `allow`/`disabled` waivers) and is NOT added to the verdict block-forcing condition (weighted, not a categorical hard-block) — matching the spec. The corpus is a curated seed (~150 names) shipped as committed static data, expandable; it deliberately includes the fixtures' target `express`. FP controls live in the rule, not the match predicate, so the predicate stays a clean similarity function reused by the gate.
