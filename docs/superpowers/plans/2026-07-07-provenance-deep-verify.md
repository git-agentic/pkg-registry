# Phase 9 — Provenance Deep-Verify Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Full offline Sigstore verification of npm attestation bundles at the audit gate, a per-namespace provenance-identity policy gate, and served-bytes integrity recomputation.

**Architecture:** A new pure `verifyProvenance()` in core (sibling of `signature.ts`) verifies attestation bundles with `@sigstore/verify` against pinned trust material (bundled `trusted-root.json` + npm attestation keys — static inputs, never fetched at audit time). The proxy fetches bundles on the *acquisition* path (`Upstream.getAttestations`), recomputes tarball integrity from served bytes, and `runAudit` widens `PackageMeta.provenance` to `verified | invalid | absent | unknown` plus an extracted identity. `score.ts` gains a `provenanceIdentities` policy gate evaluated at score time.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; new core deps `@sigstore/verify@^3.1.1`, `@sigstore/bundle@^4.0.0`, `@sigstore/protobuf-specs@^0.5.1`.

**Spec:** `docs/superpowers/specs/2026-07-07-provenance-deep-verify-design.md`. One security refinement over the spec (record in ADR-0022 and amend the spec in Task 9): a thrown error while verifying *present* bundles maps to **`invalid`**, not `unknown` — a crafted crash-bundle must not fail open past an identity gate. `unknown` is reserved for missing inputs only (bundle unfetchable, no trust material, empty bundle list).

## Global Constraints

- **Invariant #3:** no network at audit time. Attestation fetching lives in `Upstream` (acquisition path); `verifyProvenance` is pure crypto over bytes.
- **Invariant #1:** deterministic scoring — the `scoring is deterministic across runs` test must stay green; trust-root staleness uses an injectable `verifyAt` timestamp and an info (zero-weight-by-default) finding.
- **Invariant #6:** the audit never crashes; `verifyProvenance` never throws (returns a status).
- ESM only, NodeNext: internal imports use `.js` specifiers even from `.ts`.
- Tests stay hermetic: `LocalFixtureUpstream` only; captured real Sigstore bundles are *data* fixtures verified offline. Never hit live npm in `npm test`.
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/<pkg>` instead of deleting `dist/`.
- After editing anything under `fixtures/`, re-run `npm run fixtures` (registry.json is regenerated and gitignored; `.tarballs/` is gitignored).
- Run all commands from the repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.
- The probe workspace with captured artifacts exists at
  `/private/tmp/claude-501/-Users-tonibergholm-Developer-claude-pkg-registry/db8ab792-be49-4412-9f70-01d542fbc919/scratchpad/sigstore-probe` (referred to below as `$PROBE`). Each copy step has a network fallback.

---

### Task 1: Dependencies + vendored trust material and attestation fixtures

**Files:**
- Modify: `packages/core/package.json` (via npm install)
- Create: `packages/core/trust/trusted-root.json`
- Create: `packages/core/trust/npm-attestation-keys.json`
- Create: `fixtures/attestations/sigstore-3.0.0.attestations.json`
- Create: `fixtures/vendored/sigstore-3.0.0.tgz`

**Interfaces:**
- Produces: the four data files above, consumed by Tasks 2, 5, 6. `trusted-root.json` is the canonical protobuf-JSON TUF target; `npm-attestation-keys.json` is the raw `registry.npmjs.org/keys.json` TUF target (shape `{"keys":[{"keyId","keyUsage","publicKey":{"rawBytes","keyDetails","validFor":{"start","end"}}}]}`).

- [ ] **Step 1: Install the sigstore verification deps into core**

```bash
npm install @sigstore/verify@^3.1.1 @sigstore/bundle@^4.0.0 @sigstore/protobuf-specs@^0.5.1 -w packages/core
```

- [ ] **Step 2: Copy captured artifacts from the probe workspace**

```bash
PROBE=/private/tmp/claude-501/-Users-tonibergholm-Developer-claude-pkg-registry/db8ab792-be49-4412-9f70-01d542fbc919/scratchpad/sigstore-probe
mkdir -p packages/core/trust fixtures/attestations fixtures/vendored
cp "$PROBE/tufcache/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json" packages/core/trust/trusted-root.json
cp "$PROBE/tufcache/tuf-repo-cdn.sigstore.dev/targets/registry.npmjs.org%2Fkeys.json" packages/core/trust/npm-attestation-keys.json
cp "$PROBE/attestations.json" fixtures/attestations/sigstore-3.0.0.attestations.json
cp "$PROBE/sigstore-3.0.0.tgz" fixtures/vendored/sigstore-3.0.0.tgz
```

Fallback if `$PROBE` is gone (requires network, one-time):
`curl -s "https://registry.npmjs.org/-/npm/v1/attestations/sigstore@3.0.0" -o fixtures/attestations/sigstore-3.0.0.attestations.json`,
`curl -sL "https://registry.npmjs.org/sigstore/-/sigstore-3.0.0.tgz" -o fixtures/vendored/sigstore-3.0.0.tgz`, and for the trust files run in a temp dir: `node -e 'import("@sigstore/tuf").then(async t=>{await t.getTrustedRoot({cachePath:"./tufcache"})})'` (with `@sigstore/tuf` installed) then copy the two targets from `tufcache/tuf-repo-cdn.sigstore.dev/targets/`.

- [ ] **Step 3: Verify the vendored tarball's integrity matches the real packument claim**

```bash
node -e "
const {createHash}=require('node:crypto');const fs=require('node:fs');
const b=fs.readFileSync('fixtures/vendored/sigstore-3.0.0.tgz');
const got='sha512-'+createHash('sha512').update(b).digest('base64');
const want='sha512-PHMifhh3EN4loMcHCz6l3v/luzgT3za+9f8subGgeMNjbJjzH4Ij/YoX3Gvu+kaouJRIlVdTHHCREADYf+ZteA==';
if(got!==want){console.error('INTEGRITY MISMATCH',got);process.exit(1)}
console.log('vendored tarball integrity OK');"
```

Expected: `vendored tarball integrity OK`

- [ ] **Step 4: Sanity-check JSON parses and build still passes**

```bash
node -e "JSON.parse(require('node:fs').readFileSync('packages/core/trust/trusted-root.json','utf8')); JSON.parse(require('node:fs').readFileSync('packages/core/trust/npm-attestation-keys.json','utf8')); JSON.parse(require('node:fs').readFileSync('fixtures/attestations/sigstore-3.0.0.attestations.json','utf8')); console.log('all parse')"
npm run build
```

Expected: `all parse`, clean build.

- [ ] **Step 5: Commit**

```bash
git add packages/core/package.json package-lock.json packages/core/trust fixtures/attestations fixtures/vendored
git commit -m "feat(phase9): vendor pinned Sigstore trust material + real attestation fixtures; add @sigstore verify deps"
```

---

### Task 2: Core types + `verifyProvenance()` (offline Sigstore verifier)

**Files:**
- Modify: `packages/core/src/types.ts:81` (PackageMeta.provenance) and add types
- Create: `packages/core/src/provenance.ts`
- Modify: `packages/core/src/index.ts` (exports)
- Test: `packages/core/test/provenance.test.ts`

**Interfaces:**
- Consumes: Task 1's data files.
- Produces (used by Tasks 3–8):
  - `type ProvenanceStatus = "verified" | "invalid" | "absent" | "unknown"`
  - `interface ProvenanceIdentity { workflow: string|null; issuer: string|null; sourceRepository: string|null; ref: string|null; builder: string|null; commit: string|null }`
  - `PackageMeta.provenance: ProvenanceStatus` and `PackageMeta.provenanceIdentity?: ProvenanceIdentity | null`
  - `interface ProvenanceTrustMaterial { trustedRootJson: unknown; npmKeys: NpmAttestationKey[] }`
  - `verifyProvenance(input: { name: string; version: string; integrity: string; claimed: boolean; attestations: unknown | null; trust: ProvenanceTrustMaterial | null; now?: string }): ProvenanceVerification` where `ProvenanceVerification = { status: ProvenanceStatus; identity: ProvenanceIdentity | null; reason: string | null; rootStale: boolean }`
  - `loadDefaultTrustMaterial(): ProvenanceTrustMaterial | null`, `loadTrustMaterial(opts: { trustedRootPath: string; npmKeysPath?: string }): ProvenanceTrustMaterial`

- [ ] **Step 1: Update types.ts**

Replace line 81's `provenance: "present" | "absent";` and add the new types:

```ts
// in types.ts, after SignatureVerdict:
/** Result of verifying a package's provenance attestation bundles (Phase 9). */
export type ProvenanceStatus = "verified" | "invalid" | "absent" | "unknown";

/** Identity extracted from a verified SLSA provenance attestation. */
export interface ProvenanceIdentity {
  /** Signing workflow identity (Fulcio cert SAN), e.g. "https://github.com/o/r/.github/workflows/release.yml@refs/heads/main". */
  workflow: string | null;
  /** OIDC issuer, e.g. "https://token.actions.githubusercontent.com". */
  issuer: string | null;
  /** Source repository URL from the signed SLSA predicate. */
  sourceRepository: string | null;
  /** Git ref the build ran from, e.g. "refs/heads/main". */
  ref: string | null;
  /** Builder id, e.g. "https://github.com/actions/runner/github-hosted". */
  builder: string | null;
  /** Resolved source commit SHA. */
  commit: string | null;
}
```

In `PackageMeta` replace the provenance field with:

```ts
  /** Verified provenance-attestation status (ADR-0022). */
  provenance: ProvenanceStatus;
  /** Identity from the verified SLSA attestation; null unless provenance is "verified". */
  provenanceIdentity?: ProvenanceIdentity | null;
```

- [ ] **Step 2: Write the failing test** (`packages/core/test/provenance.test.ts`)

```ts
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { Buffer } from "node:buffer";
import { loadDefaultTrustMaterial, verifyProvenance } from "../src/provenance.js";
import { FIXTURES } from "./helpers.js";

const ATTESTATIONS = JSON.parse(
  readFileSync(join(FIXTURES, "attestations", "sigstore-3.0.0.attestations.json"), "utf8"),
) as { attestations: { predicateType: string; bundle: { dsseEnvelope: { payload: string } } }[] };

// Real integrity of sigstore@3.0.0 (matches the attestation subject digest).
const REAL_INTEGRITY =
  "sha512-PHMifhh3EN4loMcHCz6l3v/luzgT3za+9f8subGgeMNjbJjzH4Ij/YoX3Gvu+kaouJRIlVdTHHCREADYf+ZteA==";

const trust = loadDefaultTrustMaterial();
const base = { name: "sigstore", version: "3.0.0", integrity: REAL_INTEGRITY, claimed: true, trust };

describe("verifyProvenance — real captured bundle, offline", () => {
  test("bundled trust material loads", () => {
    assert.ok(trust, "packages/core/trust/*.json must load");
    assert.ok(trust!.npmKeys.length >= 1);
  });

  test("verified: real SLSA + publish attestations verify and identity is extracted", () => {
    const r = verifyProvenance({ ...base, attestations: ATTESTATIONS });
    assert.equal(r.status, "verified");
    assert.equal(r.identity?.sourceRepository, "https://github.com/sigstore/sigstore-js");
    assert.equal(r.identity?.issuer, "https://token.actions.githubusercontent.com");
    assert.equal(r.identity?.builder, "https://github.com/actions/runner/github-hosted");
    assert.equal(r.identity?.ref, "refs/heads/main");
    assert.equal(r.identity?.commit, "3a57a741bfb9f7c3bca69b63e170fc28e9432e69");
    assert.match(r.identity?.workflow ?? "", /^https:\/\/github\.com\/sigstore\/sigstore-js\//);
  });

  test("invalid: tampered DSSE payload", () => {
    const tampered = structuredClone(ATTESTATIONS);
    const slsa = tampered.attestations.find((a) => a.predicateType === "https://slsa.dev/provenance/v1")!;
    const p = Buffer.from(slsa.bundle.dsseEnvelope.payload, "base64").toString();
    slsa.bundle.dsseEnvelope.payload = Buffer.from(p.replace("sigstore-js", "evil-repo")).toString("base64");
    const r = verifyProvenance({ ...base, attestations: tampered });
    assert.equal(r.status, "invalid");
    assert.ok(r.reason);
  });

  test("invalid: valid attestation for a DIFFERENT tarball (subject-binding failure)", () => {
    const r = verifyProvenance({ ...base, integrity: "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" });
    assert.equal(r.status, "invalid");
    assert.match(r.reason ?? "", /subject digest/);
  });

  test("invalid: malformed bundle fails closed, not unknown", () => {
    const r = verifyProvenance({ ...base, attestations: { attestations: [{ predicateType: "x", bundle: { garbage: true } }] } });
    assert.equal(r.status, "invalid");
  });

  test("absent: not claimed", () => {
    assert.equal(verifyProvenance({ ...base, claimed: false, attestations: null }).status, "absent");
  });

  test("unknown: claimed but bundles unfetchable", () => {
    assert.equal(verifyProvenance({ ...base, attestations: null }).status, "unknown");
  });

  test("unknown: claimed but no trust material configured", () => {
    assert.equal(verifyProvenance({ ...base, attestations: ATTESTATIONS, trust: null }).status, "unknown");
  });

  test("unknown: attestation endpoint returned an empty list", () => {
    assert.equal(verifyProvenance({ ...base, attestations: { attestations: [] } }).status, "unknown");
  });

  test("rootStale: false today, true far in the future when all CAs expired", () => {
    const now = verifyProvenance({ ...base, attestations: ATTESTATIONS, now: "2026-07-07T00:00:00Z" });
    assert.equal(now.rootStale, false);
    const far = verifyProvenance({ ...base, attestations: ATTESTATIONS, now: "2126-01-01T00:00:00Z" });
    assert.equal(far.rootStale, true);
  });

  test("determinism: same inputs, same result", () => {
    const a = verifyProvenance({ ...base, attestations: ATTESTATIONS, now: "2026-07-07T00:00:00Z" });
    const b = verifyProvenance({ ...base, attestations: ATTESTATIONS, now: "2026-07-07T00:00:00Z" });
    assert.deepEqual(a, b);
  });
});
```

- [ ] **Step 3: Run to verify it fails**

```bash
npx tsx --test packages/core/test/provenance.test.ts
```

Expected: FAIL — cannot find module `../src/provenance.js`.

- [ ] **Step 4: Implement `packages/core/src/provenance.ts`**

```ts
import { Buffer } from "node:buffer";
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { bundleFromJSON } from "@sigstore/bundle";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import type { ProvenanceIdentity, ProvenanceStatus } from "./types.js";

export type { ProvenanceIdentity, ProvenanceStatus };

/** One key from npm's TUF-distributed `registry.npmjs.org/keys.json` target. */
export interface NpmAttestationKey {
  keyId: string;
  keyUsage?: string;
  publicKey: {
    rawBytes: string;
    keyDetails?: string;
    validFor?: { start?: string | null; end?: string | null };
  };
}

/**
 * Pinned Sigstore trust material — a STATIC input like NPM_SIGNING_KEYS, never
 * fetched at audit time (invariant #3). `trustedRootJson` is the canonical
 * protobuf-JSON `trusted_root.json` TUF target.
 */
export interface ProvenanceTrustMaterial {
  trustedRootJson: unknown;
  npmKeys: NpmAttestationKey[];
}

export interface ProvenanceVerification {
  status: ProvenanceStatus;
  identity: ProvenanceIdentity | null;
  /** Human-readable cause when status is "invalid" or "unknown". */
  reason: string | null;
  /** True when every CA in the pinned root is past its validity window. */
  rootStale: boolean;
}

const SLSA_V1 = "https://slsa.dev/provenance/v1";

let defaultTrust: ProvenanceTrustMaterial | null | undefined;

/** Load the trust material bundled with the package (packages/core/trust/). */
export function loadDefaultTrustMaterial(): ProvenanceTrustMaterial | null {
  if (defaultTrust !== undefined) return defaultTrust;
  try {
    // ../trust resolves to packages/core/trust from BOTH src/ (tsx) and dist/ (built).
    const trustedRootJson = JSON.parse(readFileSync(new URL("../trust/trusted-root.json", import.meta.url), "utf8")) as unknown;
    const keysDoc = JSON.parse(readFileSync(new URL("../trust/npm-attestation-keys.json", import.meta.url), "utf8")) as { keys?: NpmAttestationKey[] };
    defaultTrust = { trustedRootJson, npmKeys: keysDoc.keys ?? [] };
  } catch {
    defaultTrust = null;
  }
  return defaultTrust;
}

/** Load operator-supplied trust material from explicit paths (env override). */
export function loadTrustMaterial(opts: { trustedRootPath: string; npmKeysPath?: string }): ProvenanceTrustMaterial {
  const trustedRootJson = JSON.parse(readFileSync(opts.trustedRootPath, "utf8")) as unknown;
  const npmKeys = opts.npmKeysPath
    ? ((JSON.parse(readFileSync(opts.npmKeysPath, "utf8")) as { keys?: NpmAttestationKey[] }).keys ?? [])
    : [];
  return { trustedRootJson, npmKeys };
}

interface AttestationEntry {
  predicateType?: string;
  bundle?: unknown;
}

/**
 * Offline-verify a package's attestation bundles against pinned trust material.
 * Pure and total: never throws, same inputs ⇒ same result.
 *
 * Status semantics (ADR-0022):
 * - "absent": the packument claimed no attestations.
 * - "unknown": claimed, but an input is missing (bundles unfetchable, empty
 *   list, or no trust material). Fail-open — outages never break installs.
 * - "invalid": bundles are PRESENT but any of them fails crypto, chain, tlog,
 *   parsing, or subject binding. Fail-closed — a crafted bundle must not
 *   degrade to "unknown" and slip past an identity gate.
 * - "verified": every present attestation verifies AND every subject digest
 *   binds to `integrity` (the SRI of the ACTUAL served bytes).
 */
export function verifyProvenance(input: {
  name: string;
  version: string;
  integrity: string;
  claimed: boolean;
  attestations: unknown | null;
  trust: ProvenanceTrustMaterial | null;
  /** Injectable clock (ISO) for root-staleness; an explicit input for determinism. */
  now?: string;
}): ProvenanceVerification {
  if (!input.claimed) return { status: "absent", identity: null, reason: null, rootStale: false };
  if (!input.trust) return { status: "unknown", identity: null, reason: "no Sigstore trust material configured", rootStale: false };
  const rootStale = trustRootStale(input.trust, input.now);
  if (!input.attestations) {
    return { status: "unknown", identity: null, reason: "attestation bundle could not be fetched", rootStale };
  }
  const list = (input.attestations as { attestations?: AttestationEntry[] }).attestations;
  if (!Array.isArray(list) || list.length === 0) {
    return { status: "unknown", identity: null, reason: "attestation endpoint returned no bundles", rootStale };
  }
  try {
    const verifier = buildVerifier(input.trust);
    let identity: ProvenanceIdentity | null = null;
    for (const a of list) {
      const bundle = bundleFromJSON(a.bundle);
      const result = verifier.verify(toSignedEntity(bundle));
      const stmt = statementOf(bundle);
      const bindErr = checkSubjectBinding(stmt, input.integrity);
      if (bindErr) return { status: "invalid", identity: null, reason: bindErr, rootStale };
      if (a.predicateType === SLSA_V1) identity = extractIdentity(result, stmt);
    }
    return { status: "verified", identity, reason: null, rootStale };
  } catch (e) {
    return { status: "invalid", identity: null, reason: (e as Error)?.message ?? "attestation verification failed", rootStale };
  }
}

function buildVerifier(trust: ProvenanceTrustMaterial): Verifier {
  const root = TrustedRoot.fromJSON(trust.trustedRootJson);
  // keyFinder resolves the npm publish attestation's key hint from the pinned
  // registry.npmjs.org/keys.json target. Probed 2026-07-07: one Verifier with
  // {ctlog 1, tlog 1, tsa 0} verifies BOTH the Fulcio-cert SLSA bundle and the
  // public-key npm publish bundle.
  const keyFinder = (hint: string) => {
    const k = trust.npmKeys.find((x) => x.keyId === hint);
    if (!k) throw new Error(`key not found: ${hint}`);
    const body = (k.publicKey.rawBytes.match(/.{1,64}/g) ?? []).join("\n");
    const start = k.publicKey.validFor?.start ? new Date(k.publicKey.validFor.start) : new Date(0);
    const end = k.publicKey.validFor?.end ? new Date(k.publicKey.validFor.end) : null;
    return {
      publicKey: createPublicKey(`-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`),
      validFor: (d: Date) => d >= start && (end === null || d <= end),
    };
  };
  return new Verifier(toTrustMaterial(root, keyFinder), { ctlogThreshold: 1, tlogThreshold: 1, tsaThreshold: 0 });
}

interface InTotoStatement {
  subject?: { name?: string; digest?: Record<string, string> }[];
  predicate?: {
    buildDefinition?: {
      externalParameters?: { workflow?: { ref?: unknown; repository?: unknown; path?: unknown } };
      resolvedDependencies?: { digest?: Record<string, string> }[];
    };
    runDetails?: { builder?: { id?: unknown } };
  };
}

function statementOf(bundle: ReturnType<typeof bundleFromJSON>): InTotoStatement {
  const env = (bundle as { content?: { dsseEnvelope?: { payload?: Uint8Array } } }).content?.dsseEnvelope;
  if (!env?.payload) throw new Error("attestation bundle has no DSSE envelope");
  return JSON.parse(Buffer.from(env.payload).toString("utf8")) as InTotoStatement;
}

/**
 * The in-toto subject digest (hex sha512) must match the tarball SRI. This is
 * the binding that makes verification mean something: a cryptographically valid
 * attestation for DIFFERENT bytes is invalid here. (Name/purl matching is
 * deliberately not attempted — the digest is the strong bind; purl encodings
 * vary across registries.)
 */
function checkSubjectBinding(stmt: InTotoStatement, integrity: string): string | null {
  const subjects = stmt.subject;
  if (!Array.isArray(subjects) || subjects.length === 0) return "attestation statement has no subject";
  for (const s of subjects) {
    const hex = s?.digest?.["sha512"];
    if (typeof hex !== "string" || hex.length === 0) return "attestation subject has no sha512 digest";
    const sri = "sha512-" + Buffer.from(hex, "hex").toString("base64");
    if (sri !== integrity) return "attestation subject digest does not match tarball integrity";
  }
  return null;
}

function extractIdentity(result: unknown, stmt: InTotoStatement): ProvenanceIdentity {
  const id = (result as { identity?: { subjectAlternativeName?: string; extensions?: { issuer?: string } } }).identity;
  const pred = stmt.predicate ?? {};
  const wf = pred.buildDefinition?.externalParameters?.workflow ?? {};
  const commit = pred.buildDefinition?.resolvedDependencies?.find((d) => typeof d?.digest?.["gitCommit"] === "string")?.digest?.["gitCommit"];
  return {
    workflow: id?.subjectAlternativeName ?? null,
    issuer: id?.extensions?.issuer ?? null,
    sourceRepository: typeof wf.repository === "string" ? wf.repository : null,
    ref: typeof wf.ref === "string" ? wf.ref : null,
    builder: typeof pred.runDetails?.builder?.id === "string" ? pred.runDetails.builder.id : null,
    commit: typeof commit === "string" ? commit : null,
  };
}

/** Stale when EVERY CA in the pinned root has a validity window that has ended. */
function trustRootStale(trust: ProvenanceTrustMaterial, nowIso?: string): boolean {
  try {
    const root = trust.trustedRootJson as { certificateAuthorities?: { validFor?: { end?: string } }[] };
    const cas = root.certificateAuthorities ?? [];
    if (cas.length === 0) return false;
    const now = nowIso ? new Date(nowIso) : new Date();
    return cas.every((ca) => typeof ca.validFor?.end === "string" && new Date(ca.validFor.end) < now);
  } catch {
    return false;
  }
}
```

- [ ] **Step 5: Export from `packages/core/src/index.ts`** — add alongside the existing `verifyRegistrySignature` export block:

```ts
export {
  verifyProvenance,
  loadDefaultTrustMaterial,
  loadTrustMaterial,
  type ProvenanceTrustMaterial,
  type ProvenanceVerification,
  type NpmAttestationKey,
} from "./provenance.js";
```

Also ensure `ProvenanceStatus` and `ProvenanceIdentity` are exported from wherever `types.js` types are re-exported (check the existing `export type` list in index.ts and add both).

- [ ] **Step 6: Run the test — expect compile errors elsewhere first**

`types.ts`'s `provenance` widening breaks `audit.ts:103` (`"present"`), `score.ts:49`, and `rules/provenance.ts`. Make the *minimal* interim edits so this task compiles (Task 3/4 finish them properly):
- `audit.ts:103`: `provenance: input.hasProvenance ? "unknown" : "absent",` (interim; Task 3 replaces)
- `score.ts:49`: change `!== "present"` to `!== "verified"` (this is already the Task 4 semantic — fine to land now)
- `rules/provenance.ts:23`: change `if (provenance === "absent")` — keep as-is (still valid).

```bash
npx tsx --test packages/core/test/provenance.test.ts
```

Expected: PASS (all provenance.test.ts tests).

- [ ] **Step 7: Run the full core suite to see interim carnage — record, don't fix**

```bash
npm run build && npm test 2>&1 | tail -20
```

Some tests referencing `"present"` will fail (provenance-rule, score requireProvenance, proxy signature-verify). These are fixed in Tasks 3–5. If any *other* suite fails, stop and investigate before proceeding.

- [ ] **Step 8: Commit**

```bash
git add packages/core/src packages/core/test/provenance.test.ts
git commit -m "feat(phase9): verifyProvenance — offline Sigstore bundle verification + identity extraction (ADR-0022)"
```

---

### Task 3: Audit integration — status on meta, integrity tamper check, rule + staleness findings

**Files:**
- Modify: `packages/core/src/audit.ts`
- Modify: `packages/core/src/rules/provenance.ts`
- Test: `packages/core/test/provenance-rule.test.ts` (update), `packages/core/test/audit.test.ts` (extend)

**Interfaces:**
- Consumes: `verifyProvenance`, `loadDefaultTrustMaterial`, `ProvenanceTrustMaterial` (Task 2).
- Produces: `AuditTarballInput` gains `attestations?: unknown | null`, `trustMaterial?: ProvenanceTrustMaterial | null` (undefined ⇒ bundled default; null ⇒ none), `verifyAt?: string`. `runAudit` sets `meta.provenance`/`meta.provenanceIdentity`, and appends findings `integrity-mismatch` (critical) and `trust-root-stale` (info) when warranted. Tasks 5–6 call `runAudit` with these fields.

- [ ] **Step 1: Update `provenance-rule.test.ts` for the new statuses**

The file's `input(sig, prov)` helper builds meta with the old union. Update the provenance argument type to `ProvenanceStatus`, replace `"present"` with `"verified"` in existing cases, and add:

```ts
  test("invalid provenance is critical", () => {
    const f = provenanceRule.run(input("verified", "invalid"));
    assert.equal(f.find((x) => x.message.includes("provenance"))!.severity, "critical");
  });
  test("unknown provenance is low", () => {
    const f = provenanceRule.run(input("verified", "unknown"));
    assert.equal(f.find((x) => x.message.includes("provenance"))!.severity, "low");
  });
  test("verified provenance emits nothing", () => {
    assert.deepEqual(provenanceRule.run(input("verified", "verified")), []);
  });
```

(Keep the existing `absent → info` case.)

- [ ] **Step 2: Extend `audit.test.ts` with tamper + provenance-input tests**

Add (adapting to the file's existing fixture helpers — it already builds real tarballs via `helpers.ts`):

```ts
describe("phase 9: integrity recompute + provenance wiring", () => {
  test("claimed integrity mismatch yields a critical integrity-mismatch finding and actual integrity on meta", async () => {
    const tgz = tarball("leftpad-lite", "1.0.0");
    const audit = await runAudit({
      meta: { name: "leftpad-lite", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity: "sha512-BOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUS==" },
      tarball: tgz, signatures: null, hasProvenance: false, attestations: null, trustMaterial: null,
    });
    const f = audit.findings.find((x) => x.ruleId === "integrity-mismatch");
    assert.ok(f, "integrity-mismatch finding expected");
    assert.equal(f!.severity, "critical");
    assert.notEqual(audit.meta.integrity, "sha512-BOGUS…");
    assert.match(audit.meta.integrity!, /^sha512-/);
  });

  test("matching claimed integrity yields no tamper finding", async () => {
    const tgz = tarball("leftpad-lite", "1.0.0");
    const { integrityOf } = await import("../src/extract.js");
    const audit = await runAudit({
      meta: { name: "leftpad-lite", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity: integrityOf(tgz) },
      tarball: tgz, signatures: null, hasProvenance: false, attestations: null, trustMaterial: null,
    });
    assert.equal(audit.findings.find((x) => x.ruleId === "integrity-mismatch"), undefined);
  });

  test("provenance status flows to meta: claimed + no bundles + no trust = unknown", async () => {
    const audit = await runAudit({
      meta: { name: "x", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false },
      tarball: tarball("leftpad-lite", "1.0.0"), signatures: null,
      hasProvenance: true, attestations: null, trustMaterial: null,
    });
    assert.equal(audit.meta.provenance, "unknown");
  });
});
```

(Adjust `meta` literals to match `AuditTarballInput["meta"]`'s Omit shape; run and fix type errors.)

- [ ] **Step 3: Run to verify failures**

```bash
npx tsx --test packages/core/test/provenance-rule.test.ts packages/core/test/audit.test.ts
```

Expected: FAIL (rule doesn't handle invalid/unknown; runAudit lacks the new inputs).

- [ ] **Step 4: Implement `audit.ts` changes**

Extend `AuditTarballInput`:

```ts
  /** Fetched attestation-endpoint response (acquisition path), or null when unfetchable. */
  attestations?: unknown | null;
  /** Pinned Sigstore trust material. undefined ⇒ bundled default; null ⇒ none (provenance stays unknown when claimed). */
  trustMaterial?: ProvenanceTrustMaterial | null;
  /** Injectable clock (ISO) for trust-root staleness; defaults to now. */
  verifyAt?: string;
```

Rework the body of `runAudit` (replacing lines 89–107):

```ts
  const extracted = await extractTarball(input.tarball, baseline);
  // Always recompute from the served bytes (ADR-0022): the claimed integrity is
  // an assertion to CHECK, not a value to trust. Mismatch ⇒ critical finding.
  const actualIntegrity = integrityOf(input.tarball);
  const claimedIntegrity = input.meta.integrity ?? null;
  const integrityMismatch = claimedIntegrity !== null && claimedIntegrity !== actualIntegrity;
  // The registry signature is over the CLAIMED integrity (npm's statement about
  // its own dist entry); byte-tampering is carried by integrity-mismatch instead.
  const signature = verifyRegistrySignature(
    { name: input.meta.name, version: input.meta.version, integrity: claimedIntegrity ?? actualIntegrity },
    input.signatures ?? null,
    input.signingKeys ?? NPM_SIGNING_KEYS,
  );
  const prov = verifyProvenance({
    name: input.meta.name,
    version: input.meta.version,
    integrity: actualIntegrity,
    claimed: input.hasProvenance ?? false,
    attestations: input.attestations ?? null,
    trust: input.trustMaterial === undefined ? loadDefaultTrustMaterial() : input.trustMaterial,
    now: input.verifyAt,
  });
  const meta: PackageMeta = {
    ...input.meta,
    integrity: actualIntegrity,
    unpackedSize: extracted.unpackedSize,
    fileCount: extracted.fileCount,
    hasInstallScripts: detectInstallScripts(extracted.files) || input.meta.hasInstallScripts,
    signature,
    provenance: prov.status,
    provenanceIdentity: prov.identity,
  };

  const audit = buildAudit(meta, extracted.files, { mode, durationMs: Date.now() - started, baselineCapabilities });
  if (integrityMismatch) {
    audit.findings.push({
      ruleId: "integrity-mismatch", category: "provenance", severity: "critical",
      message: `served tarball bytes do not match the claimed dist.integrity (${claimedIntegrity!.slice(0, 24)}…) — possible mirror tampering`,
      onChangedFile: false, evidence: [],
    });
  }
  if (prov.rootStale) {
    audit.findings.push({
      ruleId: "trust-root-stale", category: "provenance", severity: "info",
      message: "pinned Sigstore trust root is past its validity window — update packages/core/trust/trusted-root.json",
      onChangedFile: false, evidence: [],
    });
  }
  return audit;
```

Add the imports: `verifyProvenance`, `loadDefaultTrustMaterial`, `type ProvenanceTrustMaterial` from `./provenance.js`.

- [ ] **Step 5: Implement the rule update** in `rules/provenance.ts` — replace the provenance block:

```ts
    if (provenance === "invalid") add("critical", "provenance attestation failed verification — possible forgery or tampering");
    else if (provenance === "unknown") add("low", "provenance attested but could not be verified (bundle unavailable or no trust material)");
    else if (provenance === "absent") add("info", "no build provenance attestation");
    // "verified" emits nothing — identity is surfaced on meta, not as a finding.
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
npx tsx --test packages/core/test/provenance-rule.test.ts packages/core/test/audit.test.ts packages/core/test/provenance.test.ts
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/core/src packages/core/test
git commit -m "feat(phase9): runAudit verifies provenance + recomputes served-bytes integrity; rule maps new statuses"
```

---

### Task 4: Policy `provenanceIdentities` + score-time identity gate

**Files:**
- Modify: `packages/core/src/policy.ts`
- Modify: `packages/core/src/score.ts`
- Test: `packages/core/test/policy.test.ts`, `packages/core/test/score.test.ts`

**Interfaces:**
- Consumes: `ProvenanceStatus`, `ProvenanceIdentity` on meta (Tasks 2–3).
- Produces: `EnterprisePolicy.provenanceIdentities?: ProvenanceIdentityRequirement[]` where `ProvenanceIdentityRequirement = { pattern: string; repository?: string; issuer?: string; workflowRef?: string; builder?: string }`. `score()` blocks + appends a weight-0 critical `provenance-identity` finding on violation. `requireProvenance` now demands `"verified"` (landed in Task 2 Step 6).

- [ ] **Step 1: Write failing tests**

In `policy.test.ts` add:

```ts
describe("provenanceIdentities parsing", () => {
  test("valid entries parse through", () => {
    const p = parsePolicy(Buffer.from(JSON.stringify({
      ...JSON.parse(JSON.stringify(DEFAULT_POLICY)),
      provenanceIdentities: [{ pattern: "@acme/*", repository: "https://github.com/acme/*", issuer: "https://token.actions.githubusercontent.com" }],
    })));
    assert.equal(p.provenanceIdentities?.[0]?.pattern, "@acme/*");
  });
  test("rejects entries without a pattern", () => {
    assert.throws(() => parsePolicy(Buffer.from(JSON.stringify({
      ...JSON.parse(JSON.stringify(DEFAULT_POLICY)),
      provenanceIdentities: [{ repository: "x" }],
    }))), /provenanceIdentities/);
  });
  test("rejects non-string constraint fields", () => {
    assert.throws(() => parsePolicy(Buffer.from(JSON.stringify({
      ...JSON.parse(JSON.stringify(DEFAULT_POLICY)),
      provenanceIdentities: [{ pattern: "a", repository: 42 }],
    }))), /provenanceIdentities/);
  });
});
```

In `score.test.ts` (using its existing `auditWith(signature, provenance)` helper — extend the helper so a `provenanceIdentity` can be injected, e.g. `auditWith(sig, prov, identity?)` setting `meta.provenanceIdentity`):

```ts
describe("provenance identity gate", () => {
  const ID = {
    workflow: "https://github.com/acme/pkg/.github/workflows/release.yml@refs/heads/main",
    issuer: "https://token.actions.githubusercontent.com",
    sourceRepository: "https://github.com/acme/pkg", ref: "refs/heads/main",
    builder: "https://github.com/actions/runner/github-hosted", commit: "abc123",
  };
  const policyWith = (entry: object) => ({ ...DEFAULT_POLICY, provenanceIdentities: [entry] } as EnterprisePolicy);

  test("verified + matching identity passes", () => {
    const r = score(auditWith("verified", "verified", ID), policyWith({ pattern: "pkg-a", repository: "https://github.com/acme/*" }));
    assert.equal(r.verdict, "allow");
  });
  test("verified + wrong repository blocks with a critical zero-weight finding", () => {
    const r = score(auditWith("verified", "verified", ID), policyWith({ pattern: "pkg-a", repository: "https://github.com/evil/*" }));
    assert.equal(r.verdict, "block");
    const f = r.findings.find((x) => x.ruleId === "provenance-identity");
    assert.ok(f); assert.equal(f!.severity, "critical"); assert.equal(f!.weight, 0);
  });
  test("absent provenance in an identity-constrained namespace blocks", () => {
    assert.equal(score(auditWith("verified", "absent"), policyWith({ pattern: "pkg-a", repository: "https://github.com/acme/*" })).verdict, "block");
  });
  test("unknown provenance does NOT trip the identity gate (outage tolerance)", () => {
    assert.equal(score(auditWith("verified", "unknown"), policyWith({ pattern: "pkg-a", repository: "https://github.com/acme/*" })).verdict, "allow");
  });
  test("non-matching pattern is unaffected", () => {
    assert.equal(score(auditWith("verified", "absent"), policyWith({ pattern: "other-pkg", repository: "x" })).verdict, "allow");
  });
  test("requireProvenance demands verified: unknown trips it", () => {
    const p = { ...DEFAULT_POLICY, requireProvenance: ["pkg-a"] } as EnterprisePolicy;
    assert.equal(score(auditWith("verified", "unknown"), p).verdict, "block");
    assert.equal(score(auditWith("verified", "verified"), p).verdict, "allow");
  });
});
```

(`"pkg-a"` = whatever package name `auditWith` puts on meta — check the helper and use its actual name. The existing `requireProvenance` tests at score.test.ts:125–131 must be updated: `"present"` no longer exists; `verified` satisfies, `unknown`/`absent` do not.)

- [ ] **Step 2: Run to verify failure**

```bash
npx tsx --test packages/core/test/policy.test.ts packages/core/test/score.test.ts
```

Expected: FAIL (`provenanceIdentities` unknown; gate missing).

- [ ] **Step 3: Implement policy.ts**

Add after `requireProvenance` in the interface:

```ts
  /** Per-namespace provenance identity constraints (ADR-0022): matching packages
   *  must have VERIFIED provenance whose identity satisfies every given field.
   *  `repository`/`workflowRef`/`builder` are anchored globs (matchPackage);
   *  `issuer` is exact. `workflowRef` matches the full signing identity (cert SAN). */
  provenanceIdentities?: ProvenanceIdentityRequirement[];
```

```ts
export interface ProvenanceIdentityRequirement {
  pattern: string;
  repository?: string;
  issuer?: string;
  workflowRef?: string;
  builder?: string;
}
```

In `parsePolicy`, after the requireSignature/requireProvenance block:

```ts
  // Validate provenanceIdentities if present.
  const pi = (p as { provenanceIdentities?: unknown }).provenanceIdentities;
  if (pi !== undefined) {
    if (!Array.isArray(pi)) throw new Error("invalid policy: provenanceIdentities must be an array");
    for (let i = 0; i < pi.length; i++) {
      const e = pi[i] as Record<string, unknown>;
      if (!e || typeof e !== "object" || typeof e.pattern !== "string") {
        throw new Error(`invalid policy: provenanceIdentities[${i}] must have a string "pattern"`);
      }
      for (const f of ["repository", "issuer", "workflowRef", "builder"] as const) {
        if (e[f] !== undefined && typeof e[f] !== "string") {
          throw new Error(`invalid policy: provenanceIdentities[${i}].${f} must be a string`);
        }
      }
    }
  }
```

And in the return object: `...(pi !== undefined ? { provenanceIdentities: pi as ProvenanceIdentityRequirement[] } : {}),`

- [ ] **Step 4: Implement the gate in score.ts**

After the `reqProv` line (which already reads `!== "verified"`), add:

```ts
  // Identity gate (ADR-0022): every matching entry must be satisfied (fail-closed
  // AND). "unknown" is exempt — an outage must not block ordinary installs; the
  // requireProvenance gate is the opt-in fail-closed lever for that case.
  let idViolation: string | null = null;
  const idEntries = (policy.provenanceIdentities ?? []).filter((e) => matchPackage(e.pattern, audit.meta.name));
  if (idEntries.length > 0 && audit.meta.provenance !== "unknown") {
    if (audit.meta.provenance !== "verified") {
      idViolation = `provenance is ${audit.meta.provenance}, policy requires verified provenance`;
    } else {
      const id = audit.meta.provenanceIdentity ?? null;
      for (const e of idEntries) {
        const v = identityViolation(e, id);
        if (v) { idViolation = v; break; }
      }
    }
  }
  if (idViolation) {
    scored.push({
      ruleId: "provenance-identity", category: "provenance", severity: "critical",
      message: `provenance identity policy violation — ${idViolation}`,
      onChangedFile: false, evidence: [], weight: 0, waived: false,
    });
  }
```

Note ordering: this push must come **after** the `hardBlock` computation (move the push below the `hardBlock` line, or compute `hardBlock` before pushing) — the synthesized weight-0 finding blocks via the flag, not via hardBlock. The verdict line becomes:

```ts
  if (denied || hardBlock || reqSig || reqProv || idViolation !== null) verdict = "block";
```

Helper at module level (below `clamp`):

```ts
function identityViolation(
  e: import("./policy.js").ProvenanceIdentityRequirement,
  id: import("./types.js").ProvenanceIdentity | null,
): string | null {
  const checks: [string, string | undefined, string | null, boolean][] = [
    ["repository", e.repository, id?.sourceRepository ?? null, true],
    ["issuer", e.issuer, id?.issuer ?? null, false],
    ["workflowRef", e.workflowRef, id?.workflow ?? null, true],
    ["builder", e.builder, id?.builder ?? null, true],
  ];
  for (const [label, want, actual, glob] of checks) {
    if (want === undefined) continue;
    const ok = actual !== null && (glob ? matchPackage(want, actual) : want === actual);
    if (!ok) return `${label} is ${actual ?? "unknown"}, policy requires ${want}`;
  }
  return null;
}
```

(Use proper top-of-file type imports rather than inline `import()` if the file style prefers — it does: add `type ProvenanceIdentityRequirement` to the policy.js import and `ProvenanceIdentity` to the types.js import.)

- [ ] **Step 5: Run tests**

```bash
npx tsx --test packages/core/test/policy.test.ts packages/core/test/score.test.ts
```

Expected: PASS (including the pinned determinism test — the default policy has no identity entries).

- [ ] **Step 6: Commit**

```bash
git add packages/core/src packages/core/test
git commit -m "feat(phase9): provenanceIdentities policy gate + requireProvenance upgraded to verified (ADR-0022)"
```

---

### Task 5: Upstream `getAttestations` + fixture pipeline (vendored real package, new fixture classes)

**Files:**
- Modify: `packages/proxy/src/upstream.ts`
- Modify: `scripts/make-fixtures.ts`
- Modify: `fixtures/index.json`
- Create: `fixtures/vendored/vendored.json`
- Create: `fixtures/benign/prov-unknown/1.0.0/package/package.json` + `index.js`
- Create: `fixtures/benign/prov-mismatch/1.0.0/package/package.json` + `index.js`
- Modify: `packages/proxy/test/signature-verify.test.ts` (Phase 8 expectation updates)

**Interfaces:**
- Consumes: `fixtures/attestations/sigstore-3.0.0.attestations.json`, `fixtures/vendored/sigstore-3.0.0.tgz` (Task 1).
- Produces: `Upstream.getAttestations(pkg: string, version: string): Promise<unknown | null>` on the interface and both implementations; `registry.json` version entries gain `attestationsFile?: string | null`; fixture packages `sigstore@3.0.0` (verified path), `prov-unknown@1.0.0` (claimed, unfetchable), `prov-mismatch@1.0.0` (real bundle over wrong bytes ⇒ invalid). Task 6 consumes all three.

- [ ] **Step 1: Add `getAttestations` to the `Upstream` interface** (upstream.ts:43):

```ts
export interface Upstream {
  readonly name: string;
  getPackument(pkg: string): Promise<UpstreamPackument>;
  getTarball(pkg: string, version: string): Promise<Buffer>;
  /** Fetch the attestation-endpoint response for a version; null when unavailable.
   *  Acquisition-path network (invariant #3 keeps the AUDIT offline, not this). */
  getAttestations(pkg: string, version: string): Promise<unknown | null>;
}
```

`NpmUpstream`:

```ts
  async getAttestations(pkg: string, version: string): Promise<unknown | null> {
    try {
      const name = encodeURIComponent(pkg).replace("%40", "@");
      const res = await fetch(`${this.registry}/-/npm/v1/attestations/${name}@${version}`, {
        headers: { accept: "application/json" },
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null; // fail-open to "unknown" — an outage must not break installs
    }
  }
```

`LocalFixtureUpstream` (RegistryDoc version type gains `attestationsFile?: string | null`):

```ts
  async getAttestations(pkg: string, version: string): Promise<unknown | null> {
    const m = this.doc.packages[pkg]?.versions[version];
    if (!m?.attestationsFile) return null;
    return JSON.parse(readFileSync(join(this.fixturesDir, "attestations", m.attestationsFile), "utf8"));
  }
```

- [ ] **Step 2: Update `fixtures/index.json`**

The `provenance` field becomes `false | "claimed" | { "attestationsFile": string }`:
- Flip every existing `"provenance": true` to `"provenance": false` (those fixtures have no real bundles — under Phase 9 semantics a bare claim would read `unknown`, which is not what those fixtures test).
- Add two new packages:

```json
    "prov-unknown": {
      "class": "benign",
      "versions": { "1.0.0": { "signature": "valid", "provenance": "claimed" } }
    },
    "prov-mismatch": {
      "class": "benign",
      "versions": { "1.0.0": { "signature": "valid", "provenance": { "attestationsFile": "sigstore-3.0.0.attestations.json" } } }
    }
```

- [ ] **Step 3: Create the two new fixture package dirs**

`fixtures/benign/prov-unknown/1.0.0/package/package.json`:

```json
{ "name": "prov-unknown", "version": "1.0.0", "description": "benign fixture: provenance claimed but bundle unfetchable", "license": "MIT", "main": "index.js" }
```

`fixtures/benign/prov-unknown/1.0.0/package/index.js`:

```js
module.exports = { ok: true };
```

`prov-mismatch` identical but name `prov-mismatch` and description `"benign fixture: real attestation bundle over the wrong tarball bytes"`.

- [ ] **Step 4: Create `fixtures/vendored/vendored.json`**

```json
[
  {
    "name": "sigstore",
    "version": "3.0.0",
    "tarballFile": "sigstore-3.0.0.tgz",
    "attestationsFile": "sigstore-3.0.0.attestations.json",
    "license": "Apache-2.0",
    "_comment": "Real, benign npm package vendored for the end-to-end verified-provenance path. Scored as data like every fixture; never executed."
  }
]
```

- [ ] **Step 5: Update `scripts/make-fixtures.ts`**

Type changes: `IndexFile` versions value `provenance` becomes `false | "claimed" | { attestationsFile: string }`; `RegistryVersion` gains `attestationsFile?: string`.

In the per-version loop, replace `attestations: vmeta.provenance,` with:

```ts
        attestations: vmeta.provenance !== false,
        attestationsFile: typeof vmeta.provenance === "object" ? vmeta.provenance.attestationsFile : undefined,
```

After the synthetic-package loop (before `writeFileSync(...registry.json...)`), add the vendored pass:

```ts
  // Vendored real packages: pre-built tarballs with real attestation bundles,
  // for the end-to-end verified-provenance path. Bytes are copied verbatim so
  // integrity is stable; unpackedSize/fileCount are recomputed at audit time
  // from extraction, so 0 here is never observed by the engine.
  const VENDORED = join(FIX, "vendored");
  const vendoredManifest = join(VENDORED, "vendored.json");
  if (existsSync(vendoredManifest)) {
    const vendored = JSON.parse(readFileSync(vendoredManifest, "utf8")) as {
      name: string; version: string; tarballFile: string; attestationsFile: string; license?: string;
    }[];
    for (const v of vendored) {
      const buf = readFileSync(join(VENDORED, v.tarballFile));
      writeFileSync(join(OUT_DIR, v.tarballFile), buf);
      const integrity = `sha512-${createHash("sha512").update(buf).digest("base64")}`;
      registry.packages[v.name] = {
        name: v.name, author: null,
        versions: {
          [v.version]: {
            version: v.version, author: null, license: v.license ?? null, hasInstallScripts: false,
            dist: { tarballFile: v.tarballFile, integrity, unpackedSize: 0, fileCount: 0 },
            signatures: null, attestations: true, attestationsFile: v.attestationsFile,
          },
        },
      };
      console.log(`vendored ${v.name}@${v.version} -> ${v.tarballFile} (${buf.length} B)`);
    }
  }
```

- [ ] **Step 6: Regenerate fixtures and verify registry.json shape**

```bash
npm run fixtures
node -e "
const r=require('./fixtures/registry.json');
const s=r.packages['sigstore'].versions['3.0.0'];
if(!s||!s.attestationsFile) throw new Error('vendored entry missing');
if(s.dist.integrity!=='sha512-PHMifhh3EN4loMcHCz6l3v/luzgT3za+9f8subGgeMNjbJjzH4Ij/YoX3Gvu+kaouJRIlVdTHHCREADYf+ZteA==') throw new Error('vendored integrity drift');
if(r.packages['prov-unknown'].versions['1.0.0'].attestations!==true) throw new Error('prov-unknown claim missing');
console.log('registry.json OK');"
```

Expected: `registry.json OK`

- [ ] **Step 7: Update Phase 8 expectations in `signature-verify.test.ts`**

- Line 46–47: test name → `"a validly-signed fixture verifies with provenance absent"`, assertion → `"verified/absent"` (leftpad-lite no longer claims provenance).
- Line ~60 (`prov-absent` case): unchanged (still `absent`).
- Line ~89 (`"a verified/present package..."`): rename to `"a verified-signature package not matching any requirement is allowed"`; behavior unchanged.
- The `requireProvenance: ["prov-absent"]` gate test still passes (`absent !== "verified"`).

- [ ] **Step 8: Build + run the proxy signature suite and full core suite**

```bash
npm run build
npx tsx --test packages/proxy/test/signature-verify.test.ts
npx tsx --test packages/core/test/
```

Expected: PASS. (LocalFixtureUpstream now implements getAttestations; any other Upstream stub in tests will fail compilation — add `getAttestations: async () => null` to any inline stub upstreams the compiler flags.)

- [ ] **Step 9: Commit**

```bash
git add packages/proxy/src/upstream.ts scripts/make-fixtures.ts fixtures/index.json fixtures/vendored/vendored.json fixtures/benign/prov-unknown fixtures/benign/prov-mismatch packages/proxy/test/signature-verify.test.ts
git commit -m "feat(phase9): Upstream.getAttestations + vendored real-provenance fixture pipeline"
```

---

### Task 6: Server acquisition changes, trust wiring, header + provenance e2e suite

**Files:**
- Modify: `packages/proxy/src/server.ts` (auditVersion, gateAndSend, ServerOptions, publish path)
- Modify: `packages/proxy/src/index.ts` (env override wiring)
- Test: `packages/proxy/test/provenance-verify.test.ts` (new)

**Interfaces:**
- Consumes: `getAttestations` (Task 5), `runAudit` new inputs (Task 3), `loadTrustMaterial`/`loadDefaultTrustMaterial` (Task 2), fixtures (Task 5).
- Produces: `ServerOptions.trustMaterial?: ProvenanceTrustMaterial | null` (undefined ⇒ bundled default via runAudit; null ⇒ none); response header `x-sentinel-provenance`; env vars `SENTINEL_TRUSTED_ROOT` / `SENTINEL_NPM_ATTESTATION_KEYS`.

- [ ] **Step 1: Write the failing e2e test** (`packages/proxy/test/provenance-verify.test.ts`)

```ts
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type EnterprisePolicy, type AuditReport } from "@sentinel/core";
import { createServer, type ServerOptions } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

function boot(overrides: Partial<ServerOptions> = {}): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), ...overrides,
  });
  return new Promise((res) => {
    const server = app.listen(0, () => res({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }));
  });
}

async function report(base: string, pkg: string, version: string): Promise<AuditReport> {
  const r = await fetch(`${base}/-/audit/${pkg}/${version}`);
  assert.equal(r.status, 200);
  return (await r.json()) as AuditReport;
}

describe("provenance deep-verify (e2e, offline, bundled trust root)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot()); });
  after(() => server?.close());

  test("vendored real package verifies end-to-end with identity", async () => {
    const r = await report(base, "sigstore", "3.0.0");
    assert.equal(r.meta.provenance, "verified");
    assert.equal(r.meta.provenanceIdentity?.sourceRepository, "https://github.com/sigstore/sigstore-js");
  });

  test("claimed-but-unfetchable is unknown", async () => {
    assert.equal((await report(base, "prov-unknown", "1.0.0")).meta.provenance, "unknown");
  });

  test("no claim is absent", async () => {
    assert.equal((await report(base, "leftpad-lite", "1.0.0")).meta.provenance, "absent");
  });

  test("real bundle over wrong bytes is invalid and hard-blocks", async () => {
    const r = await report(base, "prov-mismatch", "1.0.0");
    assert.equal(r.meta.provenance, "invalid");
    assert.equal(r.verdict, "block");
  });

  test("x-sentinel-provenance header is set on the tarball path", async () => {
    const res = await fetch(`${base}/sigstore/-/sigstore-3.0.0.tgz`);
    assert.equal(res.headers.get("x-sentinel-provenance"), "verified");
  });
});

describe("provenance identity gate (e2e, block mode)", () => {
  let server: Server; let base: string;
  before(async () => {
    ensureFixtures();
    const policy: EnterprisePolicy = {
      ...DEFAULT_POLICY,
      provenanceIdentities: [{ pattern: "sigstore", repository: "https://github.com/evil/*" }],
    };
    ({ server, base } = await boot({ enterprisePolicy: policy, policy: "block" }));
  });
  after(() => server?.close());

  test("verified-but-wrong-identity is blocked with the identity finding", async () => {
    const res = await fetch(`${base}/sigstore/-/sigstore-3.0.0.tgz`);
    assert.equal(res.status, 403);
    const body = (await res.json()) as { findings: { ruleId: string }[] };
    assert.ok(body.findings.some((f) => f.ruleId === "provenance-identity"));
  });
});

describe("identity gate positive + requireProvenance upgrade (e2e)", () => {
  let server: Server; let base: string;
  before(async () => {
    ensureFixtures();
    const policy: EnterprisePolicy = {
      ...DEFAULT_POLICY,
      provenanceIdentities: [{ pattern: "sigstore", repository: "https://github.com/sigstore/*" }],
      requireProvenance: ["prov-unknown"],
    };
    ({ server, base } = await boot({ enterprisePolicy: policy, policy: "block" }));
  });
  after(() => server?.close());

  test("matching identity is not blocked by the gate", async () => {
    const r = await report(base, "sigstore", "3.0.0");
    assert.equal(r.findings.find((f) => f.ruleId === "provenance-identity"), undefined);
    assert.notEqual(r.verdict, "block");
  });

  test("requireProvenance blocks an unknown-provenance package", async () => {
    const res = await fetch(`${base}/prov-unknown/-/prov-unknown-1.0.0.tgz`);
    assert.equal(res.status, 403);
  });
});

describe("served-bytes tamper detection (stub upstream)", () => {
  test("bytes differing from claimed integrity block critically", async () => {
    const inner = new LocalFixtureUpstream(FIXTURES);
    const tampering = {
      name: "tamper-stub",
      getPackument: (p: string) => inner.getPackument(p),
      getAttestations: async () => null,
      // Serve DIFFERENT bytes than the packument's claimed integrity.
      getTarball: async (p: string, v: string) => (await inner.getTarball("net-fetch-lite", "1.0.0")),
    };
    const { server, base } = await boot({ upstream: tampering, policy: "block" });
    try {
      const r = await fetch(`${base}/-/audit/leftpad-lite/1.0.0`);
      const rep = (await r.json()) as AuditReport;
      assert.equal(rep.verdict, "block");
      assert.ok(rep.findings.some((f) => f.ruleId === "integrity-mismatch"));
    } finally { server.close(); }
  });
});
```

- [ ] **Step 2: Run to verify failure**

```bash
npx tsx --test packages/proxy/test/provenance-verify.test.ts
```

Expected: FAIL (server doesn't fetch attestations; header missing; ServerOptions lacks trustMaterial).

- [ ] **Step 3: Implement server.ts changes**

`ServerOptions` gains:

```ts
  /** Pinned Sigstore trust material. undefined ⇒ bundled default; null ⇒ disabled. */
  trustMaterial?: ProvenanceTrustMaterial | null;
```

(import `type ProvenanceTrustMaterial` from `@sentinel/core`.)

In `auditVersion`, replace lines 102–124 with:

```ts
    const tarball = providedTarball ?? (await upstream.getTarball(pkg, version));
    // Cache and report by the ACTUAL bytes hash; the claimed integrity goes into
    // runAudit for the tamper check (ADR-0022).
    const actualIntegrity = integrityOf(tarball);

    const cached = store.get(actualIntegrity);
    if (cached) return { report: cached.report, tarball };

    const prev = previousVersion(Object.keys(pm.versions), version);
    const baselineTarball = prev ? await upstream.getTarball(pkg, prev) : undefined;
    const attestations = vmeta.hasProvenance ? await upstream.getAttestations(pkg, version) : null;

    const meta: Omit<PackageMeta, "unpackedSize" | "fileCount" | "signature" | "provenance"> = {
      name: pkg,
      version,
      author: vmeta.author,
      maintainers: vmeta.maintainers,
      license: vmeta.license,
      hasInstallScripts: vmeta.hasInstallScripts,
      integrity: vmeta.integrity ?? actualIntegrity,
    };

    const audit = await runAudit({
      meta, tarball, baselineTarball,
      signatures: vmeta.signatures, hasProvenance: vmeta.hasProvenance,
      attestations, signingKeys, trustMaterial: opts.trustMaterial,
    });
    const report = score(audit, enterprisePolicy, policyHash);
    store.put(report);
    return { report, tarball };
```

In `gateAndSend`, after the `x-sentinel-policy` header:

```ts
    res.setHeader("x-sentinel-provenance", report.meta.provenance);
```

In the publish path (line ~313), add `attestations: null,` to the `runAudit` call.

- [ ] **Step 4: Wire env overrides in proxy `index.ts`**

```ts
function resolveTrustMaterial(): ProvenanceTrustMaterial | null | undefined {
  const rootPath = process.env.SENTINEL_TRUSTED_ROOT;
  if (!rootPath) return undefined; // bundled default
  try {
    return loadTrustMaterial({ trustedRootPath: rootPath, npmKeysPath: process.env.SENTINEL_NPM_ATTESTATION_KEYS });
  } catch (err) {
    console.error(`FATAL: cannot load trust material from SENTINEL_TRUSTED_ROOT: ${(err as Error).message}`);
    process.exit(1);
  }
}
```

Import `loadTrustMaterial, type ProvenanceTrustMaterial` from `@sentinel/core`; in `main()` add `const trustMaterial = resolveTrustMaterial();` and pass `trustMaterial` in the `createServer({...})` options (undefined is fine — spread as-is). Add a boot log line: `` console.log(`  trust    : ${trustMaterial === undefined ? "bundled Sigstore root" : "operator-supplied root"}`); ``

- [ ] **Step 5: Run the new suite + neighbors**

```bash
npm run build
npx tsx --test packages/proxy/test/provenance-verify.test.ts packages/proxy/test/signature-verify.test.ts packages/proxy/test/proxy.test.ts
```

Expected: PASS. Note: `proxy.test.ts` may assert on cache keys or metas that assumed claimed integrity — if a failure appears, it will be an expectation drift from the recompute change; update the expectation (the actual bytes hash is now authoritative).

- [ ] **Step 6: Commit**

```bash
git add packages/proxy/src packages/proxy/test/provenance-verify.test.ts
git commit -m "feat(phase9): acquisition-path attestation fetch, served-bytes recompute, x-sentinel-provenance, trust env override"
```

---

### Task 7: audit-tree provenance rollup

**Files:**
- Modify: `packages/core/src/tree.ts`
- Modify: `packages/proxy/src/server.ts` (audit-tree row mapping, lines ~197–214)
- Modify: `packages/cli/src/format.ts` (`formatTree`)
- Test: `packages/core/test/tree.test.ts`, `packages/proxy/test/tree.test.ts` / `audit-tree-e2e.test.ts` (update row literals)

**Interfaces:**
- Consumes: `ProvenanceStatus` (Task 2).
- Produces: `TreePackageRow.provenance: ProvenanceStatus | null` (null on error rows); `TreeAggregate.provenance: { verified: number; invalid: number; absent: number; unknown: number }`.

- [ ] **Step 1: Write failing test additions** in `packages/core/test/tree.test.ts`:

```ts
  test("aggregate rolls up provenance counts; error rows are excluded", () => {
    const rows: TreePackageRow[] = [
      { name: "a", version: "1", status: "allow", score: 100, topFinding: null, error: null, provenance: "verified" },
      { name: "b", version: "1", status: "allow", score: 100, topFinding: null, error: null, provenance: "absent" },
      { name: "c", version: "1", status: "block", score: 0, topFinding: "x", error: null, provenance: "invalid" },
      { name: "d", version: "1", status: "error", score: null, topFinding: null, error: "boom", provenance: null },
    ];
    const agg = aggregateTree(rows, "block");
    assert.deepEqual(agg.provenance, { verified: 1, invalid: 1, absent: 1, unknown: 0 });
  });
```

Existing row literals in this file (and in proxy tree tests) need `provenance: <status or null>` added once the type changes.

- [ ] **Step 2: Run to verify failure** — `npx tsx --test packages/core/test/tree.test.ts` → FAIL.

- [ ] **Step 3: Implement**

`tree.ts`: add to `TreePackageRow`: `provenance: ProvenanceStatus | null;` (import the type). Add to `TreeAggregate`: `provenance: { verified: number; invalid: number; absent: number; unknown: number };`. In `aggregateTree`:

```ts
  const provenance = { verified: 0, invalid: 0, absent: 0, unknown: 0 };
  // inside the loop, after counts[r.status]++:
    if (r.provenance) provenance[r.provenance]++;
  // return { verdict, gated, counts, provenance };
```

`server.ts` audit-tree mapping: success rows add `provenance: report.meta.provenance,`; error rows add `provenance: null,`.

`format.ts` `formatTree`, after the counts line:

```ts
  const pv = a.provenance;
  L.push(c(C.gray, `  provenance: ${pv.verified} verified · ${pv.invalid} invalid · ${pv.absent} absent · ${pv.unknown} unknown`));
```

- [ ] **Step 4: Fix compile fallout** — add `provenance` to every `TreePackageRow` literal the compiler flags (core + proxy tests, and any CLI lockfile test rows).

- [ ] **Step 5: Run**

```bash
npm run build && npx tsx --test packages/core/test/tree.test.ts packages/proxy/test/tree.test.ts packages/proxy/test/audit-tree-e2e.test.ts
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/core packages/proxy packages/cli
git commit -m "feat(phase9): provenance status per audit-tree row + aggregate rollup"
```

---

### Task 8: CLI report + dashboard surfacing

**Files:**
- Modify: `packages/cli/src/format.ts` (`formatReport`, line 46)
- Modify: `packages/proxy/public/index.html` (row metadata cell + CSS)

**Interfaces:**
- Consumes: `PackageMeta.provenance` / `provenanceIdentity` (Task 3).

- [ ] **Step 1: `formatReport` provenance lines** — replace line 46 with:

```ts
  const prov = m.provenance === "verified" ? c(C.green, "verified")
    : m.provenance === "invalid" ? c(C.red, "invalid")
    : m.provenance === "unknown" ? c(C.yellow, "unknown") : c(C.gray, "absent");
  L.push(`  provenance ${prov}`);
  const pid = m.provenanceIdentity;
  if (m.provenance === "verified" && pid) {
    const commit = pid.commit ? ` (commit ${pid.commit.slice(0, 7)})` : "";
    L.push(`             ${c(C.gray, `built by ${pid.builder ?? "unknown builder"} from ${pid.sourceRepository ?? "?"}${pid.ref ? `@${pid.ref}` : ""}${commit}`)}`);
  }
```

- [ ] **Step 2: Dashboard** — in `index.html`:

CSS (after the `.sig-*` line 49):

```css
  .prov-verified { color: var(--allow); } .prov-invalid { color: var(--block); } .prov-unknown { color: var(--warn); } .prov-absent { color: var(--muted); }
```

Row metadata cell (line 103) — replace `prov: ${m.provenance}<br/>` with:

```js
      prov: <span class="prov-${m.provenance}">${m.provenance}</span>${m.provenanceIdentity && m.provenance === "verified" ? ` · <span class="meta" title="${esc(m.provenanceIdentity.workflow || "")}">${esc((m.provenanceIdentity.sourceRepository || "").replace("https://github.com/", ""))}</span>` : ""}<br/>
```

- [ ] **Step 3: Eyeball via the demo proxy** (offline, fixtures upstream):

```bash
SENTINEL_UPSTREAM=fixtures SENTINEL_BOOT_EXIT=1 node packages/proxy/dist/index.js
```

Expected: boots and exits cleanly (full visual check happens in Task 9's DoD run).

- [ ] **Step 4: Build + full test sweep**

```bash
npm run build && npm test 2>&1 | tail -5
```

Expected: all green (this is the first task after which the whole suite should pass).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/format.ts packages/proxy/public/index.html
git commit -m "feat(phase9): provenance status + verified identity in CLI report and dashboard"
```

---

### Task 9: Docs, ADR-0022, spec amendment, final verification

**Files:**
- Create: `docs/adr/0022-provenance-deep-verify.md`
- Modify: `ARCHITECTURE.md` (§3 — add §3.10 after the Phase 8 section; §5 PackageMeta snapshot)
- Modify: `CLAUDE.md` (What-this-is phase list; test-count line)
- Modify: `README.md` (feature list + env vars `SENTINEL_TRUSTED_ROOT`, `SENTINEL_NPM_ATTESTATION_KEYS`)
- Modify: `docs/superpowers/specs/2026-07-07-provenance-deep-verify-design.md` (spec amendment)

- [ ] **Step 1: Write ADR-0022** — follow the house style of `docs/adr/0021-signature-provenance-verification.md`. Required content: Context (ADR-0021's deferred items + trust-the-claim gap); Decision (gate-time verify, acquisition-path fetch via `Upstream.getAttestations`, `@sigstore/verify` against pinned `packages/core/trust/` material, status model `verified|invalid|absent|unknown`, subject-digest binding, served-bytes integrity recompute keyed by actual bytes, `provenanceIdentities` score-time gate with fail-closed AND across matching entries, `requireProvenance` ⇒ verified, `unknown` exempt from the identity gate but not from requireProvenance); the **fail-closed refinement** (thrown verification error over present bundles ⇒ `invalid`, never `unknown` — a crash-bundle must not bypass the identity gate; `unknown` = missing inputs only); Consequences (three new core deps — Sigstore-project-maintained, provenance-published; trust root is operator-updated static data, staleness surfaced as a zero-weight info finding via injectable `verifyAt`; old bundles stay verified — Sigstore verification is tlog-timestamp-anchored); Deferred (TUF auto-refresh; staleness enforcement; purl name-binding check — digest binding is the strong bind; source-commit liveness checks); Rejected (async-enrich-only — advisory verification can't block forgeries; hand-rolled verifier — chain building/SCTs/Merkle proofs are where security bugs are born; verifier-level identity policy — rules/verifier stay policy-blind per ADR-0014). Extends ADR-0021, ADR-0020, ADR-0014, ADR-0002.

- [ ] **Step 2: Amend the spec** — in the design doc's §2, add after the status table:

```markdown
> **Implementation refinement (ADR-0022):** a thrown error while verifying
> *present* bundles maps to `invalid`, not `unknown` — a crafted crash-bundle
> must not fail open past an identity gate. `unknown` is reserved for missing
> inputs (bundle unfetchable, empty bundle list, no trust material).
```

- [ ] **Step 3: ARCHITECTURE.md §3.10** — describe the flow: packument claims attestations → `getAttestations` on acquisition → `verifyProvenance` (pure, pinned trust) → status + identity on meta → rule findings + score-time identity gate → header/dashboard/audit-tree surfacing. Update the §5 `PackageMeta` snapshot with `provenance: ProvenanceStatus` + `provenanceIdentity`.

- [ ] **Step 4: CLAUDE.md** — add the Phase 9 sentence to "What this is" (mirror the Phase 8 sentence's density; mention `verifyProvenance`, pinned `packages/core/trust/`, `provenanceIdentities`, served-bytes recompute). Update the `npm test` count line with the ACTUAL number from the next step.

- [ ] **Step 5: Full Definition-of-Done run**

```bash
npm run build
npm run fixtures
npm test 2>&1 | tail -6
npm run demo 2>&1 | tail -3
```

Expected: build clean; ALL tests pass (record the exact count for CLAUDE.md); demo still detects/blocks the malicious fixture. If the count differs from CLAUDE.md's documented count, update the doc — never force the number.

- [ ] **Step 6: Commit**

```bash
git add docs ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs(phase9): ADR-0022 provenance deep-verify; ARCHITECTURE §3.10; CLAUDE/README updates"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 acquisition+module → Tasks 2/3/5/6; §2 semantics incl. publish attestation + staleness → Task 2; §3 policy gate + requireProvenance upgrade → Task 4; §4 fixtures/e2e/tamper/header/dashboard/audit-tree/CLI → Tasks 5–8; vendored verified e2e (10 KB tarball — probe confirmed) → Tasks 1/5/6; docs/DoD → Task 9.
- **Type consistency:** `ProvenanceStatus`/`ProvenanceIdentity`/`ProvenanceTrustMaterial` defined once in Task 2 and consumed by name everywhere; `TreePackageRow.provenance` (Task 7) matches Task 2's status union; `provenance-identity` ruleId consistent between Task 4 gate and Task 6 e2e assertion.
- **Known judgment calls:** verification errors over present bundles → `invalid` (fail-closed, documented in ADR + spec amendment); registry signature verified over *claimed* integrity while provenance binds to *actual* bytes (each checks the layer that produced it); `verified` emits no finding (mirrors verified-signature behavior).
