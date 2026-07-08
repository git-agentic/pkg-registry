# Phase 19 — Signed Audit Attestations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit a signed in-toto/DSSE Verification Summary Attestation that binds an audited dependency tree (by its SBOM digest) to a policy hash + aggregate verdict, offline-verifiable against a pinned Ed25519 key — a deploy-time trust primitive.

**Architecture:** A pure `packages/core/src/attest.ts` produces (`buildAuditStatement` + `signAttestation`) and verifies (`verifyAttestation`) the attestation, reusing the repo's Ed25519 primitives (`signPolicy`/`verifyPolicyBytes`) and the CycloneDX SBOM (Phase 14) as the subject; the CLI adds `attest keygen`, `attest`, and `verify-attestation`. Signing is operator-side (CLI), never on the proxy. Scoring is untouched.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; `node:crypto` Ed25519 (reused, no new dep); `node:test` via `tsx`.

## Global Constraints

- **Reuse the existing Ed25519 primitives** — `signPolicy(raw: Buffer, privateKeyPem): base64 sig` and `verifyPolicyBytes(raw: Buffer, sigB64, publicKeyPem): boolean` are exactly "Ed25519 sign/verify arbitrary bytes"; sign/verify the DSSE PAE with them. `generateKeypair()` for keygen. Do NOT add a new signing dependency.
- **Standard DSSE + in-toto Statement.** Envelope `{ payloadType: "application/vnd.in-toto+json", payload: base64(statementBytes), signatures: [{ keyid, sig }] }`; the signature is Ed25519 over the DSSE **PAE**: `"DSSEv1 " + byteLen(payloadType) + " " + payloadType + " " + byteLen(statementBytes) + " " + statementBytes`.
- **Subject = SBOM sha256 (hex).** The in-toto subject digest is `{ sha256: <hex> }` where hex = `createHash("sha256").update(sbomBytes).digest("hex")`. (Note: this is HEX, not the base64 SRI `integrityOfAlgo` returns.)
- **`predicateType` = `"https://sentinel.dev/attestation/audit-summary/v1"`** (export as `SENTINEL_PREDICATE_TYPE`). Statement `_type` = `"https://in-toto.io/Statement/v1"`.
- **`verifyAttestation` is pure, offline, total** — never fetches, never throws; a malformed/tampered envelope ⇒ `{ valid: false, reason }` (fail-closed, never `unknown`). No `Date.now()` in verify.
- **Determinism** — `buildAuditStatement` takes an injected `now`; Ed25519 is deterministic; the statement is serialized with `JSON.stringify` over a FIXED key insertion order, so the same `(tree, sbomDigest, now, key)` yields a byte-identical envelope.
- **Signing off the proxy** — the proxy only gains an optional `TreeAuditResult.policyHash?`; the signing key is CLI-only. Private keys written `{ mode: 0o600 }`.
- **Invariant #1 untouched** — the attestation is over the audit result; scoring is unchanged.
- ESM only, NodeNext: internal imports use `.js` specifiers; cross-package imports use the package name.
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/<pkg>`.
- Run all commands from repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.

---

### Task 1: Core `attest.ts` — build, sign, verify, keyid, PAE

**Files:**
- Create: `packages/core/src/attest.ts`
- Modify: `packages/core/src/tree.ts` (`TreeAuditResult.policyHash?`)
- Modify: `packages/core/src/index.ts` (exports)
- Test: `packages/core/test/attest.test.ts`

**Interfaces:**
- Consumes: `TreeAuditResult` (tree.js), `signPolicy`/`verifyPolicyBytes`/`generateKeypair` (policy.js), `ENGINE_VERSION` (audit.js).
- Produces (used by Tasks 2–3): the types + `SENTINEL_PREDICATE_TYPE`, `buildAuditStatement(tree, { sbomDigest, sbomName, now }): InTotoStatementV1`, `pae(payloadType, payload): Buffer`, `signAttestation(statement, privateKeyPem, keyid): DsseEnvelope`, `attestationKeyid(publicKeyPem): string`, `verifyAttestation(envelope, publicKeyPem, opts?): VerifyResult`.

- [ ] **Step 1: Write the failing test** (`packages/core/test/attest.test.ts`)

```ts
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";
import { generateKeypair } from "../src/policy.js";
import {
  buildAuditStatement, signAttestation, verifyAttestation, attestationKeyid, pae,
  SENTINEL_PREDICATE_TYPE, type DsseEnvelope,
} from "../src/attest.js";
import type { TreeAuditResult } from "../src/tree.js";

const tree: TreeAuditResult = {
  policyHash: "policy-abc",
  aggregate: { verdict: "block", gated: true, counts: { allow: 1, warn: 0, block: 1, error: 0 }, provenance: { verified: 0, invalid: 0, absent: 2, unknown: 0 }, integrityMismatch: 0 },
  packages: [
    { name: "ok", version: "1.0.0", status: "allow", score: 100, topFinding: null, topFindingRuleId: null, error: null, provenance: "absent", integrityMismatch: false },
    { name: "evil", version: "2.0.0", status: "block", score: 10, topFinding: "x", topFindingRuleId: "release-anomaly", error: null, provenance: "absent", integrityMismatch: false },
  ],
};
const sbomBytes = Buffer.from(JSON.stringify({ bomFormat: "CycloneDX" }));
const sbomDigest = createHash("sha256").update(sbomBytes).digest("hex");

function envelope(): { env: DsseEnvelope; pub: string } {
  const { publicKey, privateKey } = generateKeypair();
  const keyid = attestationKeyid(publicKey);
  const stmt = buildAuditStatement(tree, { sbomDigest, sbomName: "sbom.json", now: "2026-07-08T00:00:00Z" });
  return { env: signAttestation(stmt, privateKey, keyid), pub: publicKey };
}

describe("attest", () => {
  test("build → sign → verify round-trips valid", () => {
    const { env, pub } = envelope();
    const r = verifyAttestation(env, pub);
    assert.equal(r.valid, true);
    if (r.valid) {
      assert.equal(r.predicate.verdict, "block");
      assert.equal(r.predicate.policyHash, "policy-abc");
      assert.equal(r.statement.subject[0]!.digest.sha256, sbomDigest);
      assert.equal(r.statement.predicateType, SENTINEL_PREDICATE_TYPE);
    }
  });

  test("deterministic — same inputs yield a byte-identical envelope", () => {
    const { publicKey: _p, privateKey } = generateKeypair();
    const keyid = "SHA256:fixed";
    const stmt = buildAuditStatement(tree, { sbomDigest, sbomName: "sbom.json", now: "2026-07-08T00:00:00Z" });
    assert.deepEqual(signAttestation(stmt, privateKey, keyid), signAttestation(stmt, privateKey, keyid));
  });

  test("PAE conformance — exact DSSEv1 preamble", () => {
    const pt = "application/vnd.in-toto+json";
    const p = pae(pt, Buffer.from("HELLO")).toString("utf8");
    assert.equal(p, `DSSEv1 ${Buffer.byteLength(pt)} ${pt} 5 HELLO`);
  });

  test("tampered payload → invalid-signature", () => {
    const { env, pub } = envelope();
    const bad = { ...env, payload: Buffer.from(JSON.stringify({ hacked: true })).toString("base64") };
    const r = verifyAttestation(bad, pub);
    assert.equal(r.valid, false);
    if (!r.valid) assert.equal(r.reason, "invalid-signature");
  });

  test("wrong public key → invalid-signature", () => {
    const { env } = envelope();
    const other = generateKeypair().publicKey;
    assert.equal(verifyAttestation(env, other).valid, false);
  });

  test("malformed envelope → invalid (never throws)", () => {
    assert.equal(verifyAttestation({ nonsense: 1 }, envelope().pub).valid, false);
    assert.equal(verifyAttestation(null, envelope().pub).valid, false);
  });

  test("opts: subject/policy/verdict mismatch → specific reason", () => {
    const { env, pub } = envelope();
    assert.equal((verifyAttestation(env, pub, { expectedSbomDigest: "deadbeef" }) as { reason: string }).reason, "subject-mismatch");
    assert.equal((verifyAttestation(env, pub, { expectedPolicyHash: "nope" }) as { reason: string }).reason, "policy-mismatch");
    assert.equal((verifyAttestation(env, pub, { requireVerdict: "allow" }) as { reason: string }).reason, "verdict-block");
    // allow-or-warn also rejects a block:
    assert.equal(verifyAttestation(env, pub, { requireVerdict: "allow-or-warn" }).valid, false);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/core/test/attest.test.ts
```

Expected: FAIL — `../src/attest.js` not found.

- [ ] **Step 3a: Add the optional field to `TreeAuditResult` in `packages/core/src/tree.ts`**

```ts
export interface TreeAuditResult {
  aggregate: TreeAggregate;
  packages: TreePackageRow[];
  /** Hash of the policy the tree was scored under (Phase 19 attestation); set by the proxy route. */
  policyHash?: string;
}
```

- [ ] **Step 3b: Implement `packages/core/src/attest.ts`**

```ts
import { createHash, createPublicKey } from "node:crypto";
import { signPolicy, verifyPolicyBytes } from "./policy.js";
import { ENGINE_VERSION } from "./audit.js";
import type { TreeAuditResult, Verdict } from "./tree.js";

export const SENTINEL_PREDICATE_TYPE = "https://sentinel.dev/attestation/audit-summary/v1";
const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
const PAYLOAD_TYPE = "application/vnd.in-toto+json";

export interface AuditPredicate {
  verifier: { name: string; version: string };
  policyHash: string | null;
  verdict: Verdict;
  gated: boolean;
  counts: { allow: number; warn: number; block: number; error: number };
  packageCount: number;
  timestamp: string;
}
export interface InTotoStatementV1 {
  _type: string;
  subject: { name: string; digest: { sha256: string } }[];
  predicateType: string;
  predicate: AuditPredicate;
}
export interface DsseEnvelope { payloadType: string; payload: string; signatures: { keyid: string; sig: string }[]; }

export type VerifyReason =
  | "malformed" | "invalid-signature" | "wrong-predicate"
  | "subject-mismatch" | "policy-mismatch" | "verdict-block" | "verdict-warn";
export type VerifyResult =
  | { valid: true; statement: InTotoStatementV1; predicate: AuditPredicate }
  | { valid: false; reason: VerifyReason };

/** DSSE Pre-Authentication Encoding over the raw payload bytes. */
export function pae(payloadType: string, payload: Buffer): Buffer {
  const preamble = Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `, "utf8");
  return Buffer.concat([preamble, payload]);
}

/** Stable keyid for a public key: `SHA256:<base64(sha256(SPKI DER))>` (matches Phase 8 keyids). */
export function attestationKeyid(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return `SHA256:${createHash("sha256").update(der).digest("base64")}`;
}

/** Build the in-toto audit-summary Statement over a tree audit. Pure; `now` injected. */
export function buildAuditStatement(tree: TreeAuditResult, opts: { sbomDigest: string; sbomName: string; now: string }): InTotoStatementV1 {
  const a = tree.aggregate;
  return {
    _type: STATEMENT_TYPE,
    subject: [{ name: opts.sbomName, digest: { sha256: opts.sbomDigest } }],
    predicateType: SENTINEL_PREDICATE_TYPE,
    predicate: {
      verifier: { name: "sentinel", version: ENGINE_VERSION },
      policyHash: tree.policyHash ?? null,
      verdict: a.verdict,
      gated: a.gated,
      counts: { allow: a.counts.allow, warn: a.counts.warn, block: a.counts.block, error: a.counts.error },
      packageCount: tree.packages.length,
      timestamp: opts.now,
    },
  };
}

/** Sign a Statement into a DSSE envelope (Ed25519 over the PAE). */
export function signAttestation(statement: InTotoStatementV1, privateKeyPem: string, keyid: string): DsseEnvelope {
  const payloadBytes = Buffer.from(JSON.stringify(statement), "utf8");
  const sig = signPolicy(pae(PAYLOAD_TYPE, payloadBytes), privateKeyPem);
  return { payloadType: PAYLOAD_TYPE, payload: payloadBytes.toString("base64"), signatures: [{ keyid, sig }] };
}

/** Verify a DSSE audit attestation offline against a pinned key. Pure, total, fail-closed. */
export function verifyAttestation(
  envelope: unknown,
  publicKeyPem: string,
  opts: { expectedSbomDigest?: string; expectedPolicyHash?: string; requireVerdict?: "allow" | "allow-or-warn" } = {},
): VerifyResult {
  try {
    const env = envelope as DsseEnvelope;
    if (!env || typeof env.payloadType !== "string" || typeof env.payload !== "string" || !Array.isArray(env.signatures)) {
      return { valid: false, reason: "malformed" };
    }
    const payloadBytes = Buffer.from(env.payload, "base64");
    const signed = pae(env.payloadType, payloadBytes);
    const ok = env.signatures.some((s) => s && typeof s.sig === "string" && verifyPolicyBytes(signed, s.sig, publicKeyPem));
    if (!ok) return { valid: false, reason: "invalid-signature" };

    const statement = JSON.parse(payloadBytes.toString("utf8")) as InTotoStatementV1;
    if (statement.predicateType !== SENTINEL_PREDICATE_TYPE) return { valid: false, reason: "wrong-predicate" };
    const predicate = statement.predicate;

    if (opts.expectedSbomDigest && statement.subject?.[0]?.digest?.sha256 !== opts.expectedSbomDigest) {
      return { valid: false, reason: "subject-mismatch" };
    }
    if (opts.expectedPolicyHash && predicate.policyHash !== opts.expectedPolicyHash) {
      return { valid: false, reason: "policy-mismatch" };
    }
    if (opts.requireVerdict) {
      const allowed = opts.requireVerdict === "allow" ? ["allow"] : ["allow", "warn"];
      if (!allowed.includes(predicate.verdict)) {
        return { valid: false, reason: predicate.verdict === "block" ? "verdict-block" : "verdict-warn" };
      }
    }
    return { valid: true, statement, predicate };
  } catch {
    return { valid: false, reason: "malformed" };
  }
}
```

- [ ] **Step 4: Export from `packages/core/src/index.ts`**

```ts
export {
  buildAuditStatement, signAttestation, verifyAttestation, attestationKeyid, pae, SENTINEL_PREDICATE_TYPE,
  type InTotoStatementV1, type AuditPredicate, type DsseEnvelope, type VerifyResult, type VerifyReason,
} from "./attest.js";
```

- [ ] **Step 5: Run the test + build**

```bash
npm run build
npx tsx --test packages/core/test/attest.test.ts
```

Expected: PASS (7/7). Then a quick full `npm test`.

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/attest.ts packages/core/src/tree.ts packages/core/src/index.ts packages/core/test/attest.test.ts
git commit -m "feat(phase19): attest core — in-toto/DSSE build+sign+verify (Ed25519), SBOM-digest subject, keyid, PAE"
```

---

### Task 2: Proxy — `policyHash` on the audit-tree response

**Files:**
- Modify: `packages/proxy/src/server.ts` (set `policyHash` on the `TreeAuditResult`)
- Test: `packages/proxy/test/audit-tree-integrity-e2e.test.ts` (extend)

**Interfaces:**
- Consumes: `policyHash` (in `createServer`'s scope, from `opts.policyHash`).
- Produces: `POST /-/audit-tree` responses carry `policyHash`.

- [ ] **Step 1: Extend the failing test** — in `packages/proxy/test/audit-tree-integrity-e2e.test.ts`, add a case asserting the audit-tree response includes `policyHash`:

```ts
test("audit-tree response carries the policyHash for attestation binding", async () => {
  const r = await tree(base, [{ name: "leftpad-lite", version: "1.0.0" }]);
  assert.equal(typeof r.policyHash, "string");
  assert.ok(r.policyHash!.length > 0);
});
```

(The `tree(base, packages)` helper + `base` already exist in that file. `DEFAULT_POLICY`'s hash is non-empty.)

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/audit-tree-integrity-e2e.test.ts
```

Expected: FAIL — `policyHash` undefined on the response.

- [ ] **Step 3: Set `policyHash` on the result in the audit-tree route** (`packages/proxy/src/server.ts`, where `const result: TreeAuditResult = { aggregate, packages: rows };` is built):

```ts
    const result: TreeAuditResult = { aggregate, packages: rows, policyHash };
```

(`policyHash` is already in `createServer`'s scope — it's the `policyHash` option / computed hash the server was constructed with. If the local name differs, use the in-scope policy-hash variable; confirm by reading the top of `createServer`.)

- [ ] **Step 4: Build + run the test**

```bash
npm run build
npx tsx --test packages/proxy/test/audit-tree-integrity-e2e.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/audit-tree-integrity-e2e.test.ts
git commit -m "feat(phase19): expose policyHash on the audit-tree response for attestation binding"
```

---

### Task 3: CLI — `attest keygen`, `attest`, `verify-attestation`

**Files:**
- Modify: `packages/cli/src/index.ts` (three commands)
- Test: `packages/cli/test/attest-cli-e2e.test.ts`

**Interfaces:**
- Consumes: `fetchTree` (existing CLI helper), `toCycloneDX`, `generateKeypair`, `buildAuditStatement`, `signAttestation`, `verifyAttestation`, `attestationKeyid` (`@sentinel/core`).
- Produces: `sentinel attest keygen`, `sentinel attest <lockfile>`, `sentinel verify-attestation <att>`.

- [ ] **Step 1: Write the failing e2e** (`packages/cli/test/attest-cli-e2e.test.ts`) — boot an in-process proxy with `LocalFixtureUpstream`, run the CLI children via async `execFile` (model boot + run on an existing CLI e2e in `packages/cli/test`). A fixture lockfile referencing `leftpad-lite@1.0.0` + the malicious `color-stream@1.4.1`. Assert:
- `sentinel attest keygen --out <tmp>/k` writes `k.pub.pem` + `k.key.pem` (private mode 0600), exit 0.
- `sentinel attest <lockfile> --key <tmp>/k.key.pem --sbom <tmp>/sbom.json --out <tmp>/att.json -p <base>` writes a valid SBOM + a DSSE `att.json` (has `payloadType`/`payload`/`signatures`), exit 0.
- `sentinel verify-attestation <tmp>/att.json --key <tmp>/k.pub.pem` exits 0; with `--require allow` exits NON-zero (the malicious tree blocks); with a wrong key (a second keygen) exits non-zero.

```ts
// Skeleton — fill boot/run helpers from an existing CLI e2e in packages/cli/test:
// boot(): createServer(...) with LocalFixtureUpstream + all stores, listen(0)
// runCli(args, base?): promisify(execFile)("npx", ["tsx", CLI_INDEX, ...args], { env: {...process.env, ...(base?{SENTINEL_PROXY:base}:{}) } })
//   returns { code, stdout }; catch → { code: err.code, stdout }
// Write a package-lock.json in a tmp dir with node_modules/leftpad-lite@1.0.0 + node_modules/color-stream@1.4.1.
// Steps:
//   keygen → assert existsSync(k.pub.pem) && existsSync(k.key.pem); statSync(k.key.pem).mode & 0o777 === 0o600
//   attest → assert att.json parses with payloadType/payload/signatures[0].sig; sbom.json bomFormat === CycloneDX
//   verify (right key) → code 0
//   verify --require allow → code !== 0   (block tree)
//   verify (wrong pub key) → code !== 0
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/cli/test/attest-cli-e2e.test.ts
```

Expected: FAIL — the commands don't exist.

- [ ] **Step 3: Add the commands in `packages/cli/src/index.ts`.** Import the attest functions + `createHash` from `node:crypto` + `parseAnyLockfile`. Model `attest` on the existing `audit-tree` command (it already `fetchTree` + writes an SBOM). Add:

```ts
const attestCmd = program.command("attest").description("Produce a signed Sentinel audit attestation (VSA) for a dependency tree.");

attestCmd
  .command("keygen")
  .description("Generate an Ed25519 attestation signing keypair.")
  .requiredOption("--out <prefix>", "output path prefix (writes <prefix>.pub.pem and <prefix>.key.pem)")
  .action((opts: { out: string }) => {
    const { publicKey, privateKey } = generateKeypair();
    writeFileSync(`${opts.out}.pub.pem`, publicKey);
    writeFileSync(`${opts.out}.key.pem`, privateKey, { mode: 0o600 });
    console.log(`wrote ${opts.out}.pub.pem / ${opts.out}.key.pem\nkeyid: ${attestationKeyid(publicKey)}`);
  });

// Default action of `attest <lockfile>` (attach to the attestCmd itself via .argument + .action):
attestCmd
  .argument("[lockfile]", "path to the lockfile", "package-lock.json")
  .requiredOption("--key <file>", "Ed25519 private key PEM to sign with")
  .requiredOption("--out <file>", "where to write the DSSE attestation JSON")
  .option("--sbom <file>", "where to write the CycloneDX SBOM", "sentinel-sbom.json")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .action(async (lockfile: string, opts: { key: string; out: string; sbom: string; proxy: string }) => {
    try {
      const coords = parseAnyLockfile(readFileSync(lockfile, "utf8"), { filename: lockfile });
      const result = await fetchTree(opts.proxy, coords);
      const sbom = JSON.stringify(toCycloneDX(result, { now: new Date().toISOString() }), null, 2);
      writeFileSync(opts.sbom, sbom);
      const sbomDigest = createHash("sha256").update(Buffer.from(sbom)).digest("hex");
      const stmt = buildAuditStatement(result, { sbomDigest, sbomName: opts.sbom, now: new Date().toISOString() });
      const keyid = attestationKeyid(readFileSync(opts.key, "utf8").replace(/PRIVATE/, "PRIVATE")); // placeholder — see note
      const env = signAttestation(stmt, readFileSync(opts.key, "utf8"), keyid);
      writeFileSync(opts.out, JSON.stringify(env, null, 2));
      console.log(`attested ${result.aggregate.verdict} · subject sha256:${sbomDigest.slice(0, 16)}… → ${opts.out}`);
    } catch (err) {
      fail(err, opts.proxy);
    }
  });
```

**Note on `keyid`:** `attestationKeyid` needs a PUBLIC key. Derive it from the private key: `createPublicKey(privatePem).export({ type: "spki", format: "pem" })` then `attestationKeyid(pubPem)`. Replace the placeholder line with:
```ts
      const pubPem = createPublicKey(readFileSync(opts.key, "utf8")).export({ type: "spki", format: "pem" }).toString();
      const env = signAttestation(stmt, readFileSync(opts.key, "utf8"), attestationKeyid(pubPem));
```
(import `createPublicKey` from `node:crypto`.)

Then `verify-attestation`:
```ts
program
  .command("verify-attestation")
  .description("Verify a Sentinel audit attestation offline against a pinned public key (a deploy gate).")
  .argument("<attestation>", "path to the DSSE attestation JSON")
  .requiredOption("--key <file>", "pinned Ed25519 public key PEM")
  .option("--sbom <file>", "the SBOM the attestation must bind to (checks subject digest)")
  .option("--policy-hash <hash>", "require this policy hash")
  .option("--require <level>", "require verdict: allow | allow-or-warn")
  .action((attFile: string, opts: { key: string; sbom?: string; policyHash?: string; require?: string }) => {
    const env = JSON.parse(readFileSync(attFile, "utf8"));
    const expectedSbomDigest = opts.sbom ? createHash("sha256").update(readFileSync(opts.sbom)).digest("hex") : undefined;
    const requireVerdict = opts.require === "allow" || opts.require === "allow-or-warn" ? opts.require : undefined;
    const r = verifyAttestation(env, readFileSync(opts.key, "utf8"), { expectedSbomDigest, expectedPolicyHash: opts.policyHash, requireVerdict });
    if (r.valid) {
      console.log(`✓ valid · verdict ${r.predicate.verdict} · policy ${r.predicate.policyHash ?? "?"} · ${r.predicate.timestamp}`);
    } else {
      console.error(`✗ attestation rejected: ${r.reason}`);
      process.exitCode = 2;
    }
  });
```

(Ensure `createHash`, `createPublicKey` imported from `node:crypto`; `parseAnyLockfile`, the attest functions, `toCycloneDX`, `generateKeypair` imported from `@sentinel/core`. Commander note: attaching both subcommands AND a default `.argument/.action` to `attestCmd` — verify commander 15 supports a parent command with both a default action and a `keygen` subcommand; if it conflicts, make `attest` the tree command and `attest-keygen` a sibling, adjusting the e2e accordingly.)

- [ ] **Step 4: Build + run the e2e + full suite**

```bash
npm run build
npx tsx --test packages/cli/test/attest-cli-e2e.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS; record counts.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/index.ts packages/cli/test/attest-cli-e2e.test.ts
git commit -m "feat(phase19): sentinel attest keygen/attest + verify-attestation (offline deploy gate)"
```

---

### Task 4: Docs, ADR-0032, final verification

**Files:**
- Create: `docs/adr/0032-signed-audit-attestations.md`
- Modify: `ARCHITECTURE.md` (the attestation produce/verify layer + deploy-gate flow)
- Modify: `CLAUDE.md` (What-this-is phase list; `sentinel attest`/`verify-attestation`; test-count line)
- Modify: `README.md` (attestation usage + the deploy-gate story)

- [ ] **Step 1: Write ADR-0032** — follow the style of `docs/adr/0027-ecosystem-breadth-sbom.md`. Required content: **Context** (Sentinel verifies trust IN but produces none; the audit result isn't a portable/gateable artifact). **Decision** (a pure `attest.ts` producing an in-toto Statement in a DSSE envelope, Ed25519-signed over the PAE, subject = SBOM sha256, predicate = a VSA-style summary {policyHash, verdict, gated, counts}; `verifyAttestation` pure/offline/total/fail-closed; signing operator-side in the CLI, never on the proxy; `sentinel attest keygen`/`attest` + `verify-attestation` as a deploy gate; the proxy only exposes an optional `policyHash` on the audit-tree response). **Determinism** (Ed25519 + injected `now` ⇒ byte-identical envelope; scoring untouched — invariant #1; `verifyAttestation` makes no network call). **Consequences** (extends enforcement to deploy-time via a portable offline-verifiable artifact; reuses existing Ed25519 + SBOM + in-toto shapes — no new dep; the custom `predicateType` bounds SLSA-verifier interop — documented). **Deferred** (Action auto-produce; Rekor/transparency log; multi-signer/threshold; per-package attestation; key auto-discovery). **Rejected** (a bespoke Sentinel-native signed JSON — non-standard vs DSSE/in-toto; signing on the proxy — key-hygiene risk). **VERIFY** the provenance/signing ADR numbers you cite with `head -1 docs/adr/00*.md | grep -iE "provenance|signature|sign|policy"` before citing; extends ADR-0002.

- [ ] **Step 2: ARCHITECTURE.md** — document the attestation layer (`attest.ts` produce/verify, DSSE/in-toto, SBOM-digest subject, PAE), the CLI surfaces, and the offline deploy-gate flow. Note signing is off the proxy + invariant #1 untouched.

- [ ] **Step 3: CLAUDE.md** — add the Phase 19 sentence to "What this is" (mirror recent-phase density). Note `sentinel attest` + `sentinel verify-attestation` in the CLI list. Update the `npm test` count to the ACTUAL number from Step 5 (preserve darwin-skip caveats).

- [ ] **Step 4: README.md** — document `sentinel attest keygen` / `sentinel attest <lockfile> --key … --sbom … --out …` / `sentinel verify-attestation <att> --key … [--sbom --policy-hash --require]`, and the deploy-gate story (CI produces the SBOM + attestation; a later offline step verifies against a pinned key). Note the SLSA-VSA framing + the custom-predicate interop boundary.

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
git commit -m "docs(phase19): ADR-0032 signed audit attestations; ARCHITECTURE/CLAUDE/README"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 architecture → Task 1 (attest.ts core) + Task 2 (policyHash plumbing); §2 statement/predicate/PAE/sign/keyid → Task 1; §3 verify + CLI surfaces + deploy gate → Task 1 (verifyAttestation) + Task 3 (three CLI commands); §4 testing/DoD → each task's tests + Task 4. The malicious-fixture-still-blocks + attestation-verdict-block is Task 3's e2e (`--require allow` exits non-zero). Determinism/invariant #1 (attest over the result, injected `now`, byte-identical envelope) in Task 1 + reaffirmed in Task 4.
- **Type consistency:** `InTotoStatementV1`/`AuditPredicate`/`DsseEnvelope`/`VerifyResult` + `buildAuditStatement`/`signAttestation`/`verifyAttestation`/`attestationKeyid`/`pae`/`SENTINEL_PREDICATE_TYPE` (Task 1) consumed by the CLI (Task 3); `TreeAuditResult.policyHash?` (Task 1) set by the proxy route (Task 2) and read by `buildAuditStatement` (Task 1). `verifyAttestation`'s `opts` (`expectedSbomDigest`/`expectedPolicyHash`/`requireVerdict`) + `reason` values consistent between Task 1 and the CLI (Task 3).
- **Known judgment calls:** reuse `signPolicy`/`verifyPolicyBytes` as the Ed25519 sign/verify-arbitrary-bytes primitives (no new crypto); the subject digest is HEX sha256 (in-toto convention) not the base64 SRI `integrityOfAlgo` returns; `keyid` is derived from the PUBLIC key (the CLI derives the pub key from the private key via `createPublicKey`); canonical serialization is `JSON.stringify` over a fixed insertion order (deterministic — no external canonicalizer); the `attest` parent command carries both a `keygen` subcommand and a default tree-attest action (the plan flags the commander-15 fallback to a sibling command if that conflicts).
