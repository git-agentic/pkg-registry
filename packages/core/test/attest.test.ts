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
  claimCorpus: { version: "claims-7", hash: "claims-hash" },
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
      assert.deepEqual(r.predicate.claimCorpus, { version: "claims-7", hash: "claims-hash" });
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
