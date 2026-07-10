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

  test("identity extraction keys on the signed statement, not the outer wrapper label", () => {
    const relabeled = structuredClone(ATTESTATIONS);
    const slsa = relabeled.attestations.find((a) => a.predicateType === "https://slsa.dev/provenance/v1")!;
    slsa.predicateType = "https://example.com/mislabeled";
    const r = verifyProvenance({ ...base, attestations: relabeled });
    assert.equal(r.status, "verified");
    assert.equal(r.identity?.sourceRepository, "https://github.com/sigstore/sigstore-js");
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
    const r = verifyProvenance({
      ...base,
      attestations: ATTESTATIONS,
      integrity: "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
    });
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

  test("unknown: bundles verify and bind but none carries the SLSA v1 predicate", () => {
    const publishOnly = structuredClone(ATTESTATIONS);
    publishOnly.attestations = publishOnly.attestations.filter(
      (a) => a.predicateType !== "https://slsa.dev/provenance/v1",
    );
    assert.equal(publishOnly.attestations.length, 1, "fixture must still contain exactly the non-SLSA publish attestation");
    const r = verifyProvenance({ ...base, attestations: publishOnly });
    assert.equal(r.status, "unknown");
    assert.equal(r.identity, null);
    assert.match(r.reason ?? "", /no recognized SLSA v1/i);
  });

  test("rootStale: real root with an open-ended CA never reports stale, even far in the future", () => {
    const now = verifyProvenance({ ...base, attestations: ATTESTATIONS, now: "2026-07-07T00:00:00Z" });
    assert.equal(now.rootStale, false);
    const far = verifyProvenance({ ...base, attestations: ATTESTATIONS, now: "2126-01-01T00:00:00Z" });
    assert.equal(far.rootStale, false);
  });

  test("rootStale: stale when every CA in the trust material has ended", () => {
    const staleTrust = structuredClone(trust!);
    const root = staleTrust.trustedRootJson as { certificateAuthorities: { validFor?: { end?: string } }[] };
    for (const ca of root.certificateAuthorities) {
      ca.validFor = { ...(ca.validFor ?? {}), end: "2020-01-01T00:00:00.000Z" };
    }
    // attestations: null keeps the path away from actual crypto against the mutated root.
    const r = verifyProvenance({ ...base, attestations: null, trust: staleTrust, now: "2026-07-07T00:00:00Z" });
    assert.equal(r.status, "unknown");
    assert.equal(r.rootStale, true);
  });

  test("determinism: same inputs, same result", () => {
    const a = verifyProvenance({ ...base, attestations: ATTESTATIONS, now: "2026-07-07T00:00:00Z" });
    const b = verifyProvenance({ ...base, attestations: ATTESTATIONS, now: "2026-07-07T00:00:00Z" });
    assert.deepEqual(a, b);
  });
});
