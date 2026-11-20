import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { Buffer } from "node:buffer";
import { extractIdentity, fulcioSourceExtensions, loadDefaultTrustMaterial } from "../src/provenance.js";
import { FIXTURES } from "./helpers.js";

const ATTESTATIONS = JSON.parse(
  readFileSync(join(FIXTURES, "attestations", "sigstore-3.0.0.attestations.json"), "utf8"),
) as { attestations: { predicateType: string; bundle: { verificationMaterial: { x509CertificateChain?: { certificates: { rawBytes: string }[] } } } }[] };
const leaf = Buffer.from(
  ATTESTATIONS.attestations.find((a) => a.predicateType === "https://slsa.dev/provenance/v1")!.bundle.verificationMaterial.x509CertificateChain!.certificates[0]!.rawBytes,
  "base64",
);
const NONE = { sourceRepository: null, ref: null };

describe("F14: source repository/ref come from the Fulcio certificate, not the signer-written predicate", () => {
  test("extension walker reads OID .12 and .14 from the real leaf certificate", () => {
    assert.deepEqual(fulcioSourceExtensions(leaf), {
      sourceRepository: "https://github.com/sigstore/sigstore-js",
      ref: "refs/heads/main",
    });
  });

  test("a certificate without the extensions (a CA cert from the pinned root) yields nulls", () => {
    const root = loadDefaultTrustMaterial()!.trustedRootJson as { certificateAuthorities: { certChain: { certificates: { rawBytes: string }[] } }[] };
    const ca = Buffer.from(root.certificateAuthorities[0]!.certChain.certificates[0]!.rawBytes, "base64");
    assert.deepEqual(fulcioSourceExtensions(ca), NONE);
  });

  test("malformed or truncated DER never throws", () => {
    for (const bad of [Buffer.alloc(0), Buffer.from([0x30]), Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), leaf.subarray(0, 200), Buffer.from("garbage")]) {
      assert.deepEqual(fulcioSourceExtensions(bad), NONE);
    }
  });

  test("extractIdentity ignores a predicate that claims another repository/ref", () => {
    const forged = {
      predicate: {
        buildDefinition: { externalParameters: { workflow: { repository: "https://github.com/acme/lib", ref: "refs/heads/release" } } },
        runDetails: { builder: { id: "https://github.com/actions/runner/github-hosted" } },
      },
    };
    const id = extractIdentity(
      { identity: { subjectAlternativeName: "https://github.com/evil/x/.github/workflows/r.yml@refs/heads/main", extensions: { issuer: "https://token.actions.githubusercontent.com" } } },
      forged,
      leaf,
    );
    assert.equal(id.sourceRepository, "https://github.com/sigstore/sigstore-js");
    assert.equal(id.ref, "refs/heads/main");
  });

  test("no certificate extension means null, with no predicate fallback", () => {
    const forged = { predicate: { buildDefinition: { externalParameters: { workflow: { repository: "https://github.com/acme/lib", ref: "refs/heads/x" } } } } };
    const id = extractIdentity({ identity: {} }, forged, Buffer.alloc(0));
    assert.equal(id.sourceRepository, null);
    assert.equal(id.ref, null);
  });
});
