import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { matchPackage } from "../src/policy.js";
import { verifyRegistrySignature, type NpmSigningKey } from "../src/signature.js";

const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const spkiPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const keyid = "SHA256:" + createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("base64");
const KEYS: NpmSigningKey[] = [{ keyid, spkiPem, expires: null }];
const payload = { name: "demo", version: "1.0.0", integrity: "sha512-abc" };
const goodSig = sign("sha256", Buffer.from("demo@1.0.0:sha512-abc"), privateKey).toString("base64");

describe("signature: unmatched keyids are no better than unsigned", () => {
  test("signatures with only an unknown keyid, against a non-empty trusted set, are unsigned", () => {
    assert.equal(verifyRegistrySignature(payload, [{ keyid: "SHA256:fake", sig: goodSig }], KEYS), "unsigned");
  });
  test("a fake keyid beside a valid signature still verifies", () => {
    assert.equal(
      verifyRegistrySignature(payload, [{ keyid: "SHA256:fake", sig: "AA==" }, { keyid, sig: goodSig }], KEYS),
      "verified",
    );
  });
  test("an empty trusted set keeps the unknown verdict (nothing to verify against)", () => {
    assert.equal(verifyRegistrySignature(payload, [{ keyid: "SHA256:fake", sig: goodSig }], []), "unknown");
  });
});

describe("policy glob matcher", () => {
  test("keeps the documented semantics", () => {
    assert.equal(matchPackage("@acme/*", "@acme/lib"), true);
    assert.equal(matchPackage("@acme/*", "@other/lib"), false);
    assert.equal(matchPackage("lodash", "lodash"), true);
    assert.equal(matchPackage("lodash", "lodash2"), false);
    assert.equal(matchPackage("*", ""), true);
    assert.equal(matchPackage("a*b*c", "aXXbYYc"), true);
    assert.equal(matchPackage("a*b*c", "abc"), true);
    assert.equal(matchPackage("a*b*c", "aXXbYY"), false);
    assert.equal(matchPackage("a.b", "aXb"), false, "regex metacharacters stay literal");
    assert.equal(matchPackage("a**b", "ab"), true);
    assert.equal(matchPackage("*x", "yx"), true);
    assert.equal(matchPackage("*x", "xy"), false);
  });
  test("a multi-star pattern against a 50 KB non-matching string finishes fast", () => {
    const t = Date.now();
    assert.equal(matchPackage("a*a*a*b", "a".repeat(50_000)), false);
    assert.ok(Date.now() - t < 100, `took ${Date.now() - t} ms`);
  });
});
