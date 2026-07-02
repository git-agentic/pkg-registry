import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { verifyRegistrySignature, type NpmSigningKey, type RegistrySignature } from "../src/signature.js";

// A synthetic P-256 key acting like an npm signing key.
const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const spkiPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
const keyid = "SHA256:" + createHash("sha256").update(spkiDer).digest("base64");
const KEYS: NpmSigningKey[] = [{ keyid, spkiPem, expires: null }];

const payload = { name: "demo", version: "1.0.0", integrity: "sha512-abc" };
function signFor(p: typeof payload, kid = keyid): RegistrySignature {
  const sig = sign("sha256", Buffer.from(`${p.name}@${p.version}:${p.integrity}`), privateKey); // DER default
  return { keyid: kid, sig: sig.toString("base64") };
}

describe("verifyRegistrySignature", () => {
  test("verified: a valid signature over the payload against a matching key", () => {
    assert.equal(verifyRegistrySignature(payload, [signFor(payload)], KEYS), "verified");
  });
  test("invalid: signature over a different payload (tamper)", () => {
    const wrong = signFor({ ...payload, integrity: "sha512-EVIL" });
    assert.equal(verifyRegistrySignature(payload, [wrong], KEYS), "invalid");
  });
  test("unsigned: no signatures", () => {
    assert.equal(verifyRegistrySignature(payload, null, KEYS), "unsigned");
    assert.equal(verifyRegistrySignature(payload, [], KEYS), "unsigned");
  });
  test("unknown: signature keyid matches no configured key", () => {
    assert.equal(verifyRegistrySignature(payload, [signFor(payload, "SHA256:nope")], KEYS), "unknown");
  });
});
