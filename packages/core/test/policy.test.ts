import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import {
  DEFAULT_POLICY, generateKeypair, signPolicy, verifyPolicyBytes,
  policyHashOfBytes, parsePolicy, loadPolicy,
} from "../src/index.js";

const rawDefault = Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, version: "acme-1" }));

describe("policy signing", () => {
  test("sign → verify round-trips; tamper fails", () => {
    const { publicKey, privateKey } = generateKeypair();
    const sig = signPolicy(rawDefault, privateKey);
    assert.equal(verifyPolicyBytes(rawDefault, sig, publicKey), true);
    const tampered = Buffer.from(rawDefault.toString().replace("acme-1", "acme-2"));
    assert.equal(verifyPolicyBytes(tampered, sig, publicKey), false);
  });

  test("policyHashOfBytes is stable and prefixed", () => {
    assert.equal(policyHashOfBytes(rawDefault), policyHashOfBytes(rawDefault));
    assert.match(policyHashOfBytes(rawDefault), /^sha256-[0-9a-f]{64}$/);
  });

  test("parsePolicy rejects a non-schema-1 document", () => {
    assert.throws(() => parsePolicy(Buffer.from(JSON.stringify({ schema: 9 }))));
  });

  test("loadPolicy verifies signature and returns policy + raw-bytes hash", () => {
    const { publicKey, privateKey } = generateKeypair();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-policy-"));
    const file = join(dir, "policy.json");
    writeFileSync(file, rawDefault);
    writeFileSync(file + ".sig", signPolicy(rawDefault, privateKey));
    const { policy, hash } = loadPolicy({ file, sig: file + ".sig", publicKeyPem: publicKey });
    assert.equal(policy.version, "acme-1");
    assert.equal(hash, policyHashOfBytes(rawDefault));
  });

  test("loadPolicy throws on a bad signature (caller fails closed)", () => {
    const { publicKey } = generateKeypair();
    const other = generateKeypair();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-policy-"));
    const file = join(dir, "policy.json");
    writeFileSync(file, rawDefault);
    writeFileSync(file + ".sig", signPolicy(rawDefault, other.privateKey)); // wrong key
    assert.throws(() => loadPolicy({ file, sig: file + ".sig", publicKeyPem: publicKey }), /signature/i);
  });
});
