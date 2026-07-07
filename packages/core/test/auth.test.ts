import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateKeypair } from "../src/policy.js";
import { signToken, verifyToken } from "../src/auth.js";

const { publicKey, privateKey } = generateKeypair();
const NOW = 1_000_000; // fixed unix seconds for determinism

describe("auth tokens", () => {
  test("round-trips a role token", () => {
    const t = signToken({ role: "operator", sub: "alice", ttlSeconds: 3600 }, privateKey, NOW);
    const r = verifyToken(t, publicKey, NOW + 10);
    assert.equal(r.ok, true);
    if (r.ok) { assert.equal(r.role, "operator"); assert.equal(r.sub, "alice"); assert.equal(r.exp, NOW + 3600); }
  });

  test("each role verifies", () => {
    for (const role of ["operator", "agent", "publisher"] as const) {
      const t = signToken({ role, sub: "x", ttlSeconds: 60 }, privateKey, NOW);
      const r = verifyToken(t, publicKey, NOW);
      assert.equal(r.ok && r.role, role);
    }
  });

  test("a tampered payload is bad-signature", () => {
    const t = signToken({ role: "agent", sub: "x", ttlSeconds: 60 }, privateKey, NOW);
    const s = t.split(".")[1];
    const forged = Buffer.from(JSON.stringify({ role: "operator", sub: "x", iat: NOW, exp: NOW + 60 })).toString("base64url");
    const r = verifyToken(`${forged}.${s}`, publicKey, NOW);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "bad-signature");
  });

  test("an expired token is expired", () => {
    const t = signToken({ role: "operator", sub: "x", ttlSeconds: 60 }, privateKey, NOW);
    const r = verifyToken(t, publicKey, NOW + 61);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "expired");
  });

  test("a token from a different key is bad-signature", () => {
    const other = generateKeypair();
    const t = signToken({ role: "operator", sub: "x", ttlSeconds: 60 }, other.privateKey, NOW);
    const r = verifyToken(t, publicKey, NOW);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "bad-signature");
  });

  test("garbage is malformed", () => {
    assert.equal(verifyToken("not-a-token", publicKey, NOW).ok, false);
    const r = verifyToken("not-a-token", publicKey, NOW);
    if (!r.ok) assert.equal(r.reason, "malformed");
  });

  test("an unknown role is bad-role", async () => {
    // hand-sign a payload with an invalid role using the raw primitives (ESM import, no require)
    const { createPrivateKey, sign } = await import("node:crypto");
    const payload = Buffer.from(JSON.stringify({ role: "root", sub: "x", iat: NOW, exp: NOW + 60 })).toString("base64url");
    const sig = sign(null, Buffer.from(payload), createPrivateKey(privateKey)).toString("base64url");
    const r = verifyToken(`${payload}.${sig}`, publicKey, NOW);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "bad-role");
  });

  test("a validly-signed non-object payload (null) is malformed, not a throw", async () => {
    const { createPrivateKey, sign } = await import("node:crypto");
    for (const raw of ["null", "5", "\"hi\"", "[1,2]"]) {
      const payload = Buffer.from(raw).toString("base64url");
      const sig = sign(null, Buffer.from(payload), createPrivateKey(privateKey)).toString("base64url");
      const token = `${payload}.${sig}`;
      let r: ReturnType<typeof verifyToken>;
      assert.doesNotThrow(() => { r = verifyToken(token, publicKey, NOW); });
      assert.equal(r!.ok, false);
      if (!r!.ok) assert.equal(r!.reason, "malformed");
    }
  });
});
