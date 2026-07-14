import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateKeypair, signToken, type Role } from "@agentic-sentinel/core";
import { makeAuthz } from "../src/authz.js";

const { publicKey, privateKey } = generateKeypair();
const tok = (role: Role) => signToken({ role, sub: "x", ttlSeconds: 3600 }, privateKey);

function fakeRes() {
  return { statusCode: 200, body: undefined as unknown, status(c: number) { this.statusCode = c; return this; }, json(b: unknown) { this.body = b; return this; } };
}
function call(mw: (req: any, res: any, next: () => void) => void, authHeader?: string) {
  const req = { headers: authHeader ? { authorization: authHeader } : {} };
  const res = fakeRes();
  let nexted = false;
  mw(req, res, () => { nexted = true; });
  return { nexted, status: res.statusCode };
}

describe("makeAuthz", () => {
  test("disabled (no key): requireRole is a pass-through", () => {
    const az = makeAuthz(undefined);
    assert.equal(az.enabled, false);
    assert.equal(call(az.requireRole(["operator"])).nexted, true);
  });

  test("enabled: no token → 401", () => {
    const az = makeAuthz(publicKey);
    const r = call(az.requireRole(["operator"]));
    assert.equal(r.nexted, false);
    assert.equal(r.status, 401);
  });

  test("enabled: operator token on operator route → next", () => {
    const az = makeAuthz(publicKey);
    assert.equal(call(az.requireRole(["operator"]), `Bearer ${tok("operator")}`).nexted, true);
  });

  test("enabled: agent token on operator route → 403", () => {
    const az = makeAuthz(publicKey);
    const r = call(az.requireRole(["operator"]), `Bearer ${tok("agent")}`);
    assert.equal(r.nexted, false);
    assert.equal(r.status, 403);
  });

  test("enabled: a bad token → 401", () => {
    const az = makeAuthz(publicKey);
    assert.equal(call(az.requireRole(["operator"]), "Bearer garbage").status, 401);
  });

  test("enabled: a non-Bearer header → 401", () => {
    const az = makeAuthz(publicKey);
    assert.equal(call(az.requireRole(["operator"]), `Basic ${tok("operator")}`).status, 401);
  });
});
