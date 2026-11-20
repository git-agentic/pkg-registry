import assert from "node:assert/strict";
import { after, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@git-agentic/sentinel-core";
import { createServer } from "../src/server.js";
import { createRateLimiter } from "../src/rate-limit.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import type { Upstream } from "../src/upstream.js";

const servers: Server[] = [];
after(() => servers.forEach((s) => s.close()));

interface Seen { path: string; method: string; headers: Record<string, string>; body?: Buffer }

async function boot(overrides: Partial<Parameters<typeof createServer>[0]> = {}) {
  const seen: Seen[] = [];
  const upstream: Upstream = {
    name: "capture",
    async getPackument() { throw new Error("unused"); },
    async getTarball() { throw new Error("unused"); },
    async getAttestations() { return null; },
    async proxyRegistryRequest(path, init) {
      seen.push({ path, method: init.method, headers: init.headers, ...(init.body ? { body: init.body } : {}) });
      return { status: 200, headers: { "content-type": "application/json" }, body: Buffer.from("{}") };
    },
  };
  const app = createServer({
    upstream, store: new AuditStore(), approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(),
    ...overrides,
  });
  const server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
  servers.push(server);
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen };
}

const CREDS = { authorization: "Bearer client-secret", cookie: "session=abc", "npm-otp": "123456", "x-probe": "keep" };

describe("F17: client credentials are not forwarded upstream on compatibility routes", () => {
  test("authorization, cookie and npm-otp are dropped on every compat route except POST /-/v1/login", async () => {
    const { base, seen } = await boot();
    const routes = [
      { path: "/-/v1/search?text=x", method: "GET" },
      { path: "/-/npm/v1/security/advisories/bulk", method: "POST" },
      { path: "/-/npm/v1/keys", method: "GET" },
      { path: "/-/npm/v1/attestations/lodash@4.17.21", method: "GET" },
    ];
    for (const r of routes) {
      const res = await fetch(`${base}${r.path}`, { method: r.method, headers: { ...CREDS, "content-type": "application/json" }, ...(r.method === "POST" ? { body: "{}" } : {}) });
      assert.equal(res.status, 200);
    }
    assert.equal(seen.length, routes.length);
    for (const call of seen) {
      assert.equal(call.headers["authorization"], undefined, `${call.path} leaked authorization`);
      assert.equal(call.headers["cookie"], undefined, `${call.path} leaked cookie`);
      assert.equal(call.headers["npm-otp"], undefined, `${call.path} leaked npm-otp`);
      assert.equal(call.headers["x-probe"], "keep");
    }
  });

  test("POST /-/v1/login keeps its credentials (npm's own web login needs them)", async () => {
    const { base, seen } = await boot();
    const res = await fetch(`${base}/-/v1/login`, { method: "POST", headers: { ...CREDS, "content-type": "application/json" }, body: "{}" });
    assert.equal(res.status, 200);
    assert.equal(seen[0]!.headers["authorization"], "Bearer client-secret");
    assert.equal(seen[0]!.headers["cookie"], "session=abc");
  });
});

describe("F20: compatibility bodies are capped and rate-gated", () => {
  test("a 9 MiB body is refused with 413 before reaching the upstream", async () => {
    const { base, seen } = await boot();
    const res = await fetch(`${base}/-/npm/v1/security/advisories/bulk`, { method: "POST", headers: { "content-type": "application/json" }, body: Buffer.alloc(9 * 1024 * 1024, 0x61) });
    assert.equal(res.status, 413);
    assert.equal(seen.length, 0);
  });

  test("a 2 MiB advisories/bulk body (a large real npm audit tree) still passes", async () => {
    const { base, seen } = await boot();
    const res = await fetch(`${base}/-/npm/v1/security/advisories/bulk`, { method: "POST", headers: { "content-type": "application/json" }, body: Buffer.alloc(2 * 1024 * 1024, 0x61) });
    assert.equal(res.status, 200);
    assert.equal(seen[0]!.body!.length, 2 * 1024 * 1024);
  });

  test("compat routes honour the rate gate", async () => {
    const { base, seen } = await boot({ rateLimiter: createRateLimiter({ rpm: 1, now: () => 0 }) });
    assert.equal((await fetch(`${base}/-/npm/v1/keys`)).status, 200);
    const second = await fetch(`${base}/-/npm/v1/keys`);
    assert.equal(second.status, 429);
    assert.equal(seen.length, 1);
  });
});
