import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, test } from "node:test";
import { AUDIT_REVISION, DEFAULT_POLICY, ENGINE_VERSION, integrityOf, type Audit, type EnterprisePolicy } from "@git-agentic/sentinel-core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import type { Upstream } from "../src/upstream.js";

const NOW = Date.parse("2026-07-13T12:00:00.000Z");
const servers: Server[] = [];
afterEach(() => { while (servers.length) servers.pop()!.close(); });

const upstream: Upstream = {
  name: "unused",
  async getPackument() { throw new Error("unused"); },
  async getTarball() { throw new Error("unused"); },
  async getAttestations() { return null; },
};
const policy: EnterprisePolicy = { ...DEFAULT_POLICY, privateNamespaces: ["@acme/*"] };

function audit(name: string, version: string, tarball: Buffer): Audit {
  return {
    schema: 3,
    meta: { name, version, integrity: integrityOf(tarball), author: null, maintainers: [], license: null, hasInstallScripts: false,
      signature: "unsigned", provenance: "absent", unpackedSize: tarball.length, fileCount: 1 },
    findings: [], capabilities: [], capabilityDelta: null,
    engine: { version: ENGINE_VERSION, revision: AUDIT_REVISION, rules: [], mode: "full" }, auditedAt: "2026-07-13T00:00:00.000Z", durationMs: 1,
  };
}

async function boot(publishTokens: string[]) {
  const privateStore = new PrivatePackageStore(undefined, () => NOW);
  const tarball = Buffer.from("tarball-1");
  privateStore.publish({ name: "@acme/widget", version: "1.0.0", integrity: integrityOf(tarball), tarball,
    manifest: { name: "@acme/widget", version: "1.0.0", dist: { integrity: integrityOf(tarball) } },
    audit: audit("@acme/widget", "1.0.0", tarball), actor: "publisher" });
  const app = createServer({ upstream, store: new AuditStore(), approvals: new ApprovalStore(), privateStore, enterprisePolicy: policy,
    policy: "observe", violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(), now: () => NOW, publishTokens });
  const server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
  servers.push(server);
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const post = (base: string, path: string, body: unknown, token?: string) => fetch(`${base}${path}`, {
  method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body),
});

describe("F18: open mode no longer exposes import/retraction without a credential", () => {
  test("POST /-/retractions without a publish token → 401; the version stays served", async () => {
    const base = await boot(["publish-token"]);
    const res = await post(base, "/-/retractions", { name: "@acme/widget", version: "1.0.0", reason: "security" });
    assert.equal(res.status, 401);
    assert.equal((await fetch(`${base}/@acme/widget/-/widget-1.0.0.tgz`)).status, 200);
  });

  test("POST /-/retractions with a wrong token → 401, with the publish token → proceeds", async () => {
    const base = await boot(["publish-token"]);
    assert.equal((await post(base, "/-/retractions", { name: "@acme/widget", version: "1.0.0", reason: "security" }, "nope")).status, 401);
    const ok = await post(base, "/-/retractions", { name: "@acme/widget", version: "1.0.0", reason: "security" }, "publish-token");
    assert.ok(ok.status < 300, `expected success, got ${ok.status}`);
  });

  test("POST /-/registry/import without a token → 401; with the token it passes auth (then the claim check applies)", async () => {
    const base = await boot(["publish-token"]);
    assert.equal((await post(base, "/-/registry/import", { name: "leftpad-lite" })).status, 401);
    assert.equal((await post(base, "/-/registry/import", { name: "leftpad-lite" }, "publish-token")).status, 403);
  });

  test("open mode with no publish tokens configured: both routes always 401", async () => {
    const base = await boot([]);
    assert.equal((await post(base, "/-/retractions", { name: "@acme/widget", version: "1.0.0", reason: "security" })).status, 401);
    assert.equal((await post(base, "/-/registry/import", { name: "leftpad-lite" }, "anything")).status, 401);
  });
});
