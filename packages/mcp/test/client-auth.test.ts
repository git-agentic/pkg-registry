import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, generateKeypair, signToken } from "@sentinel/core";
import { createServer } from "../../proxy/src/server.js";
import { AuditStore } from "../../proxy/src/store.js";
import { LocalFixtureUpstream } from "../../proxy/src/upstream.js";
import { ApprovalStore } from "../../proxy/src/approvals.js";
import { PrivatePackageStore } from "../../proxy/src/private-store.js";
import { ViolationStore } from "../../proxy/src/violations.js";
import { ApprovalRequestStore } from "../../proxy/src/approval-requests.js";
import { ProxyClient, ProxyError } from "../src/client.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

const { publicKey, privateKey } = generateKeypair();

describe("ProxyClient auth", () => {
  let server: Server; let base: string;
  before(async () => {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
      approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
      approvalRequests: new ApprovalRequestStore(), authPublicKey: publicKey,
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  test("with an agent token, a request_approval POST is authorized", async () => {
    const client = new ProxyClient(base, signToken({ role: "agent", sub: "mcp", ttlSeconds: 3600 }, privateKey));
    const rep = await client.audit("net-fetch-lite", "1.0.0");
    await assert.doesNotReject(client.approvalRequest({ name: "net-fetch-lite", version: "1.0.0", integrity: rep.meta.integrity!, reason: "x" }));
  });

  test("with NO token against an auth-enabled proxy, a POST throws ProxyError (401), not a fake success", async () => {
    const client = new ProxyClient(base); // no token
    const rep = await client.audit("net-fetch-lite", "1.0.0");
    await assert.rejects(() => client.approvalRequest({ name: "net-fetch-lite", version: "1.0.0", integrity: rep.meta.integrity!, reason: "x" }), (e) => e instanceof ProxyError && e.status === 401);
  });

  test("reads work with no token (open reads)", async () => {
    const client = new ProxyClient(base);
    assert.equal((await client.audit("leftpad-lite", "1.0.0")).verdict, "allow");
  });
});
