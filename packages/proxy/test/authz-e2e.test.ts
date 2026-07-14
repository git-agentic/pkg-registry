import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, generateKeypair, signToken, type AuditReport, type Role } from "@agentic-sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

const { publicKey, privateKey } = generateKeypair();
const tok = (role: Role) => signToken({ role, sub: "test", ttlSeconds: 3600 }, privateKey);

function boot(authPublicKey?: string): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY, policy: "block",
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(), authPublicKey,
  });
  return new Promise((r) => { const server = app.listen(0, () => r({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` })); });
}
async function integrityOf(base: string, pkg: string, v: string): Promise<string> {
  return ((await (await fetch(`${base}/-/audit/${pkg}/${v}`)).json()) as AuditReport).meta.integrity!;
}

describe("control-plane auth (enabled)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot(publicKey)); });
  after(() => server?.close());

  test("reads stay open with no token", async () => {
    assert.equal((await fetch(`${base}/-/audit/leftpad-lite/1.0.0`)).status, 200);
  });

  test("POST /-/approvals with no token → 401", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/approvals`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ integrity, decision: "approved" }) });
    assert.equal(res.status, 401);
  });

  test("POST /-/approvals with an operator token → 200", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/approvals`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tok("operator")}` }, body: JSON.stringify({ integrity, decision: "approved" }) });
    assert.equal(res.status, 200);
  });

  test("POST /-/approvals with an AGENT token → 403 (Phase 11 boundary enforced)", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/approvals`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tok("agent")}` }, body: JSON.stringify({ integrity, decision: "approved" }) });
    assert.equal(res.status, 403);
  });

  test("POST /-/approval-requests with an agent token → 200", async () => {
    const integrity = await integrityOf(base, "net-fetch-lite", "1.0.0");
    const res = await fetch(`${base}/-/approval-requests`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tok("agent")}` }, body: JSON.stringify({ name: "net-fetch-lite", version: "1.0.0", integrity, reason: "x" }) });
    assert.equal(res.status, 200);
  });

  test("POST /-/violations with an agent token → 200", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/violations`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tok("agent")}` }, body: JSON.stringify({ name: "leftpad-lite", version: "1.0.0", integrity, kind: "network", target: null, confidence: "suspected", deniedResource: null, evidence: { exitCode: 1, stderrExcerpt: "x" } }) });
    assert.equal(res.status, 200);
  });

  test("DELETE /-/violations with an agent token → 403 (clear is operator-only)", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/violations/${encodeURIComponent(integrity)}`, { method: "DELETE", headers: { authorization: `Bearer ${tok("agent")}` } });
    assert.equal(res.status, 403);
  });

  test("an expired operator token → 401", async () => {
    const expired = signToken({ role: "operator", sub: "x", ttlSeconds: 60 }, privateKey, 1000); // exp=1060, long past
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/approvals`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${expired}` }, body: JSON.stringify({ integrity, decision: "approved" }) });
    assert.equal(res.status, 401);
  });
});

describe("control-plane auth (disabled / open mode)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot(undefined)); });
  after(() => server?.close());

  test("mutations succeed with NO token when auth is disabled (backward compat)", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/approvals`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ integrity, decision: "approved" }) });
    assert.equal(res.status, 200);
  });
});
