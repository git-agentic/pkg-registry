import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type AuditReport } from "@git-agentic/sentinel-core";
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

describe("approval-requests (e2e)", () => {
  let server: Server; let base: string;
  before(async () => {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
      approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
      approvalRequests: new ApprovalRequestStore(),
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  async function integrityOf(pkg: string, v: string): Promise<string> {
    return ((await (await fetch(`${base}/-/audit/${pkg}/${v}`)).json()) as AuditReport).meta.integrity!;
  }

  test("a request for an audited integrity is recorded and listed", async () => {
    const integrity = await integrityOf("net-fetch-lite", "1.0.0");
    const res = await fetch(`${base}/-/approval-requests`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "net-fetch-lite", version: "1.0.0", integrity, reason: "need fetch" }),
    });
    assert.equal(res.status, 200);
    const list = (await (await fetch(`${base}/-/approval-requests`)).json()) as { requests: { integrity: string; requestedBy: { type: string } }[] };
    assert.ok(list.requests.some((r) => r.integrity === integrity));
    assert.equal(list.requests.find((r) => r.integrity === integrity)?.requestedBy.type, "agent");
  });

  test("a request for an un-audited integrity is 400", async () => {
    const res = await fetch(`${base}/-/approval-requests`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "x", version: "1.0.0", integrity: "sha512-UNKNOWN", reason: "y" }),
    });
    assert.equal(res.status, 400);
  });

  test("recording an approval decision clears the matching pending request", async () => {
    const integrity = await integrityOf("net-fetch-lite", "1.0.0");
    await fetch(`${base}/-/approval-requests`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "net-fetch-lite", version: "1.0.0", integrity, reason: "need fetch" }),
    });
    await fetch(`${base}/-/approvals`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ integrity, decision: "approved" }),
    });
    const list = (await (await fetch(`${base}/-/approval-requests`)).json()) as { requests: { integrity: string }[] };
    assert.ok(!list.requests.some((r) => r.integrity === integrity), "the pending request must be cleared");
  });
});
