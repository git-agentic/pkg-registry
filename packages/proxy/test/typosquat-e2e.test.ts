import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type AuditReport, type EnterprisePolicy } from "@sentinel/core";
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
function boot(policy: EnterprisePolicy): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: policy,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(),
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` })); });
}
const report = async (base: string, pkg: string, v: string): Promise<AuditReport> =>
  (await (await fetch(`${base}/-/audit/${pkg}/${v}`)).json()) as AuditReport;

describe("typosquat + dependency-confusion (e2e)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot({ ...DEFAULT_POLICY, privateNamespaces: ["@acme/*"] })); });
  after(() => server?.close());

  test("the typosquat fixture `expres` is flagged (resembles express)", async () => {
    const r = await report(base, "expres", "1.0.0");
    const f = r.findings.find((x) => x.ruleId === "typosquat");
    assert.ok(f, "expected a typosquat finding");
    assert.match(f!.message, /express/);
  });

  test("the negative-control `express` (in corpus) is NOT flagged", async () => {
    const r = await report(base, "express", "1.0.0");
    assert.equal(r.findings.find((x) => x.ruleId === "typosquat"), undefined);
  });
});
