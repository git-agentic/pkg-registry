import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type Advisory, type AuditReport } from "@agentic-sentinel/core";
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

function boot(advisories?: Advisory[]): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(), advisories,
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` })); });
}

const auditOf = async (base: string, name: string, version: string): Promise<AuditReport> =>
  (await (await fetch(`${base}/-/audit/${name}/${version}`)).json()) as AuditReport;

describe("SENTINEL_ADVISORIES threaded into the audit (e2e)", () => {
  before(() => ensureFixtures());

  test("a benign fixture named in an operator advisory blocks by identity", async () => {
    const advisories: Advisory[] = [
      { name: "leftpad-lite", version: "1.0.0", id: "MAL-TEST-9", reference: "http://example.test" },
    ];
    const { server, base } = await boot(advisories);
    try {
      const report = await auditOf(base, "leftpad-lite", "1.0.0");
      assert.equal(report.verdict, "block");
      assert.ok(report.findings.some((f) => f.ruleId === "known-advisory" && f.message.includes("MAL-TEST-9")));
    } finally {
      server.close();
    }
  });

  test("without advisories, the same package audits allow (inert by default)", async () => {
    const { server, base } = await boot();
    try {
      const report = await auditOf(base, "leftpad-lite", "1.0.0");
      assert.equal(report.verdict, "allow");
      assert.ok(!report.findings.some((f) => f.ruleId === "known-advisory"));
    } finally {
      server.close();
    }
  });

  test("the pre-existing malicious fixture still blocks", async () => {
    const { server, base } = await boot();
    try {
      const report = await auditOf(base, "color-stream", "1.4.1");
      assert.equal(report.verdict, "block");
    } finally {
      server.close();
    }
  });
});
