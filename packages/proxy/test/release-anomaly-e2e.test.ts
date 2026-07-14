import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type AuditReport } from "@agentic-sentinel/core";
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
function boot(): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(),
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` })); });
}
const audit = async (base: string, pkg: string, version: string): Promise<AuditReport> =>
  (await (await fetch(`${base}/-/audit/${pkg}/${version}`)).json()) as AuditReport;

describe("release-anomaly + capability-novelty signals (e2e, Phase 16 Task 4)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot()); });
  after(() => server?.close());

  test("steady-lib@2.0.0: same maintainer, small gap — no release-anomaly/capability-novelty finding", async () => {
    const r = await audit(base, "steady-lib", "2.0.0");
    const ruleIds = r.findings.map((f) => f.ruleId);
    assert.ok(!ruleIds.includes("release-anomaly"), `unexpected release-anomaly finding: ${JSON.stringify(r.findings)}`);
    assert.ok(!ruleIds.includes("capability-novelty"), `unexpected capability-novelty finding: ${JSON.stringify(r.findings)}`);
    assert.equal(r.verdict, "allow");
  });

  test("hijacked-lib@1.0.0 (pre-takeover): benign, allow", async () => {
    const r = await audit(base, "hijacked-lib", "1.0.0");
    assert.equal(r.verdict, "allow");
  });

  test("hijacked-lib@2.0.0: maintainer-change + capability-novelty fire, verdict elevated over 1.0.0", async () => {
    const before_ = await audit(base, "hijacked-lib", "1.0.0");
    const r = await audit(base, "hijacked-lib", "2.0.0");
    const ruleIds = r.findings.map((f) => f.ruleId);
    assert.ok(ruleIds.includes("release-anomaly"), `expected a release-anomaly (maintainer-change) finding: ${JSON.stringify(r.findings)}`);
    assert.ok(ruleIds.includes("capability-novelty"), `expected a capability-novelty finding: ${JSON.stringify(r.findings)}`);
    const takeover = r.findings.find((f) => f.ruleId === "release-anomaly" && f.severity === "high");
    assert.ok(takeover, `expected a high-severity maintainer-takeover finding: ${JSON.stringify(r.findings)}`);
    assert.ok(["warn", "block"].includes(r.verdict), `expected an elevated verdict, got ${r.verdict}`);
    assert.notEqual(r.verdict, before_.verdict);
  });

  test("freshdrop@1.0.0: first version with an install script — new-package-risk (release-anomaly) fires", async () => {
    const r = await audit(base, "freshdrop", "1.0.0");
    const finding = r.findings.find((f) => f.ruleId === "release-anomaly");
    assert.ok(finding, `expected a release-anomaly (new-package-risk) finding: ${JSON.stringify(r.findings)}`);
  });

  test("the pre-existing malicious fixture (color-stream@1.4.1) still blocks", async () => {
    const r = await audit(base, "color-stream", "1.4.1");
    assert.equal(r.verdict, "block");
  });
});
