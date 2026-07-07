import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type AuditReport } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

describe("runtime violation reporting + quarantine (e2e)", () => {
  let server: Server; let base: string; let violations: ViolationStore; let approvals: ApprovalStore;
  before(async () => {
    ensureFixtures();
    violations = new ViolationStore();
    approvals = new ApprovalStore();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
      approvals, enterprisePolicy: DEFAULT_POLICY, policy: "block",
      privateStore: new PrivatePackageStore(), violations,
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  async function integrityOf(pkg: string, version: string): Promise<string> {
    const rep = await (await fetch(`${base}/-/audit/${pkg}/${version}`)).json() as AuditReport;
    return rep.meta.integrity!;
  }

  test("a confirmed violation quarantines the integrity → next serve 403s with runtime-violation", async () => {
    const integrity = await integrityOf("leftpad-lite", "1.0.0");
    // Serve succeeds before any violation.
    assert.equal((await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`)).status, 200);

    const post = await fetch(`${base}/-/violations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "leftpad-lite", version: "1.0.0", integrity,
        kind: "filesystem", target: "/home/x/.ssh/id_rsa", confidence: "confirmed",
        deniedResource: "/home/x/.ssh", evidence: { exitCode: 1, stderrExcerpt: "EPERM ..." },
      }),
    });
    assert.equal(post.status, 200);

    const res = await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`);
    assert.equal(res.status, 403);
    const body = await res.json() as { findings: { ruleId: string }[] };
    assert.ok(body.findings.some((f) => f.ruleId === "runtime-violation"));
  });

  test("a suspected violation is recorded but does NOT quarantine", async () => {
    // Capability-free fixture at a DISTINCT integrity from test 1 (leftpad-lite@1.0.0):
    // leftpad-lite has no network/filesystem capability, so it serves 200 under block policy
    // with no approval, isolating the "suspected → not quarantined" behavior from the approval gate.
    const integrity = await integrityOf("leftpad-lite", "1.0.1");
    await fetch(`${base}/-/violations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "leftpad-lite", version: "1.0.1", integrity,
        kind: "network", target: null, confidence: "suspected",
        deniedResource: null, evidence: { exitCode: 1, stderrExcerpt: "connect EPERM" },
      }),
    });
    assert.equal((await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.1.tgz`)).status, 200);
  });

  test("DELETE clears the quarantine", async () => {
    const integrity = await integrityOf("leftpad-lite", "1.0.0");
    await fetch(`${base}/-/violations/${encodeURIComponent(integrity)}`, { method: "DELETE" });
    assert.equal((await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`)).status, 200);
  });

  test("POST for an un-audited integrity is rejected 400", async () => {
    const res = await fetch(`${base}/-/violations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "x", version: "1.0.0", integrity: "sha512-UNKNOWN", kind: "filesystem", target: "/a", confidence: "confirmed", deniedResource: "/a", evidence: { exitCode: 1, stderrExcerpt: "" } }),
    });
    assert.equal(res.status, 400);
  });
});
