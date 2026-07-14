import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, generateKeypair, signToken, type AuditReport, type Role } from "@git-agentic/sentinel-core";
import { createServer, type ServerOptions } from "../src/server.js";
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

function boot(extra: Partial<ServerOptions> = {}): Promise<{ server: Server; base: string; violations: ViolationStore; approvals: ApprovalStore }> {
  const violations = new ViolationStore();
  const approvals = new ApprovalStore();
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals, enterprisePolicy: DEFAULT_POLICY, policy: "block",
    privateStore: new PrivatePackageStore(), violations,
    approvalRequests: new ApprovalRequestStore(),
    ...extra,
  });
  return new Promise((r) => {
    const server = app.listen(0, () => r({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, violations, approvals }));
  });
}

async function integrityOf(base: string, pkg: string, version: string): Promise<string> {
  const rep = await (await fetch(`${base}/-/audit/${pkg}/${version}`)).json() as AuditReport;
  return rep.meta.integrity!;
}

// Default posture: no auth, no autoQuarantine — violations are sensed (recorded) but never
// enforced (ADR-0040). Auto-quarantine is opt-in AND auth-gated (Task B2).
describe("runtime violation reporting (default: record-only, no auth)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot()); });
  after(() => server?.close());

  test("a confirmed violation is recorded but does NOT quarantine (auto-quarantine off by default)", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
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
    const body = await post.json() as { recorded: { quarantined: boolean } };
    assert.equal(body.recorded.quarantined, false);

    // Serve is unaffected — no auto-quarantine without an opt-in + verified token.
    assert.equal((await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`)).status, 200);
  });

  test("a suspected violation is recorded but does NOT quarantine", async () => {
    // Capability-free fixture at a DISTINCT integrity from the test above (leftpad-lite@1.0.0):
    // leftpad-lite has no network/filesystem capability, so it serves 200 under block policy
    // with no approval, isolating the "suspected → not quarantined" behavior from the approval gate.
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.1");
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

  test("POST for an un-audited integrity is rejected 400", async () => {
    const res = await fetch(`${base}/-/violations`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "x", version: "1.0.0", integrity: "sha512-UNKNOWN", kind: "filesystem", target: "/a", confidence: "confirmed", deniedResource: "/a", evidence: { exitCode: 1, stderrExcerpt: "" } }),
    });
    assert.equal(res.status, 400);
  });
});

// Opt-in posture: auth enabled + autoQuarantine: true — a confirmed, agent-token-reported
// violation now quarantines and the next serve 403s.
describe("runtime violation quarantine (auth enabled + autoQuarantine: true)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot({ authPublicKey: publicKey, autoQuarantine: true })); });
  after(() => server?.close());

  test("a confirmed violation reported with an agent token quarantines the integrity → next serve 403s with runtime-violation", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    // Serve succeeds before any violation.
    assert.equal((await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`)).status, 200);

    const post = await fetch(`${base}/-/violations`, {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tok("agent")}` },
      body: JSON.stringify({
        name: "leftpad-lite", version: "1.0.0", integrity,
        kind: "filesystem", target: "/home/x/.ssh/id_rsa", confidence: "confirmed",
        deniedResource: "/home/x/.ssh", evidence: { exitCode: 1, stderrExcerpt: "EPERM ..." },
      }),
    });
    assert.equal(post.status, 200);
    const body = await post.json() as { recorded: { quarantined: boolean } };
    assert.equal(body.recorded.quarantined, true);

    const res = await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`);
    assert.equal(res.status, 403);
    const resBody = await res.json() as { findings: { ruleId: string }[] };
    assert.ok(resBody.findings.some((f) => f.ruleId === "runtime-violation"));
  });

  test("DELETE (operator token) clears the quarantine", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const del = await fetch(`${base}/-/violations/${encodeURIComponent(integrity)}`, {
      method: "DELETE", headers: { authorization: `Bearer ${tok("operator")}` },
    });
    assert.equal(del.status, 200);
    assert.equal((await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`)).status, 200);
  });
});
