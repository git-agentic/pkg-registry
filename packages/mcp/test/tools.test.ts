import assert from "node:assert/strict";
import { existsSync, writeFileSync, mkdtempSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
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
import { ProxyClient } from "../src/client.js";
import { TOOLS } from "../src/tools.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

const byName = (n: string) => TOOLS.find((t) => t.name === n)!;

// Auto-quarantine is opt-in AND auth-gated (Task B2 / ADR-0040); mint a real agent token so the
// "quarantined:true after a confirmed violation" test below can actually exercise quarantine.
const { publicKey, privateKey } = generateKeypair();
const agentToken = signToken({ role: "agent", sub: "test", ttlSeconds: 3600 }, privateKey);

describe("MCP tools", () => {
  let server: Server; let client: ProxyClient; let base: string;
  before(async () => {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
      approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
      approvalRequests: new ApprovalRequestStore(),
      authPublicKey: publicKey, autoQuarantine: true,
    });
    await new Promise<void>((r) => {
      server = app.listen(0, () => {
        base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        client = new ProxyClient(base, agentToken);
        r();
      });
    });
  });
  after(() => server?.close());

  test("sentinel_audit surfaces verdict + score for a blocking fixture", async () => {
    const r = await byName("sentinel_audit").handler({ package: "color-stream", version: "1.4.1" }, client);
    const s = r.structured as { verdict: string; quarantined: boolean };
    assert.equal(s.verdict, "block");
    assert.equal(s.quarantined, false);
    assert.match(r.text, /block/i);
  });

  test("sentinel_audit reports quarantined:true after a confirmed violation is recorded", async () => {
    const rep = await client.audit("leftpad-lite", "1.0.0");
    await fetch(`${base}/-/violations`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${agentToken}` },
      body: JSON.stringify({ name: "leftpad-lite", version: "1.0.0", integrity: rep.meta.integrity,
        kind: "filesystem", target: "/x/.ssh/id_rsa", confidence: "confirmed", deniedResource: "/x/.ssh",
        evidence: { exitCode: 1, stderrExcerpt: "EPERM" } }) });
    const r = await byName("sentinel_audit").handler({ package: "leftpad-lite", version: "1.0.0" }, client);
    assert.equal((r.structured as { quarantined: boolean }).quarantined, true);
  });

  test("sentinel_capabilities returns the manifest + approval state", async () => {
    const r = await byName("sentinel_capabilities").handler({ package: "net-fetch-lite", version: "1.0.0" }, client);
    const s = r.structured as { capabilities: unknown[]; approvalState: string };
    assert.ok(Array.isArray(s.capabilities));
    assert.ok(typeof s.approvalState === "string");
  });

  test("sentinel_check_provenance projects provenance status", async () => {
    const r = await byName("sentinel_check_provenance").handler({ package: "leftpad-lite", version: "1.0.0" }, client);
    assert.ok(["verified", "invalid", "absent", "unknown"].includes((r.structured as { provenance: string }).provenance));
  });

  test("sentinel_audit_tree parses a lockfile and returns an aggregate", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-lock-"));
    const lock = join(dir, "package-lock.json");
    writeFileSync(lock, JSON.stringify({ lockfileVersion: 3, packages: {
      "": { name: "root" },
      "node_modules/leftpad-lite": { version: "1.0.0" },
    } }));
    const r = await byName("sentinel_audit_tree").handler({ lockfile: lock }, client);
    assert.ok(["allow", "warn", "block"].includes((r.structured as { verdict: string }).verdict));
  });

  test("sentinel_list_violations returns recorded violations", async () => {
    const r = await byName("sentinel_list_violations").handler({}, client);
    assert.ok(Array.isArray((r.structured as { violations: unknown[] }).violations));
  });

  test("sentinel_explain returns the structured {report, remediation, lastKnownGood} shape", async () => {
    const r = await byName("sentinel_explain").handler({ package: "hijacked-lib", version: "2.0.0" }, client);
    const s = r.structured as { report: { verdict: string }; remediation: { items: unknown[]; guidance: string }; lastKnownGood: { version: string } | null };
    assert.ok(s.report);
    assert.ok(s.remediation);
    assert.ok(s.remediation.items.length > 0);
    assert.ok(s.lastKnownGood && typeof s.lastKnownGood.version === "string");
    assert.match(r.text, /Suggested safe version/);
  });

  test("sentinel_request_approval records a pending request (does NOT approve)", async () => {
    const r = await byName("sentinel_request_approval").handler({ package: "net-fetch-lite", version: "1.0.0", reason: "need fetch" }, client);
    assert.match(r.text, /request/i);
    const list = (await (await fetch(`${base}/-/approval-requests`)).json()) as { requests: unknown[] };
    assert.equal(list.requests.length >= 1, true);
    const approvals = (await (await fetch(`${base}/-/approvals`)).json()) as { approvals: unknown[] };
    assert.equal(approvals.approvals.length, 0);
  });
});
