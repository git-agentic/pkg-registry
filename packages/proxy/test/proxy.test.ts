import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type EnterprisePolicy } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], {
    cwd: REPO_ROOT,
    stdio: "ignore",
  });
}

describe("registry proxy (block policy, local fixtures)", () => {
  let server: Server;
  let base: string;
  let approvals: ApprovalStore;

  before(async () => {
    ensureFixtures();
    approvals = new ApprovalStore();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals,
      enterprisePolicy: DEFAULT_POLICY,
      policy: "block",
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const { port } = server.address() as AddressInfo;
        base = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(() => server?.close());

  test("health reports the upstream and policy", async () => {
    const h = await (await fetch(`${base}/-/health`)).json();
    assert.equal(h.ok, true);
    assert.equal(h.upstream, "local-fixtures");
    assert.equal(h.policy, "block");
  });

  test("packument is served with tarball URLs rewritten to the proxy", async () => {
    const doc = await (await fetch(`${base}/color-stream`)).json();
    assert.ok(doc.versions["1.4.1"], "packument lists versions");
    const url: string = doc.versions["1.4.1"].dist.tarball;
    assert.ok(url.startsWith(base), `tarball URL should point at the proxy, got ${url}`);
    assert.ok(url.endsWith("/color-stream/-/color-stream-1.4.1.tgz"));
  });

  test("audit API allows the clean version", async () => {
    const r = await (await fetch(`${base}/-/audit/color-stream/1.4.0`)).json();
    assert.equal(r.verdict, "allow");
    assert.equal(r.score, 100);
  });

  test("audit API blocks the malicious version", async () => {
    const r = await (await fetch(`${base}/-/audit/color-stream/1.4.1`)).json();
    assert.equal(r.verdict, "block");
    assert.ok(r.findings.length >= 4);
  });

  test("benign tarball is served with verdict headers", async () => {
    const res = await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.1.tgz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-sentinel-verdict"), "allow");
    assert.equal(res.headers.get("content-type"), "application/octet-stream");
    const body = Buffer.from(await res.arrayBuffer());
    assert.ok(body.length > 0, "tarball bytes are streamed through");
  });

  test("malicious tarball is BLOCKED with 403 under block policy", async () => {
    const res = await fetch(`${base}/color-stream/-/color-stream-1.4.1.tgz`);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-sentinel-verdict"), "block");
    const body = await res.json();
    assert.match(body.error, /blocked by Sentinel/i);
    assert.ok(body.findings.length >= 4, "403 body explains why");
  });

  test("audit log accumulates stats", async () => {
    const data = await (await fetch(`${base}/-/audits`)).json();
    assert.ok(data.stats.total >= 2);
    assert.ok(data.stats.block >= 1);
    assert.ok(Array.isArray(data.audits));
  });
});

describe("approval gate (block policy, local fixtures)", () => {
  let server: Server;
  let base: string;
  let approvals: ApprovalStore;

  before(async () => {
    ensureFixtures();
    approvals = new ApprovalStore();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals,
      enterprisePolicy: DEFAULT_POLICY,
      policy: "block",
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        resolve();
      });
    });
  });
  after(() => server?.close());

  async function manifest(pkg: string, version: string) {
    return (await fetch(`${base}/-/manifest/${pkg}/${version}`)).json();
  }
  async function approve(m: { name: string; version: string; integrity: string }) {
    return fetch(`${base}/-/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...m, decision: "approved", actor: { type: "agent", id: "test" } }),
    });
  }

  test("manifest reports capabilities and 'required' at first sight", async () => {
    const m = await manifest("net-fetch-lite", "1.0.0");
    assert.equal(m.verdict, "allow");
    assert.equal(m.approvalState, "required");
    assert.ok(m.approvalRequired.some((c: { target: string }) => c.target === "api.example.com"));
  });

  test("tarball is gated with 403 'approval required' before approval", async () => {
    const res = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.0.tgz`);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-sentinel-approval"), "required");
    assert.match((await res.json()).error, /approval required/i);
  });

  test("after approval the tarball serves", async () => {
    const m = await manifest("net-fetch-lite", "1.0.0");
    const r = await approve({ name: "net-fetch-lite", version: "1.0.0", integrity: m.meta.integrity });
    assert.equal(r.status, 200);
    const res = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.0.tgz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-sentinel-approval"), "approved");
  });

  test("a later version with the same capabilities is inherited (served, no prompt)", async () => {
    const m = await manifest("net-fetch-lite", "1.0.1");
    assert.equal(m.approvalState, "inherited");
    const res = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.1.tgz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-sentinel-approval"), "inherited");
  });

  test("a new capability atom re-gates the install", async () => {
    const m = await manifest("net-fetch-lite", "1.0.2");
    assert.equal(m.approvalState, "required");
    assert.ok(m.approvalRequired.some((c: { target: string }) => c.target === "telemetry.example.com"));
    const res = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.2.tgz`);
    assert.equal(res.status, 403);
  });

  test("revoke removes the approval", async () => {
    const m = await manifest("net-fetch-lite", "1.0.0");
    const del = await fetch(`${base}/-/approvals/${encodeURIComponent(m.meta.integrity)}`, { method: "DELETE" });
    assert.equal((await del.json()).revoked, true);
    const res = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.0.tgz`);
    assert.equal(res.status, 403);
  });

  test("malicious color-stream is blocked for the VERDICT reason, not approval", async () => {
    // Pre-approve its capabilities so an approval-required 403 cannot mask the verdict.
    const m = await manifest("color-stream", "1.4.1");
    await fetch(`${base}/-/approvals`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "color-stream", version: "1.4.1", integrity: m.meta.integrity, decision: "approved", actor: { type: "agent", id: "test" } }),
    });
    const res = await fetch(`${base}/color-stream/-/color-stream-1.4.1.tgz`);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-sentinel-verdict"), "block");
    assert.match((await res.json()).error, /blocked by Sentinel/i);
  });

  test("GET /-/approvals lists a recorded approval", async () => {
    // Approve 1.0.2 via API (note: 1.0.0 was revoked in a prior test so store only has
    // color-stream approved; we approve 1.0.2 fresh here)
    const m = await manifest("net-fetch-lite", "1.0.2");
    const postRes = await fetch(`${base}/-/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "net-fetch-lite", version: "1.0.2", integrity: m.meta.integrity, decision: "approved", actor: { type: "agent", id: "test" } }),
    });
    assert.equal(postRes.status, 200);
    const listed = await (await fetch(`${base}/-/approvals`)).json() as { approvals: Array<{ integrity: string; decision: string }> };
    assert.ok(listed.approvals.some((a) => a.integrity === m.meta.integrity && a.decision === "approved"),
      "GET /-/approvals must list the recorded approval");
  });

  test("POST array body approves multiple entries", async () => {
    const m100 = await manifest("net-fetch-lite", "1.0.0");
    const m101 = await manifest("net-fetch-lite", "1.0.1");
    const postRes = await fetch(`${base}/-/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify([
        { name: "net-fetch-lite", version: "1.0.0", integrity: m100.meta.integrity, decision: "approved", actor: { type: "agent", id: "test" } },
        { name: "net-fetch-lite", version: "1.0.1", integrity: m101.meta.integrity, decision: "approved", actor: { type: "agent", id: "test" } },
      ]),
    });
    assert.equal(postRes.status, 200);
    const body = await postRes.json() as { approvals: unknown[] };
    assert.equal(body.approvals.length, 2, "array POST must return 2 recorded approvals");
    // Confirm both are now approved
    const t100 = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.0.tgz`);
    assert.equal(t100.status, 200, "1.0.0 must be served after array approval");
    const t101 = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.1.tgz`);
    assert.equal(t101.status, 200, "1.0.1 must be served after array approval");
  });

  test("server-authoritative identity: bogus name in body is ignored", async () => {
    const m = await manifest("net-fetch-lite", "1.0.0");
    // Submit with a wrong package name but correct integrity
    const postRes = await fetch(`${base}/-/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "totally-wrong", version: "1.0.0", integrity: m.meta.integrity, decision: "approved", actor: { type: "agent", id: "test" } }),
    });
    assert.equal(postRes.status, 200);
    const listed = await (await fetch(`${base}/-/approvals`)).json() as { approvals: Array<{ integrity: string; name: string }> };
    const recorded = listed.approvals.find((a) => a.integrity === m.meta.integrity);
    assert.ok(recorded, "approval must be stored");
    assert.equal(recorded!.name, "net-fetch-lite", `stored name must be the audited name, got: ${recorded!.name}`);
  });
});

describe("approval gate — no forward inheritance (isolated server)", () => {
  let server: Server;
  let base: string;

  before(async () => {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals: new ApprovalStore(),
      enterprisePolicy: DEFAULT_POLICY,
      policy: "block",
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        resolve();
      });
    });
  });
  after(() => server?.close());

  async function manifest(pkg: string, version: string) {
    return (await fetch(`${base}/-/manifest/${pkg}/${version}`)).json();
  }

  test("approving 1.0.2 does NOT grant forward inheritance to 1.0.0", async () => {
    // Approve the NEWER version (1.0.2) first
    const m102 = await manifest("net-fetch-lite", "1.0.2");
    const postRes = await fetch(`${base}/-/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "net-fetch-lite", version: "1.0.2", integrity: m102.meta.integrity, decision: "approved", actor: { type: "agent", id: "test" } }),
    });
    assert.equal(postRes.status, 200);

    // 1.0.0 is OLDER — must not inherit from 1.0.2
    const m100 = await manifest("net-fetch-lite", "1.0.0");
    assert.equal(m100.approvalState, "required",
      "1.0.0 must still require approval — no forward inheritance from 1.0.2");

    const tarball = await fetch(`${base}/net-fetch-lite/-/net-fetch-lite-1.0.0.tgz`);
    assert.equal(tarball.status, 403, "tarball for 1.0.0 must be gated (no forward inheritance)");
    assert.equal(tarball.headers.get("x-sentinel-approval"), "required");
  });
});

describe("enterprise policy scoring (block policy, local fixtures)", () => {
  let server: Server;
  let base: string;

  function policy(over: Partial<EnterprisePolicy>): EnterprisePolicy {
    return { ...DEFAULT_POLICY, version: "test", ...over };
  }

  async function startWith(enterprisePolicy: EnterprisePolicy): Promise<void> {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals: new ApprovalStore(),
      enterprisePolicy,
      policy: "block",
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        resolve();
      });
    });
  }
  after(() => server?.close());

  test("a deny entry blocks an otherwise-clean package and stamps the policy header", async () => {
    await startWith(policy({ version: "denypol", deny: [{ package: "leftpad-lite", reason: "blocked" }] }));
    const res = await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.1.tgz`);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-sentinel-verdict"), "block");
    assert.equal(res.headers.get("x-sentinel-policy"), "denypol");
  });

  test("an allow waiver serves an otherwise-blocked package", async () => {
    await startWith(policy({
      allow: [{ package: "color-stream", rules: ["secret-exfil", "install-scripts", "network-egress", "obfuscation"], reason: "test" }],
    }));
    // Pre-approve capabilities so the approval gate doesn't block (mirroring the
    // "verdict reason, not approval" sibling test). The waiver flips the verdict
    // block→allow; the approval gate is a separate, orthogonal check.
    const m = await (await fetch(`${base}/-/manifest/color-stream/1.4.1`)).json();
    await fetch(`${base}/-/approvals`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "color-stream", version: "1.4.1", integrity: m.meta.integrity, decision: "approved", actor: { type: "agent", id: "test" } }),
    });
    const res = await fetch(`${base}/color-stream/-/color-stream-1.4.1.tgz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-sentinel-verdict"), "allow");
  });
});
