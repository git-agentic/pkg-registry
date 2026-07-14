import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { parsePolicy } from "@git-agentic/sentinel-core";
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
async function tarballUrl(base: string, pkg: string, version: string): Promise<string> {
  const doc = await (await fetch(`${base}/${pkg}`)).json();
  return doc.versions[version].dist.tarball as string;
}

// leftpad-lite@1.0.1 carries a fixed `time` in the fixture registry (fixtures/index.json).
const cooldownPolicy = (exempt?: string[]) => parsePolicy(Buffer.from(JSON.stringify({
  schema: 1, version: "cd",
  scoring: { severityWeight: { info: 0, low: 4, medium: 12, high: 25, critical: 55 }, diffMultiplier: 1.6, thresholds: { allow: 80, warn: 50 }, hardBlockSeverity: "critical" },
  releaseCooldown: { hours: 72, ...(exempt ? { exempt } : {}) },
})));

function startServer(opts: { policy: "block" | "observe"; enterprisePolicy: any; now: () => number }): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: opts.enterprisePolicy, policy: opts.policy, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(), now: opts.now,
  });
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }));
  });
}
const inWindow = () => Date.parse("2026-07-11T00:00:00Z");   // 24h after publish, < 72h cooldown
const pastWindow = () => Date.parse("2026-07-20T00:00:00Z"); // 10 days after publish

describe("release-cooldown e2e", () => {
  before(() => ensureFixtures());

  test("block policy + fresh version → 403 block with release-cooldown finding", async () => {
    const { server, base } = await startServer({ policy: "block", enterprisePolicy: cooldownPolicy(), now: inWindow });
    try {
      const res = await fetch(await tarballUrl(base, "leftpad-lite", "1.0.1"));
      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.verdict, "block");
      assert.ok(body.findings.some((f: any) => f.ruleId === "release-cooldown"));
    } finally { server.close(); }
  });

  test("observe policy + fresh → 200 served, header verdict block", async () => {
    const { server, base } = await startServer({ policy: "observe", enterprisePolicy: cooldownPolicy(), now: inWindow });
    try {
      const res = await fetch(await tarballUrl(base, "leftpad-lite", "1.0.1"));
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("x-sentinel-verdict"), "block");
    } finally { server.close(); }
  });

  test("preflight /-/audit matches the gate (no allow when tarball will block)", async () => {
    const { server, base } = await startServer({ policy: "block", enterprisePolicy: cooldownPolicy(), now: inWindow });
    try {
      const rep = await (await fetch(`${base}/-/audit/leftpad-lite/1.0.1`)).json();
      assert.equal(rep.verdict, "block");
    } finally { server.close(); }
  });

  test("past the window → served allow, no cooldown finding (cached score untouched)", async () => {
    const { server, base } = await startServer({ policy: "block", enterprisePolicy: cooldownPolicy(), now: pastWindow });
    try {
      const res = await fetch(await tarballUrl(base, "leftpad-lite", "1.0.1"));
      assert.equal(res.status, 200);
    } finally { server.close(); }
  });

  test("preflight /-/manifest matches the gate (no allow when tarball will block)", async () => {
    const { server, base } = await startServer({ policy: "block", enterprisePolicy: cooldownPolicy(), now: inWindow });
    try {
      const body = await (await fetch(`${base}/-/manifest/leftpad-lite/1.0.1`)).json();
      assert.equal(body.verdict, "block");
      assert.ok(body.findings.some((f: any) => f.ruleId === "release-cooldown"));
    } finally { server.close(); }
  });

  test("preflight /-/manifest past the window → normal verdict", async () => {
    const { server, base } = await startServer({ policy: "block", enterprisePolicy: cooldownPolicy(), now: pastWindow });
    try {
      const body = await (await fetch(`${base}/-/manifest/leftpad-lite/1.0.1`)).json();
      assert.notEqual(body.verdict, "block");
      assert.ok(!body.findings.some((f: any) => f.ruleId === "release-cooldown"));
    } finally { server.close(); }
  });

  test("exempt pattern bypasses even when fresh", async () => {
    const { server, base } = await startServer({ policy: "block", enterprisePolicy: cooldownPolicy(["leftpad-lite"]), now: inWindow });
    try {
      const res = await fetch(await tarballUrl(base, "leftpad-lite", "1.0.1"));
      assert.equal(res.status, 200);
    } finally { server.close(); }
  });

  // leftpad-lite@1.0.0 has no `time` entry in the fixture registry, so its
  // publish time resolves to null → cooldownDecision fails closed (blocks it)
  // regardless of the injected clock. findLastKnownGood must apply the same
  // cooldown overlay it applies everywhere else, or it will recommend
  // downgrading to a version the gate would 403 on cooldown grounds.
  test("/-/explain lastKnownGood never recommends a version blocked by cooldown", async () => {
    const { server, base } = await startServer({ policy: "block", enterprisePolicy: cooldownPolicy(), now: inWindow });
    try {
      const body = await (await fetch(`${base}/-/explain/leftpad-lite/1.0.1`)).json();
      // The only strictly-older version (1.0.0) fails the cooldown closed —
      // there is no version lastKnownGood can safely recommend.
      assert.equal(body.lastKnownGood, null);
    } finally { server.close(); }
  });
});
