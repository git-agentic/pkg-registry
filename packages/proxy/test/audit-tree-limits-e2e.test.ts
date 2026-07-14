import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@git-agentic/sentinel-core";
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

/** LocalFixtureUpstream that counts getTarball calls, to prove dedupe. */
class CountingUpstream extends LocalFixtureUpstream {
  tarballCalls = 0;
  async getTarball(pkg: string, version: string) {
    this.tarballCalls++;
    return super.getTarball(pkg, version);
  }
}

function boot(upstream: LocalFixtureUpstream, maxTreePackages?: number): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream, store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(), maxTreePackages,
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` })); });
}

async function auditTree(base: string, packages: { name: string; version: string }[]): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}/-/audit-tree`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ packages }),
  });
  return { status: res.status, body: await res.json() };
}

describe("audit-tree dedupe + cap (ADR-0037)", () => {
  before(() => ensureFixtures());

  test("duplicate coordinates are audited once but returned per-request", async () => {
    const up = new CountingUpstream(FIXTURES);
    const { server, base } = await boot(up);
    try {
      const dupes = Array.from({ length: 5 }, () => ({ name: "leftpad-lite", version: "1.0.0" }));
      const { status, body } = await auditTree(base, dupes);
      assert.equal(status, 200);
      assert.equal(body.packages.length, 5, "one row per requested coordinate");
      assert.equal(up.tarballCalls, 1, "distinct coordinate audited exactly once");
    } finally { server.close(); }
  });

  test("over-cap distinct set returns 413 naming count and limit", async () => {
    const up = new LocalFixtureUpstream(FIXTURES);
    const { server, base } = await boot(up, 2); // cap = 2 distinct
    try {
      const pkgs = [
        { name: "leftpad-lite", version: "1.0.0" },
        { name: "leftpad-lite", version: "1.0.1" },
        { name: "leftpad-lite", version: "1.0.2" },
      ];
      const { status, body } = await auditTree(base, pkgs);
      assert.equal(status, 413);
      assert.match(body.error, /3.*(exceeds|limit).*2/);
    } finally { server.close(); }
  });

  test("duplicates collapse below the cap (5 dupes of 1 distinct, cap 2 → ok)", async () => {
    const up = new LocalFixtureUpstream(FIXTURES);
    const { server, base } = await boot(up, 2);
    try {
      const dupes = Array.from({ length: 5 }, () => ({ name: "leftpad-lite", version: "1.0.0" }));
      const { status } = await auditTree(base, dupes);
      assert.equal(status, 200, "5 dupes = 1 distinct, under the cap of 2");
    } finally { server.close(); }
  });
});
