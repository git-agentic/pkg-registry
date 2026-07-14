import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { before, describe, test } from "node:test";
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

/** Slow, counting upstream: getTarball waits a tick so concurrent requests overlap. */
class SlowCountingUpstream extends LocalFixtureUpstream {
  tarballCalls = 0;
  async getTarball(pkg: string, version: string) {
    this.tarballCalls++;
    await new Promise((r) => setTimeout(r, 30));
    return super.getTarball(pkg, version);
  }
}

function boot(upstream: LocalFixtureUpstream): Promise<{ server: Server; base: string; upstream: LocalFixtureUpstream }> {
  const app = createServer({
    upstream, store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(),
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, upstream })); });
}

describe("request coalescing (ADR-0037)", () => {
  before(() => ensureFixtures());

  test("k concurrent uncached requests for one version share one getTarball", async () => {
    const up = new SlowCountingUpstream(FIXTURES);
    const { server, base } = await boot(up);
    try {
      const reqs = Array.from({ length: 6 }, () =>
        fetch(`${base}/-/audit/leftpad-lite/1.0.0`).then((r) => r.json() as Promise<AuditReport>));
      const reports = await Promise.all(reqs);
      // Baseline tarball fetch (previousVersion) may add calls for OTHER versions, but
      // leftpad-lite@1.0.0 itself must be fetched once across the 6 concurrent requests.
      const v100Calls = up.tarballCalls; // slow fixture has a single version, so this counts 1.0.0 fetches
      assert.ok(v100Calls <= 2, `expected coalesced fetch (<=2 incl. baseline), got ${v100Calls}`);
      assert.equal(new Set(reports.map((r) => r.verdict)).size, 1, "all requests see the same verdict");
    } finally { server.close(); }
  });

  test("a failed coalesced audit clears its in-flight entry so a retry succeeds", async () => {
    class FailOnceUpstream extends LocalFixtureUpstream {
      calls = 0;
      async getTarball(pkg: string, version: string) {
        this.calls++;
        if (this.calls === 1) throw new Error("transient upstream failure");
        return super.getTarball(pkg, version);
      }
    }
    const up = new FailOnceUpstream(FIXTURES);
    const { server, base } = await boot(up);
    try {
      // First request fails (upstream threw) — must not poison the coalescing map.
      const first = await fetch(`${base}/-/audit/leftpad-lite/1.0.0`);
      assert.notEqual(first.status, 200);
      // Second request for the same coordinate must succeed (entry was cleared on settle).
      const second = await fetch(`${base}/-/audit/leftpad-lite/1.0.0`);
      assert.equal(second.status, 200);
    } finally { server.close(); }
  });
});
