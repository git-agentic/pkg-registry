import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const FIXTURES = join(REPO, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO, "scripts", "make-fixtures.ts")], { cwd: REPO, stdio: "ignore" });
}
function boot(): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(),
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` })); });
}

describe("GET /-/explain (e2e)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot()); });
  after(() => server?.close());

  test("blocked release returns report + remediation + last-known-good earlier version", async () => {
    const r = await (await fetch(`${base}/-/explain/hijacked-lib/2.0.0`)).json() as {
      report: { verdict: string; findings: unknown[] };
      remediation: { items: { ruleId: string }[]; waiver: unknown };
      lastKnownGood: { version: string; score: number } | null;
    };
    assert.notEqual(r.report.verdict, "allow"); // v2 is flagged
    assert.ok(r.remediation.items.length >= 1);
    assert.ok(r.remediation.waiver); // block/warn → waiver present
    assert.equal(r.lastKnownGood?.version, "1.0.0"); // v1 is the clean earlier release
  });

  test("a clean package has no last-known-good need (or itself is fine)", async () => {
    const r = await (await fetch(`${base}/-/explain/leftpad-lite/1.0.0`)).json() as {
      report: { verdict: string }; lastKnownGood: unknown;
    };
    assert.equal(r.report.verdict, "allow");
    // no earlier clean version required; lastKnownGood may be null (no priors) — just assert shape
  });
});
