import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type TreeAuditResult } from "@sentinel/core";
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
const tree = async (base: string, packages: unknown[], failOnError?: boolean): Promise<TreeAuditResult> =>
  (await (await fetch(`${base}/-/audit-tree`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages, failOnError }) })).json()) as TreeAuditResult;

describe("audit-tree integrity cross-check + failOnError (e2e)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot()); });
  after(() => server?.close());

  test("a claimed integrity that differs from the served hash blocks the row", async () => {
    const r = await tree(base, [{ name: "leftpad-lite", version: "1.0.0", integrity: "sha512-BOGUS==" }]);
    const row = r.packages.find((p) => p.name === "leftpad-lite")!;
    assert.equal(row.integrityMismatch, true);
    assert.equal(row.status, "block");
    assert.equal(r.aggregate.integrityMismatch, 1);
  });

  test("a coordinate with no integrity is not cross-checked", async () => {
    const r = await tree(base, [{ name: "leftpad-lite", version: "1.0.0" }]);
    assert.equal(r.packages.find((p) => p.name === "leftpad-lite")!.integrityMismatch, false);
  });

  test("failOnError gates a tree containing an unresolvable package", async () => {
    const open = await tree(base, [{ name: "does-not-exist", version: "9.9.9" }]);
    assert.equal(open.aggregate.gated, false); // default fail-open
    const closed = await tree(base, [{ name: "does-not-exist", version: "9.9.9" }], true);
    assert.equal(closed.aggregate.gated, true);
  });
});
