import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@git-agentic/sentinel-core";
import { createServer } from "../src/server.js";
import { createRateLimiter } from "../src/rate-limit.js";
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

function boot(rpm?: number): Promise<{ server: Server; base: string }> {
  const rateLimiter = rpm ? createRateLimiter({ rpm, now: () => Date.now() }) : undefined;
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(), rateLimiter,
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` })); });
}

const auditTree = (base: string) => fetch(`${base}/-/audit-tree`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ packages: [{ name: "leftpad-lite", version: "1.0.0" }] }),
});

describe("rate limiting on expensive endpoints (ADR-0037)", () => {
  before(() => ensureFixtures());

  test("audit-tree 429s past the limit with Retry-After", async () => {
    const { server, base } = await boot(3);
    try {
      for (let i = 0; i < 3; i++) assert.equal((await auditTree(base)).status, 200);
      const limited = await auditTree(base);
      assert.equal(limited.status, 429);
      assert.ok(Number(limited.headers.get("retry-after")) >= 1);
    } finally { server.close(); }
  });

  test("no limiter ⇒ unlimited (no 429)", async () => {
    const { server, base } = await boot();
    try {
      for (let i = 0; i < 10; i++) assert.equal((await auditTree(base)).status, 200);
    } finally { server.close(); }
  });

  test("install-gate tarball path is never rate-limited", async () => {
    const { server, base } = await boot(1); // rpm=1: audit-tree would 429 on the 2nd call
    try {
      // Many tarball fetches must all succeed regardless of the tiny limit.
      for (let i = 0; i < 5; i++) {
        const res = await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`);
        assert.equal(res.status, 200, "tarball gate path must not be rate-limited");
      }
    } finally { server.close(); }
  });
});
