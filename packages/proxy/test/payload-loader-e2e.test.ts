import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@agentic-sentinel/core";
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
function startServer(proxyPolicy: "block" | "observe"): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, policy: proxyPolicy, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(),
  });
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }));
  });
}
async function tarballUrl(base: string, pkg: string, version: string): Promise<string> {
  const doc = await (await fetch(`${base}/${pkg}`)).json();
  return doc.versions[version].dist.tarball as string;
}

describe("payload-loader e2e", () => {
  before(() => ensureFixtures());

  test("block policy → payload-loader-entry tarball 403 with verdict block", async () => {
    const { server, base } = await startServer("block");
    try {
      const url = await tarballUrl(base, "payload-loader-entry", "1.0.0");
      const res = await fetch(url);
      assert.equal(res.status, 403);
      assert.equal((await res.json()).verdict, "block");
    } finally { server.close(); }
  });

  test("observe policy → serves 200 but header verdict is block", async () => {
    const { server, base } = await startServer("observe");
    try {
      const url = await tarballUrl(base, "payload-loader-entry", "1.0.0");
      const res = await fetch(url);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("x-sentinel-verdict"), "block");
    } finally { server.close(); }
  });
});
