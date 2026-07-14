import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@git-agentic/sentinel-core";
import { createServer } from "../../proxy/src/server.js";
import { AuditStore } from "../../proxy/src/store.js";
import { LocalFixtureUpstream } from "../../proxy/src/upstream.js";
import { ApprovalStore } from "../../proxy/src/approvals.js";
import { PrivatePackageStore } from "../../proxy/src/private-store.js";
import { ViolationStore } from "../../proxy/src/violations.js";
import { ApprovalRequestStore } from "../../proxy/src/approval-requests.js";
import { ProxyClient, ProxyError } from "../src/client.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

describe("ProxyClient", () => {
  let server: Server; let client: ProxyClient;
  before(async () => {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
      approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
      approvalRequests: new ApprovalRequestStore(),
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { client = new ProxyClient(`http://127.0.0.1:${(server.address() as AddressInfo).port}`); r(); }); });
  });
  after(() => server?.close());

  test("audit returns the real verdict for a blocking fixture", async () => {
    const rep = await client.audit("color-stream", "1.4.1");
    assert.equal(rep.verdict, "block");
  });

  test("audit resolves latest when version omitted", async () => {
    const rep = await client.audit("leftpad-lite");
    assert.equal(rep.meta.name, "leftpad-lite");
    assert.equal(rep.verdict, "allow");
  });

  test("an unknown package throws ProxyError with the status", async () => {
    await assert.rejects(() => client.audit("does-not-exist", "1.0.0"), (e) => e instanceof ProxyError && e.status === 404);
  });

  test("a bad base URL throws ProxyError (connection refused), not a fake verdict", async () => {
    const bad = new ProxyClient("http://127.0.0.1:1");
    await assert.rejects(() => bad.audit("x", "1.0.0"), (e) => e instanceof ProxyError);
  });
});
