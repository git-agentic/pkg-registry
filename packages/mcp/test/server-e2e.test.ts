import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, test } from "node:test";
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
import { ProxyClient } from "../src/client.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

let server: Server;
let client: ProxyClient;

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

test("tools are registered and round-trip over the transport", async () => {
  const mcpServer = createMcpServer(client);
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await mcpServer.connect(serverT);
  const mcp = new Client({ name: "test", version: "0.0.0" });
  await mcp.connect(clientT);

  const tools = await mcp.listTools();
  const names = tools.tools.map((t) => t.name).sort();
  assert.deepEqual(names, [
    "sentinel_audit", "sentinel_audit_tree", "sentinel_capabilities",
    "sentinel_check_provenance", "sentinel_explain", "sentinel_list_violations", "sentinel_request_approval",
  ].sort());

  const res = await mcp.callTool({ name: "sentinel_audit", arguments: { package: "color-stream", version: "1.4.1" } });
  assert.match((res.content as { text: string }[])[0].text, /block/i);
  assert.equal((res.structuredContent as { verdict: string }).verdict, "block");

  const bad = await mcp.callTool({ name: "sentinel_audit", arguments: { package: 123 } });
  assert.equal(bad.isError, true); // SDK schema validation rejects a non-string package
  await mcp.close();
});
