import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
import type { AuditReport } from "@sentinel/core";
import { createServer } from "../../proxy/src/server.js";
import { AuditStore } from "../../proxy/src/store.js";
import { LocalFixtureUpstream } from "../../proxy/src/upstream.js";
import { ApprovalStore } from "../../proxy/src/approvals.js";
import { PrivatePackageStore } from "../../proxy/src/private-store.js";
import { ViolationStore } from "../../proxy/src/violations.js";
import { ApprovalRequestStore } from "../../proxy/src/approval-requests.js";
import { HistoryDb } from "../../proxy/src/history-db.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
const CLI_ENTRY = join(HERE, "..", "src", "index.ts");

const rep = (integrity: string, name: string, verdict: "allow" | "warn" | "block"): AuditReport =>
  ({ schema: 3, meta: { name, version: "1.0.0", integrity, signature: "unsigned", provenance: "absent" }, score: verdict === "block" ? 10 : 100, verdict, findings: [] } as unknown as AuditReport);

/**
 * Run the CLI via tsx; return { code, stdout } even on non-zero exit.
 * MUST be async: the proxy runs in THIS test process, so a synchronous child
 * (execFileSync) would block the event loop and deadlock the CLI's HTTP request
 * to the in-process proxy. `await` keeps the loop turning so the proxy can serve.
 */
async function runCli(args: string[], base: string): Promise<{ code: number; stdout: string }> {
  try {
    const { stdout } = await execFileAsync(process.execPath, ["--import", "tsx", CLI_ENTRY, ...args], {
      cwd: REPO_ROOT, encoding: "utf8", env: { ...process.env, NO_COLOR: "1", SENTINEL_PROXY: base },
    });
    return { code: 0, stdout };
  } catch (err) {
    const e = err as { code?: number; stdout?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? "" };
  }
}

function boot(withHistory: boolean): Promise<{ server: Server; base: string; history?: HistoryDb }> {
  const history = withHistory ? new HistoryDb(":memory:") : undefined;
  const store = new AuditStore(undefined, undefined, history);
  if (history) { store.put(rep("sha512-1", "evil", "block")); store.put(rep("sha512-2", "ok", "allow")); }
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store, approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(undefined, history), approvalRequests: new ApprovalRequestStore(), history,
  });
  return new Promise((resolve) => {
    const s = app.listen(0, () => resolve({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, history }));
  });
}

describe("sentinel stats / history CLI (e2e)", () => {
  let withHistory: { server: Server; base: string; history?: HistoryDb };
  let withoutHistory: { server: Server; base: string; history?: HistoryDb };

  before(async () => {
    withHistory = await boot(true);
    withoutHistory = await boot(false);
  });
  after(() => { withHistory.server.close(); withHistory.history?.close(); withoutHistory.server.close(); });

  test("sentinel stats prints totals and verdict counts (exit 0)", async () => {
    const { code, stdout } = await runCli(["stats"], withHistory.base);
    assert.equal(code, 0);
    assert.match(stdout, /2/);
    assert.match(stdout, /1 block/);
  });

  test("sentinel history --verdict block prints the blocked package name (exit 0)", async () => {
    const { code, stdout } = await runCli(["history", "--verdict", "block"], withHistory.base);
    assert.equal(code, 0);
    assert.match(stdout, /evil/);
  });

  test("sentinel stats against a proxy without history prints the enable hint (exit 0)", async () => {
    const { code, stdout } = await runCli(["stats"], withoutHistory.base);
    assert.equal(code, 0);
    assert.match(stdout, /history not enabled/);
  });
});
