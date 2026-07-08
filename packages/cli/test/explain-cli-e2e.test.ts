import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
import { createServer } from "../../proxy/src/server.js";
import { AuditStore } from "../../proxy/src/store.js";
import { LocalFixtureUpstream } from "../../proxy/src/upstream.js";
import { ApprovalStore } from "../../proxy/src/approvals.js";
import { PrivatePackageStore } from "../../proxy/src/private-store.js";
import { ViolationStore } from "../../proxy/src/violations.js";
import { ApprovalRequestStore } from "../../proxy/src/approval-requests.js";

const execFileAsync = promisify(execFile);

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
const CLI_ENTRY = join(HERE, "..", "src", "index.ts");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

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

function boot(): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(),
  });
  return new Promise((resolve) => {
    const s = app.listen(0, () => resolve({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` }));
  });
}

describe("sentinel explain CLI (e2e)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot()); });
  after(() => server?.close());

  test("sentinel explain hijacked-lib 2.0.0 prints verdict, an action, last-known-good, and the waiver command (exit 0)", async () => {
    const { code, stdout } = await runCli(["explain", "hijacked-lib", "2.0.0"], base);
    assert.equal(code, 0);
    assert.match(stdout, /BLOCK|WARN/);
    assert.match(stdout, /pin to|known-good|1\.0\.0/);
    assert.match(stdout, /sentinel approve hijacked-lib 2\.0\.0/);
    // Lock in that the per-finding ACTION line renders (the command's headline feature) —
    // a distinctive action fragment not present in the last-known-good line above.
    assert.match(stdout, /Confirm the egress is expected|approve the capability manifest|pin to the prior version/);
  });
});
