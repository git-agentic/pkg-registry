import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@git-agentic/sentinel-core";
import type { AuditReport } from "@git-agentic/sentinel-core";
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

/**
 * Run the CLI via tsx; return { code, stdout, stderr } even on non-zero exit.
 * MUST be async: the proxy runs in THIS test process, so a synchronous child
 * (execFileSync) would block the event loop and deadlock the CLI's HTTP request
 * to the in-process proxy. `await` keeps the loop turning so the proxy can serve.
 */
async function runCli(args: string[], base?: string): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, ["--import", "tsx", CLI_ENTRY, ...args], {
      cwd: REPO_ROOT, encoding: "utf8", env: { ...process.env, NO_COLOR: "1", ...(base ? { SENTINEL_PROXY: base } : {}) },
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    const e = err as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
}

// Reports whose stored verdict is consistent with DEFAULT_POLICY, so an identical replay
// is "unchanged"; a stricter candidate (hardBlockSeverity: "high") flips the risky one.
function reportWith(name: string, integrity: string, severity: "high" | "info"): AuditReport {
  const hasFinding = severity === "high";
  return {
    schema: 3,
    meta: { name, version: "1.0.0", integrity, signature: "unsigned", provenance: "absent", author: null, maintainers: [], license: "MIT", hasInstallScripts: false, unpackedSize: 1, fileCount: 1 },
    score: hasFinding ? 75 : 100,
    verdict: hasFinding ? "warn" : "allow",
    findings: hasFinding ? [{ ruleId: "network-egress", category: "network", severity: "high", message: "x", onChangedFile: false, evidence: [], weight: 25, waived: false }] : [],
    capabilities: [], capabilityDelta: null,
    engine: { version: "0.1.0", rules: [], llm: null, mode: "full" }, llmSummary: null,
    auditedAt: "2026-07-01T00:00:00Z", durationMs: 0, policy: { version: "default", hash: "h" },
  } as unknown as AuditReport;
}

function boot(withHistory: boolean): Promise<{ server: Server; base: string; history?: HistoryDb }> {
  const history = withHistory ? new HistoryDb(":memory:") : undefined;
  if (history) {
    history.recordAudit(reportWith("clean", "sha512-a", "info"), "2026-07-01T00:00:00Z");
    history.recordAudit(reportWith("risky", "sha512-b", "high"), "2026-07-02T00:00:00Z");
  }
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(), history,
  });
  return new Promise((resolve) => {
    const s = app.listen(0, () => resolve({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, history }));
  });
}

describe("sentinel policy init/validate/preview (e2e)", () => {
  let withHistory: { server: Server; base: string; history?: HistoryDb };
  let withoutHistory: { server: Server; base: string; history?: HistoryDb };
  let dir: string;

  before(async () => {
    withHistory = await boot(true);
    withoutHistory = await boot(false);
    dir = mkdtempSync(join(tmpdir(), "sentinel-policy-cli-"));
  });
  after(() => { withHistory.server.close(); withHistory.history?.close(); withoutHistory.server.close(); });

  test("policy init writes a valid policy file", async () => {
    const p = join(dir, "p.json");
    const { code } = await runCli(["policy", "init", "--out", p]);
    assert.equal(code, 0);
    assert.ok(existsSync(p));
    const policy = JSON.parse(readFileSync(p, "utf8"));
    assert.ok(policy.scoring);
  });

  test("policy validate on the freshly-init'd default policy exits 0 (clean)", async () => {
    const p = join(dir, "p2.json");
    await runCli(["policy", "init", "--out", p]);
    const { code, stdout } = await runCli(["policy", "validate", p]);
    assert.equal(code, 0);
    assert.match(stdout, /valid|0 error/);
  });

  test("policy validate on an inverted-thresholds policy exits non-zero and reports threshold-inverted", async () => {
    const bad = structuredClone(DEFAULT_POLICY);
    bad.scoring.thresholds = { allow: 40, warn: 80 };
    const p = join(dir, "bad.json");
    writeFileSync(p, JSON.stringify(bad, null, 2));
    const { code, stdout, stderr } = await runCli(["policy", "validate", p]);
    assert.notEqual(code, 0);
    assert.match(stdout + stderr, /threshold-inverted/);
  });

  test("policy preview against a seeded proxy prints the transition summary", async () => {
    const p = join(dir, "candidate.json");
    const strict = structuredClone(DEFAULT_POLICY);
    strict.scoring.hardBlockSeverity = "high";
    writeFileSync(p, JSON.stringify(strict, null, 2));
    const { code, stdout } = await runCli(["policy", "preview", p, "-p", withHistory.base]);
    assert.equal(code, 0);
    assert.match(stdout, /replayed|would change|unchanged/);
  });

  test("policy preview against a no-history proxy prints the enable hint", async () => {
    const p = join(dir, "candidate2.json");
    writeFileSync(p, JSON.stringify(DEFAULT_POLICY, null, 2));
    const { code, stdout } = await runCli(["policy", "preview", p, "-p", withoutHistory.base]);
    assert.equal(code, 0);
    assert.match(stdout, /history not enabled/);
  });
});
