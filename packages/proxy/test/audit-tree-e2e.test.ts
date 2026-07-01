import assert from "node:assert/strict";
import { execFileSync, execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
const CLI_ENTRY = join(REPO_ROOT, "packages", "cli", "src", "index.ts");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

function lockfile(pkgs: { name: string; version: string }[]): string {
  const packages: Record<string, unknown> = { "": { name: "proj", version: "1.0.0" } };
  for (const p of pkgs) {
    packages[`node_modules/${p.name}`] = { version: p.version, resolved: `https://registry/${p.name}/-/x.tgz` };
  }
  return JSON.stringify({ name: "proj", version: "1.0.0", lockfileVersion: 3, packages });
}

/**
 * Run the CLI via tsx; return { code, stdout } even on non-zero exit.
 * MUST be async: the proxy runs in THIS test process, so a synchronous child
 * (execFileSync) would block the event loop and deadlock the CLI's HTTP request
 * to the in-process proxy. `await` keeps the loop turning so the proxy can serve.
 */
async function runCli(args: string[]): Promise<{ code: number; stdout: string }> {
  try {
    const { stdout } = await execFileAsync(process.execPath, ["--import", "tsx", CLI_ENTRY, ...args], {
      cwd: REPO_ROOT, encoding: "utf8", env: { ...process.env, NO_COLOR: "1" },
    });
    return { code: 0, stdout };
  } catch (err) {
    // A non-zero exit rejects; the error carries the exit code and captured stdout.
    const e = err as { code?: number; stdout?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? "" };
  }
}

describe("sentinel audit-tree end-to-end", () => {
  let server: Server;
  let base: string;
  let dir: string;

  before(async () => {
    ensureFixtures();
    dir = mkdtempSync(join(tmpdir(), "sentinel-tree-"));
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals: new ApprovalStore(),
      enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(),
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; resolve(); });
    });
  });
  after(() => server?.close());

  test("a benign tree exits 0 and prints the allow verdict", async () => {
    const lock = join(dir, "benign-lock.json");
    writeFileSync(lock, lockfile([{ name: "leftpad-lite", version: "1.0.0" }, { name: "net-fetch-lite", version: "1.0.0" }]));
    const { code, stdout } = await runCli(["audit-tree", lock, "--proxy", base]);
    assert.equal(code, 0);
    assert.match(stdout, /ALLOW/);
  });

  test("a tree with the malicious fixture exits non-zero and prints GATED", async () => {
    const lock = join(dir, "mal-lock.json");
    writeFileSync(lock, lockfile([{ name: "leftpad-lite", version: "1.0.0" }, { name: "color-stream", version: "1.4.1" }]));
    const { code, stdout } = await runCli(["audit-tree", lock, "--proxy", base]);
    assert.equal(code, 2);
    assert.match(stdout, /GATED/);
    assert.match(stdout, /color-stream@1\.4\.1/);
  });

  test("--json emits the raw result", async () => {
    const lock = join(dir, "json-lock.json");
    writeFileSync(lock, lockfile([{ name: "leftpad-lite", version: "1.0.0" }]));
    const { stdout } = await runCli(["audit-tree", lock, "--proxy", base, "--json"]);
    const parsed = JSON.parse(stdout) as { aggregate: { verdict: string } };
    assert.equal(parsed.aggregate.verdict, "allow");
  });
});
