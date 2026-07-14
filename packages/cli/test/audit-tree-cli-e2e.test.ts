import assert from "node:assert/strict";
import { execFileSync, execFile } from "node:child_process";
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
import { createServer } from "../../proxy/src/server.js";
import { AuditStore } from "../../proxy/src/store.js";
import { LocalFixtureUpstream } from "../../proxy/src/upstream.js";
import { ApprovalStore } from "../../proxy/src/approvals.js";
import { PrivatePackageStore } from "../../proxy/src/private-store.js";
import { ViolationStore } from "../../proxy/src/violations.js";
import { ApprovalRequestStore } from "../../proxy/src/approval-requests.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
const CLI_ENTRY = join(HERE, "..", "src", "index.ts");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

const YARN = `# yarn lockfile v1\n\nleftpad-lite@^1.0.0:\n  version "1.0.0"\n`;
const PNPM = `lockfileVersion: '9.0'\npackages:\n  leftpad-lite@1.0.0:\n    resolution: {integrity: sha512-x}\n`;
const PNPM_MISSING = `lockfileVersion: '9.0'\npackages:\n  does-not-exist@9.9.9:\n    resolution: {integrity: sha512-x}\n`;

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
    const e = err as { code?: number; stdout?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? "" };
  }
}

describe("sentinel audit-tree CLI: multi-format parsing, --sbom, --fail-on-error", () => {
  let server: Server;
  let base: string;
  let dir: string;

  before(async () => {
    ensureFixtures();
    dir = mkdtempSync(join(tmpdir(), "sentinel-tree-cli-"));
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals: new ApprovalStore(),
      enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(),
      violations: new ViolationStore(),
      approvalRequests: new ApprovalRequestStore(),
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; resolve(); });
    });
  });
  after(() => server?.close());

  test("yarn.lock is auto-detected and resolves (exit 0)", async () => {
    const lock = join(dir, "yarn.lock");
    writeFileSync(lock, YARN);
    const { code, stdout } = await runCli(["audit-tree", lock, "--proxy", base]);
    assert.equal(code, 0);
    assert.match(stdout, /ALLOW/);
    assert.match(stdout, /leftpad-lite@1\.0\.0/);
  });

  test("pnpm-lock.yaml with --sbom writes a valid CycloneDX BOM", async () => {
    const lock = join(dir, "pnpm-lock.yaml");
    writeFileSync(lock, PNPM);
    const sbomPath = join(dir, "sbom.json");
    await runCli(["audit-tree", lock, "--proxy", base, "--sbom", sbomPath]);
    assert.ok(existsSync(sbomPath), "sbom file should be written");
    const bom = JSON.parse(readFileSync(sbomPath, "utf8")) as {
      bomFormat: string;
      components: { name: string; version: string }[];
    };
    assert.equal(bom.bomFormat, "CycloneDX");
    assert.ok(
      bom.components.some((c) => c.name === "leftpad-lite" && c.version === "1.0.0"),
      "expected a leftpad-lite component in the SBOM",
    );
  });

  test("--fail-on-error gates an unresolvable-package tree (non-zero exit); without it, exit 0", async () => {
    const lock = join(dir, "missing-pnpm-lock.yaml");
    writeFileSync(lock, PNPM_MISSING);

    const noFlag = await runCli(["audit-tree", lock, "--proxy", base]);
    assert.equal(noFlag.code, 0, "fail-open by default");

    const withFlag = await runCli(["audit-tree", lock, "--proxy", base, "--fail-on-error"]);
    assert.notEqual(withFlag.code, 0, "--fail-on-error should gate the tree");
  });
});
