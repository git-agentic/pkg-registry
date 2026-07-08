import assert from "node:assert/strict";
import { execFileSync, execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
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
 * to the in-process proxy.
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

describe("sentinel attest keygen / attest / verify-attestation CLI", () => {
  let server: Server;
  let base: string;
  let dir: string;
  let lock: string;

  before(async () => {
    ensureFixtures();
    dir = mkdtempSync(join(tmpdir(), "sentinel-attest-cli-"));
    lock = join(dir, "package-lock.json");
    writeFileSync(lock, JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "root" },
        "node_modules/leftpad-lite": { version: "1.0.0" },
        "node_modules/color-stream": { version: "1.4.1" },
      },
    }));
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

  test("attest keygen writes a keypair with a 0600 private key, exit 0", async () => {
    const prefix = join(dir, "k");
    const { code } = await runCli(["attest-keygen", "--out", prefix]);
    assert.equal(code, 0);
    assert.ok(existsSync(`${prefix}.pub.pem`));
    assert.ok(existsSync(`${prefix}.key.pem`));
    assert.equal(statSync(`${prefix}.key.pem`).mode & 0o777, 0o600);
  });

  test("attest <lockfile> writes a valid SBOM + DSSE attestation, exit 0", async () => {
    const sbomPath = join(dir, "sbom.json");
    const attPath = join(dir, "att.json");
    const { code, stdout } = await runCli([
      "attest", lock,
      "--key", join(dir, "k.key.pem"),
      "--sbom", sbomPath,
      "--out", attPath,
      "-p", base,
    ]);
    assert.equal(code, 0, stdout);

    const bom = JSON.parse(readFileSync(sbomPath, "utf8")) as { bomFormat: string };
    assert.equal(bom.bomFormat, "CycloneDX");

    const env = JSON.parse(readFileSync(attPath, "utf8")) as {
      payloadType: string; payload: string; signatures: { keyid: string; sig: string }[];
    };
    assert.equal(typeof env.payloadType, "string");
    assert.equal(typeof env.payload, "string");
    assert.ok(Array.isArray(env.signatures) && env.signatures.length > 0);
    assert.equal(typeof env.signatures[0].sig, "string");
  });

  test("verify-attestation (right key) exits 0", async () => {
    const { code, stdout } = await runCli([
      "verify-attestation", join(dir, "att.json"),
      "--key", join(dir, "k.pub.pem"),
    ]);
    assert.equal(code, 0, stdout);
  });

  test("verify-attestation --require allow exits non-zero (the tree contains a blocking package)", async () => {
    const { code } = await runCli([
      "verify-attestation", join(dir, "att.json"),
      "--key", join(dir, "k.pub.pem"),
      "--require", "allow",
    ]);
    assert.notEqual(code, 0);
  });

  test("verify-attestation (wrong key) exits non-zero", async () => {
    const otherPrefix = join(dir, "other-k");
    await runCli(["attest-keygen", "--out", otherPrefix]);
    const { code } = await runCli([
      "verify-attestation", join(dir, "att.json"),
      "--key", `${otherPrefix}.pub.pem`,
    ]);
    assert.notEqual(code, 0);
  });
});
