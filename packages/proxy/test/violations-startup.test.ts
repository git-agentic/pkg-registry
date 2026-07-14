import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { generateKeypair } from "@git-agentic/sentinel-core";

const execFileAsync = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const ENTRY = join(REPO_ROOT, "packages", "proxy", "src", "index.ts");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

// End-to-end child-process boot tests: prove SENTINEL_AUTO_QUARANTINE=1 is fail-closed
// without SENTINEL_AUTH_PUBKEY (Task B2 / ADR-0040 — auto-quarantine must be attributable
// to a verified token), and boots clean once auth is configured.
describe("proxy boot with SENTINEL_AUTO_QUARANTINE (child process)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-auto-quarantine-"));
  ensureFixtures();

  function bootWith(extra: Record<string, string | undefined>): Promise<{ code: number; stderr: string }> {
    const env = { ...process.env, SENTINEL_UPSTREAM: "fixtures", SENTINEL_BOOT_EXIT: "1", SENTINEL_PORT: "0" };
    delete env.SENTINEL_AUTO_QUARANTINE;
    delete env.SENTINEL_AUTH_PUBKEY;
    for (const [k, v] of Object.entries(extra)) {
      if (v === undefined) delete env[k]; else env[k] = v;
    }
    return execFileAsync("npx", ["tsx", ENTRY], { cwd: REPO_ROOT, env, timeout: 20_000 })
      .then(({ stderr }) => ({ code: 0, stderr }))
      .catch((err) => ({ code: typeof err.code === "number" ? err.code : 1, stderr: String(err.stderr ?? "") }));
  }

  test("SENTINEL_AUTO_QUARANTINE=1 without SENTINEL_AUTH_PUBKEY → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_AUTO_QUARANTINE: "1" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("SENTINEL_AUTO_QUARANTINE=1 with a valid SENTINEL_AUTH_PUBKEY → boots clean, exit 0", async () => {
    const { publicKey } = generateKeypair();
    const p = join(dir, "auth.pem");
    writeFileSync(p, publicKey);
    const { code, stderr } = await bootWith({ SENTINEL_AUTO_QUARANTINE: "1", SENTINEL_AUTH_PUBKEY: p });
    assert.equal(code, 0, stderr);
  });

  test("SENTINEL_AUTO_QUARANTINE unset (default) → boots clean, exit 0", async () => {
    const { code } = await bootWith({});
    assert.equal(code, 0);
  });
});
