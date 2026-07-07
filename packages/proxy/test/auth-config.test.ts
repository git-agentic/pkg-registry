import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { describe, test } from "node:test";
import { generateKeypair } from "@sentinel/core";
import { validateAuthPublicKey } from "../src/auth-config.js";

const execFileAsync = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const ENTRY = join(REPO_ROOT, "packages", "proxy", "src", "index.ts");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

// Pure-helper unit tests (fast, reliable — no child process, no process.exit).
describe("validateAuthPublicKey (pure)", () => {
  test("empty content throws (no silent open)", () => {
    assert.throws(() => validateAuthPublicKey(""));
  });

  test("whitespace-only content throws", () => {
    assert.throws(() => validateAuthPublicKey("   \n\t  "));
  });

  test("garbage non-PEM content throws", () => {
    assert.throws(() => validateAuthPublicKey("this is not a key"));
  });

  test("a valid PEM public key is accepted and returned unchanged", () => {
    const { publicKey } = generateKeypair();
    assert.equal(validateAuthPublicKey(publicKey), publicKey);
  });
});

// End-to-end child-process boot tests: prove the real CLI entry point FATAL-exits
// on a configured-but-invalid key, rather than silently booting in open mode.
describe("proxy boot with SENTINEL_AUTH_PUBKEY (child process)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-auth-config-"));
  ensureFixtures();

  function bootWith(pubkeyPath: string | undefined): Promise<{ code: number; stderr: string }> {
    const env = { ...process.env, SENTINEL_UPSTREAM: "fixtures", SENTINEL_BOOT_EXIT: "1", SENTINEL_PORT: "0" };
    if (pubkeyPath) env.SENTINEL_AUTH_PUBKEY = pubkeyPath; else delete env.SENTINEL_AUTH_PUBKEY;
    return execFileAsync("npx", ["tsx", ENTRY], { cwd: REPO_ROOT, env, timeout: 20_000 })
      .then(({ stderr }) => ({ code: 0, stderr }))
      .catch((err) => ({ code: typeof err.code === "number" ? err.code : 1, stderr: String(err.stderr ?? "") }));
  }

  test("empty key file → non-zero exit + FATAL message", async () => {
    const p = join(dir, "empty.pem");
    writeFileSync(p, "");
    const { code, stderr } = await bootWith(p);
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("garbage non-PEM key file → non-zero exit + FATAL message", async () => {
    const p = join(dir, "garbage.pem");
    writeFileSync(p, "not a real key at all");
    const { code, stderr } = await bootWith(p);
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("unset SENTINEL_AUTH_PUBKEY → boots fine (open mode), exit 0", async () => {
    const { code } = await bootWith(undefined);
    assert.equal(code, 0);
  });
});
