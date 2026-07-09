import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";

const execFileAsync = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const ENTRY = join(REPO_ROOT, "packages", "proxy", "src", "index.ts");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

// FATAL-exit posture for the Phase 23 env vars (parity with SENTINEL_AUTH_PUBKEY /
// SENTINEL_ADVISORIES): set-but-invalid must refuse to boot, valid must boot.
describe("proxy boot with SENTINEL_TARBALL_ORIGINS / SENTINEL_PUBLIC_BASE_URL (child process)", () => {
  ensureFixtures();

  function bootWith(extra: Record<string, string>): Promise<{ code: number; stderr: string }> {
    const env = { ...process.env, SENTINEL_UPSTREAM: "fixtures", SENTINEL_BOOT_EXIT: "1", SENTINEL_PORT: "0" };
    delete env.SENTINEL_TARBALL_ORIGINS;
    delete env.SENTINEL_PUBLIC_BASE_URL;
    Object.assign(env, extra);
    return execFileAsync("npx", ["tsx", ENTRY], { cwd: REPO_ROOT, env, timeout: 20_000 })
      .then(({ stderr }) => ({ code: 0, stderr }))
      .catch((err) => ({ code: typeof err.code === "number" ? err.code : 1, stderr: String(err.stderr ?? "") }));
  }

  test("origin entry with a path → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_TARBALL_ORIGINS: "https://cdn.example.com/tarballs" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("non-http origin entry → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_TARBALL_ORIGINS: "ftp://cdn.example.com" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("malformed public base URL → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_PUBLIC_BASE_URL: "not a url" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("valid values for both → boots, exit 0", async () => {
    const { code } = await bootWith({
      SENTINEL_TARBALL_ORIGINS: "https://cdn.example.com",
      SENTINEL_PUBLIC_BASE_URL: "https://sentinel.corp.example",
    });
    assert.equal(code, 0);
  });

  test("both unset → boots, exit 0 (zero behavior change)", async () => {
    const { code } = await bootWith({});
    assert.equal(code, 0);
  });
});
