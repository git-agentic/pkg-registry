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

describe("proxy boot with Phase 24 limit env vars (child process)", () => {
  ensureFixtures();
  const VARS = ["SENTINEL_MAX_TREE_PACKAGES", "SENTINEL_MAX_TARBALL_BYTES", "SENTINEL_MAX_PACKUMENT_BYTES", "SENTINEL_RATE_LIMIT_RPM", "SENTINEL_MAX_UNPACKED_BYTES", "SENTINEL_MAX_FILE_COUNT"];

  function bootWith(extra: Record<string, string>): Promise<{ code: number; stderr: string }> {
    const env = { ...process.env, SENTINEL_UPSTREAM: "fixtures", SENTINEL_BOOT_EXIT: "1", SENTINEL_PORT: "0" };
    for (const v of VARS) delete env[v];
    Object.assign(env, extra);
    return execFileAsync("npx", ["tsx", ENTRY], { cwd: REPO_ROOT, env, timeout: 20_000 })
      .then(({ stderr }) => ({ code: 0, stderr }))
      .catch((err) => ({ code: typeof err.code === "number" ? err.code : 1, stderr: String(err.stderr ?? "") }));
  }

  test("non-integer tree cap → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_MAX_TREE_PACKAGES: "lots" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("zero tarball cap → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_MAX_TARBALL_BYTES: "0" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("negative rate limit → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_RATE_LIMIT_RPM: "-5" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("non-integer unpacked cap → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_MAX_UNPACKED_BYTES: "big" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("zero file-count cap → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_MAX_FILE_COUNT: "0" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("valid values for all four → boots, exit 0", async () => {
    const { code } = await bootWith({
      SENTINEL_MAX_TREE_PACKAGES: "3000",
      SENTINEL_MAX_TARBALL_BYTES: "104857600",
      SENTINEL_MAX_PACKUMENT_BYTES: "52428800",
      SENTINEL_RATE_LIMIT_RPM: "120",
    });
    assert.equal(code, 0);
  });

  test("all unset → boots, exit 0 (zero behavior change)", async () => {
    const { code } = await bootWith({});
    assert.equal(code, 0);
  });
});
