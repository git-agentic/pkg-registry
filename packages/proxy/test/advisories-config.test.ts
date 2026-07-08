import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
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

// End-to-end child-process boot tests: prove the real CLI entry point FATAL-exits on a
// readable-but-CORRUPT SENTINEL_ADVISORIES file (parity with SENTINEL_AUTH_PUBKEY),
// not just an unreadable one, and that a legitimately empty advisory list still boots.
describe("proxy boot with SENTINEL_ADVISORIES (child process)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-advisories-config-"));
  ensureFixtures();

  function bootWith(advisoriesPath: string | undefined): Promise<{ code: number; stderr: string }> {
    const env = { ...process.env, SENTINEL_UPSTREAM: "fixtures", SENTINEL_BOOT_EXIT: "1", SENTINEL_PORT: "0" };
    if (advisoriesPath) env.SENTINEL_ADVISORIES = advisoriesPath; else delete env.SENTINEL_ADVISORIES;
    return execFileAsync("npx", ["tsx", ENTRY], { cwd: REPO_ROOT, env, timeout: 20_000 })
      .then(({ stderr }) => ({ code: 0, stderr }))
      .catch((err) => ({ code: typeof err.code === "number" ? err.code : 1, stderr: String(err.stderr ?? "") }));
  }

  test("non-JSON advisories file → non-zero exit + FATAL message", async () => {
    const p = join(dir, "garbage.json");
    writeFileSync(p, "not json at all");
    const { code, stderr } = await bootWith(p);
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("valid JSON that is not an array → non-zero exit + FATAL message", async () => {
    const p = join(dir, "object.json");
    writeFileSync(p, JSON.stringify({ not: "an array" }));
    const { code, stderr } = await bootWith(p);
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("a legitimately empty JSON array → boots fine (bundled-only), exit 0", async () => {
    const p = join(dir, "empty.json");
    writeFileSync(p, "[]");
    const { code } = await bootWith(p);
    assert.equal(code, 0);
  });

  test("unset SENTINEL_ADVISORIES → boots fine, exit 0", async () => {
    const { code } = await bootWith(undefined);
    assert.equal(code, 0);
  });
});
