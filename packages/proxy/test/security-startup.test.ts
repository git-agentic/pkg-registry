import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, test } from "node:test";

const execFileAsync = promisify(execFile);
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const ENTRY = join(REPO_ROOT, "packages", "proxy", "src", "index.ts");
const FIXTURES = join(REPO_ROOT, "fixtures");

describe("proxy startup validation (F16, F18)", () => {
  if (!existsSync(join(FIXTURES, "registry.json")) || !existsSync(join(FIXTURES, ".tarballs"))) {
    execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
  }

  function bootWith(extra: Record<string, string>): Promise<{ code: number; output: string }> {
    const env: Record<string, string | undefined> = { ...process.env, SENTINEL_UPSTREAM: "fixtures", SENTINEL_BOOT_EXIT: "1", SENTINEL_PORT: "0" };
    delete env["SENTINEL_POLICY"]; delete env["SENTINEL_HOST"];
    Object.assign(env, extra);
    return execFileAsync("node", ["--import", "tsx", ENTRY], { cwd: REPO_ROOT, env, timeout: 20_000, encoding: "utf8" })
      .then(({ stdout, stderr }) => ({ code: 0, output: stdout + stderr }))
      .catch((err) => ({ code: typeof err.code === "number" ? err.code : 1, output: String(err.stdout ?? "") + String(err.stderr ?? "") }));
  }

  for (const bad of ["Block", "enforce", "", " block", "observe "]) {
    test(`SENTINEL_POLICY=${JSON.stringify(bad)} → FATAL, non-zero exit`, async () => {
      const { code, output } = await bootWith({ SENTINEL_POLICY: bad });
      assert.notEqual(code, 0);
      assert.match(output, /FATAL.*SENTINEL_POLICY/);
    });
  }

  for (const good of ["observe", "block"]) {
    test(`SENTINEL_POLICY=${good} boots`, async () => {
      assert.equal((await bootWith({ SENTINEL_POLICY: good })).code, 0);
    });
  }

  test("binds 127.0.0.1 by default and says so in the startup log", async () => {
    const { code, output } = await bootWith({});
    assert.equal(code, 0);
    assert.match(output, /listening on http:\/\/127\.0\.0\.1:/);
  });

  test("SENTINEL_HOST overrides the bind address", async () => {
    const { code, output } = await bootWith({ SENTINEL_HOST: "0.0.0.0" });
    assert.equal(code, 0);
    assert.match(output, /host\s*:\s*0\.0\.0\.0/);
  });

  test("empty SENTINEL_HOST → FATAL", async () => {
    const { code, output } = await bootWith({ SENTINEL_HOST: "" });
    assert.notEqual(code, 0);
    assert.match(output, /FATAL.*SENTINEL_HOST/);
  });
});
