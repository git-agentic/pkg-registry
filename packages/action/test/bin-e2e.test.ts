import assert from "node:assert/strict";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { describe, test } from "node:test";

const execFileAsync = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO, "fixtures");
const BIN = join(REPO, "packages", "action", "dist", "index.js");

function ensureBuilt(): void {
  if (!existsSync(BIN)) execFileSync("npm", ["run", "build"], { cwd: REPO, stdio: "ignore" });
  if (!existsSync(join(FIXTURES, "registry.json"))) execFileSync("npx", ["tsx", join(REPO, "scripts", "make-fixtures.ts")], { cwd: REPO, stdio: "ignore" });
}
function lockDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-bin-"));
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify({
    name: "demo", lockfileVersion: 3,
    packages: { "": { name: "demo" }, "node_modules/leftpad-lite": { version: "1.0.0" }, "node_modules/color-stream": { version: "1.4.1" } },
  }));
  return dir;
}
async function run(dir: string, extraEnv: Record<string, string>): Promise<{ code: number; stdout: string }> {
  // Scrub inherited GitHub Actions env so the action's output mode is driven only
  // by `extraEnv` — otherwise, when this suite itself runs inside GitHub Actions,
  // GITHUB_OUTPUT/GITHUB_STEP_SUMMARY route the report to a file + emit `::error::`
  // annotations instead of printing the plain report to stdout (the "no GitHub env"
  // path this test asserts). A test whose behavior flips based on where it runs is
  // the bug being fixed here.
  const env: NodeJS.ProcessEnv = { ...process.env, SENTINEL_CI_FIXTURES: FIXTURES };
  for (const k of Object.keys(env)) if (k.startsWith("GITHUB_")) delete env[k];
  Object.assign(env, extraEnv);
  try {
    const { stdout } = await execFileAsync("node", [BIN], { cwd: dir, env });
    return { code: 0, stdout };
  } catch (e) {
    const err = e as { code?: number; stdout?: string };
    return { code: err.code ?? 1, stdout: err.stdout ?? "" };
  }
}

describe("sentinel-ci bin (e2e)", () => {
  test("fail-on=block on a malicious tree exits non-zero", async () => {
    ensureBuilt();
    const { code } = await run(lockDir(), { INPUT_FAIL_ON: "block", INPUT_SBOM_PATH: join(tmpdir(), `sb-${Date.now()}.json`) });
    assert.equal(code, 2);
  });
  test("fail-on=none exits 0 and prints the report to stdout (no GitHub env)", async () => {
    ensureBuilt();
    const { code, stdout } = await run(lockDir(), { INPUT_FAIL_ON: "none", INPUT_SBOM_PATH: join(tmpdir(), `sb2-${Date.now()}.json`) });
    assert.equal(code, 0);
    assert.match(stdout, /Sentinel dependency audit/);
  });
});
