import assert from "node:assert/strict";
import { execFile, execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
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

  for (const [signal, code] of [["SIGTERM", 143], ["SIGINT", 130]] as const) {
    test(`${signal} during the debounce window flushes the audit store and exits ${code}`, async () => {
      const file = join(mkdtempSync(join(tmpdir(), "sentinel-sig-")), "audits.json");
      const port = 41000 + Math.floor(Math.random() * 20000);
      const child = spawn("node", ["--import", "tsx", ENTRY], { cwd: REPO_ROOT,
        env: { ...process.env, SENTINEL_UPSTREAM: "fixtures", SENTINEL_PORT: String(port), SENTINEL_STORE: file } });
      let out = "";
      child.stdout.on("data", (d: Buffer) => { out += d.toString(); });
      const exited = new Promise<number | null>((resolve) => child.on("exit", (c) => resolve(c)));
      const deadline = Date.now() + 15_000;
      while (!/listening on/.test(out) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
      assert.match(out, /listening on/);
      const res = await fetch(`http://127.0.0.1:${port}/-/audit/leftpad-lite/1.0.0`);
      assert.equal(res.status, 200);
      child.kill(signal); // well inside the 500 ms debounce window
      assert.equal(await exited, code);
      const rows = JSON.parse(readFileSync(file, "utf8")) as { name: string }[];
      assert.ok(rows.some((r) => r.name === "leftpad-lite"));
    });
  }
});
