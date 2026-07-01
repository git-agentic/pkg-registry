import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHELL = join(HERE, "..", "src", "script-shell.ts");
const runShell = (args: string[], env: NodeJS.ProcessEnv) => {
  try {
    const out = execFileSync("node", ["--import", "tsx", SHELL, ...args], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { code: 0, out };
  } catch (e: any) { return { code: e.status ?? 1, out: (e.stdout ?? "") + (e.stderr ?? "") }; }
};

describe("sentinel-script-shell guard", () => {
  test("refuses to run when SENTINEL_ENFORCE is not set (fail closed)", () => {
    const r = runShell(["-c", "echo SHOULD_NOT_RUN"], { ...process.env, SENTINEL_ENFORCE: "" });
    assert.notEqual(r.code, 0, "must exit non-zero without SENTINEL_ENFORCE");
    assert.ok(!r.out.includes("SHOULD_NOT_RUN"), "the command must not have executed");
  });
  test("refuses a malformed invocation (not -c <cmd>)", () => {
    const r = runShell(["oops"], { ...process.env, SENTINEL_ENFORCE: "1" });
    assert.notEqual(r.code, 0);
  });
});
