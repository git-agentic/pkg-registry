import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { runLifecycleScripts } from "../src/runner.js";
import type { Sandbox, SandboxResult } from "../src/types.js";
import type { Capability } from "@sentinel/core";

function fakeSandbox(captured: NodeJS.ProcessEnv[]): Sandbox {
  return { run(_cmd, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv }): SandboxResult {
    captured.push(opts.env ?? {});
    return { exitCode: 0, stdout: "", stderr: "" };
  } };
}

test("runLifecycleScripts forwards projectRoot to the sandbox", () => {
  let seen: string | undefined = "UNSET";
  const spy: Sandbox = {
    run(_cmd, opts) { seen = opts.projectRoot; return { exitCode: 0, stdout: "", stderr: "" }; },
  };
  const dir = mkdtempSync(join(tmpdir(), "runner-pr-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ scripts: { postinstall: "echo hi" } }));
  runLifecycleScripts({ packageDir: dir, sandbox: spy, homeDir: "/home/x", projectRoot: "/work/app" });
  assert.equal(seen, "/work/app");
});

describe("runLifecycleScripts env scrubbing", () => {
  test("passes a scrubbed env to the sandbox (secret dropped, allowlisted kept, approval honored)", () => {
    const dir = mkdtempSync(join(tmpdir(), "run-env-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: "echo hi" } }));
    process.env.SENTINEL_TEST_SECRET_TOKEN = "LEAK";  // a credential-shaped var
    const captured: NodeJS.ProcessEnv[] = [];
    const approved: Capability[] = [{ kind: "env", target: "SENTINEL_TEST_SECRET_TOKEN", evidence: [] }];
    try {
      runLifecycleScripts({ packageDir: dir, sandbox: fakeSandbox(captured), approved, homeDir: "/home/test" });
      const env = captured[0]!;
      assert.equal(env.SENTINEL_TEST_SECRET_TOKEN, "LEAK", "approved env var passes through");
      assert.ok(env.PATH !== undefined, "allowlisted PATH kept");
      // and without the approval it is dropped:
      const captured2: NodeJS.ProcessEnv[] = [];
      runLifecycleScripts({ packageDir: dir, sandbox: fakeSandbox(captured2), approved: [], homeDir: "/home/test" });
      assert.equal(captured2[0]!.SENTINEL_TEST_SECRET_TOKEN, undefined, "unapproved secret dropped");
    } finally {
      delete process.env.SENTINEL_TEST_SECRET_TOKEN;
    }
  });
});
