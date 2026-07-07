// packages/proxy/test/enforce-e2e.test.ts
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ViolationStore } from "../src/violations.js";
import { DEFAULT_POLICY } from "@sentinel/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "..", "..", "fixtures");
// Use the BUILT wrapper (plain node — no tsx). The shim runs in a temp project cwd where a bare
// `tsx` specifier would NOT resolve, so pointing at compiled dist/ is what makes the shim work.
const CLI_DIST_SHELL = join(HERE, "..", "..", "cli", "dist", "script-shell.js");

function ensureFixtures() {
  if (!existsSync(join(FIXTURES, "registry.json")))
    execFileSync("npx", ["tsx", join(HERE, "..", "..", "..", "scripts", "make-fixtures.ts")], { stdio: "ignore" });
}
function ensureBuilt() {
  // The e2e test needs the compiled wrapper. `npm test` is preceded by `npm run build`, but build if missing.
  if (!existsSync(CLI_DIST_SHELL))
    execFileSync("npx", ["tsc", "--build", "--force", join(HERE, "..", "..", "cli")], { stdio: "ignore" });
}

// Sandbox availability: darwin always; linux only when bwrap can create namespaces.
const sandboxWorks = (() => {
  if (process.platform === "darwin") return true;
  if (process.platform !== "linux") return false;
  const r = spawnSync("bwrap", ["--ro-bind", "/", "/", "--dev", "/dev", "true"], { encoding: "utf8" });
  return !r.error && r.status === 0;
})();

describe("install --enforce (e2e) blocks an undeclared action; install otherwise succeeds", {
  skip: sandboxWorks ? false : "requires a working sandbox (Seatbelt on darwin / bwrap on Linux)",
}, () => {
  let server: Server; let base: string;

  before(async () => {
    ensureFixtures();
    ensureBuilt();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(), approvals: new ApprovalStore(),
      enterprisePolicy: DEFAULT_POLICY, policy: "block",
      violations: new ViolationStore(),
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  // Build one enforced install into `home`, returning the fixture's install dir. Approves the fixture first.
  async function enforcedInstall(home: string, enforce: boolean): Promise<string> {
    // approve enforce-probe via the real gate (fetch manifest → POST approval)
    const m = await (await fetch(`${base}/-/manifest/enforce-probe/1.0.0`)).json() as any;
    await fetch(`${base}/-/approvals`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify([{ name: "enforce-probe", version: "1.0.0", integrity: m.meta.integrity, decision: "approved", actor: { type: "test", id: "e2e" } }]),
    });
    const proj = realpathSync(mkdtempSync(join(home, "proj-")));
    writeFileSync(join(proj, "package.json"), JSON.stringify({ name: "consumer", version: "1.0.0" }));
    // executable script-shell shim → runs our wrapper under tsx (no build needed)
    const shim = join(proj, "shim.sh");
    writeFileSync(shim, `#!/bin/sh\nexec node "${CLI_DIST_SHELL}" "$@"\n`);
    chmodSync(shim, 0o755);
    const env: NodeJS.ProcessEnv = {
      ...process.env, HOME: home, npm_config_cache: join(home, ".npmcache"), npm_config_audit: "false", npm_config_fund: "false",
    };
    if (enforce) Object.assign(env, { npm_config_script_shell: shim, SENTINEL_ENFORCE: "1", SENTINEL_PROXY: base });
    // Use async spawn (not spawnSync): the proxy runs on THIS process's event loop, and a blocking
    // spawnSync would freeze it — npm (a child) could never fetch packument/tarball/manifest from the
    // in-process proxy, deadlocking the install. Awaiting keeps the loop free to serve the request path.
    const r = await new Promise<{ status: number | null; stderr: string }>((resolve) => {
      const child = spawn("npm", ["install", "enforce-probe@1.0.0", "--registry", base, "--no-audit", "--no-fund"], {
        cwd: proj, env,
      });
      let stderr = "";
      child.stderr.on("data", (d) => { stderr += d; });
      child.on("close", (status) => resolve({ status, stderr }));
    });
    assert.equal(r.status, 0, `npm install must succeed. stderr:\n${r.stderr}`);
    return join(proj, "node_modules", "enforce-probe");
  }

  test("ENFORCED: the undeclared ssh read is blocked, but the package installs and its script runs", async () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "enf-home-")));
    mkdirSync(join(home, ".ssh"), { recursive: true });
    writeFileSync(join(home, ".ssh", "id_rsa"), "TOPSECRET-ENFORCE-KEY");
    const dir = await enforcedInstall(home, true);
    assert.ok(existsSync(join(dir, "ran.txt")), "positive control: the postinstall must have run under the sandbox");
    const leaked = existsSync(join(dir, "leaked.txt")) ? readFileSync(join(dir, "leaked.txt"), "utf8") : "";
    assert.ok(!leaked.includes("TOPSECRET-ENFORCE-KEY"), "the undeclared ssh read must have been DENIED");
    assert.equal(readFileSync(join(home, ".ssh", "id_rsa"), "utf8"), "TOPSECRET-ENFORCE-KEY", "real secret untouched");
  });

  test("CONTROL: without --enforce, the same read is NOT blocked (proves --enforce is the cause)", async () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "enf-home2-")));
    mkdirSync(join(home, ".ssh"), { recursive: true });
    writeFileSync(join(home, ".ssh", "id_rsa"), "TOPSECRET-ENFORCE-KEY");
    const dir = await enforcedInstall(home, false);
    const leaked = existsSync(join(dir, "leaked.txt")) ? readFileSync(join(dir, "leaked.txt"), "utf8") : "";
    assert.ok(leaked.includes("TOPSECRET-ENFORCE-KEY"), "unsandboxed, the postinstall reads the secret (control)");
  });
});
