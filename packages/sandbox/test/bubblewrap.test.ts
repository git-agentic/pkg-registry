import assert from "node:assert/strict";
import net from "node:net";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { BubblewrapSandbox } from "../src/bubblewrap.js";
import { runLifecycleScripts } from "../src/runner.js";
import { scrubEnv } from "../src/env.js";
import type { Capability } from "@sentinel/core";

const bwrapWorks = (() => {
  if (process.platform !== "linux") return false;
  const r = spawnSync("bwrap", ["--ro-bind", "/", "/", "--dev", "/dev", "true"], { encoding: "utf8" });
  return !r.error && r.status === 0;
})();
const skip = process.platform !== "linux"
  ? "requires Linux"
  : (bwrapWorks ? false : "bwrap cannot create namespaces here (see ci.yml: apparmor_restrict_unprivileged_userns=0)");

test("Linux CI must actually run bwrap enforcement (no silent skip)", {
  skip: process.env.CI && process.platform === "linux" ? false : "only enforced in Linux CI",
}, () => {
  assert.ok(bwrapWorks, "bwrap cannot create user namespaces in CI — the Linux enforcement tests would silently skip. Check the ci.yml userns mitigation (kernel.apparmor_restrict_unprivileged_userns).");
});

describe("BubblewrapSandbox enforcement", { skip }, () => {
  test("a denied credential read leaves the secret unobtained (EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-read-")));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_rsa"), "TOPSECRET-XYZ");
    const out = join(home, "out.txt");
    new BubblewrapSandbox().run(`cat ${join(home, ".ssh", "id_rsa")} > ${out} 2>/dev/null || true`, { cwd: home, approved: [], homeDir: home });
    assert.ok(existsSync(out), "positive control: the sandboxed script must have run (output file created)");
    const got = existsSync(out) ? readFileSync(out, "utf8") : "";
    assert.ok(!got.includes("TOPSECRET-XYZ"), "the secret bytes must NOT have been obtained");
    assert.equal(readFileSync(join(home, ".ssh", "id_rsa"), "utf8"), "TOPSECRET-XYZ", "real secret untouched");
  });

  test("a denied network connection never lands (loopback listener)", async () => {
    const got: boolean[] = [];
    const server = net.createServer((s) => { got.push(true); s.destroy(); });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as net.AddressInfo).port;
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-net-")));
    const ran = join(home, "ran.txt");
    // Connect via node, not a /dev/tcp bashism — BubblewrapSandbox runs `/bin/sh -c`, which is
    // dash on Ubuntu (no /dev/tcp). Under --unshare-net the sandbox has its own netns, so this
    // 127.0.0.1 cannot reach the host listener; the assertion is on the listener side (EFFECT).
    // The script also writes a ran-marker so we can prove bwrap actually launched it.
    const connect = `node -e "require('fs').writeFileSync('${ran}','RAN');const s=require('net').connect(${port},'127.0.0.1');s.on('connect',()=>s.end());s.on('error',()=>{});setTimeout(()=>process.exit(0),400)"`;
    new BubblewrapSandbox().run(connect, { cwd: home, approved: [], homeDir: home });
    await new Promise((r) => setTimeout(r, 200));
    server.close();
    assert.ok(existsSync(ran), "positive control: the sandboxed script must have run");
    assert.equal(got.length, 0, "the sandboxed connection must not have reached the listener");
  });

  test("an unapproved write to a persistence path is denied (planted file unchanged)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-write-")));
    const rc = join(home, ".bashrc");
    const allowed = join(home, "allowed.txt");
    writeFileSync(rc, "ORIGINAL");
    new BubblewrapSandbox().run(`echo OK > "${allowed}"; echo PWNED >> "${rc}" 2>/dev/null || true`, { cwd: home, approved: [], homeDir: home });
    assert.equal(readFileSync(allowed, "utf8").trim(), "OK", "script must have executed (positive control)");
    assert.equal(readFileSync(rc, "utf8"), "ORIGINAL", "the denied write must have been blocked");
  });

  test("an unapproved credential env-var never reaches the script; approval passes it through (EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-env-")));
    const out = join(home, "leak.txt");
    const cmd = `node -e "require('fs').writeFileSync('${out}', String(process.env.SECRET_API_KEY||''))"`;
    new BubblewrapSandbox().run(cmd, { cwd: home, approved: [], homeDir: home, env: scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, []) });
    assert.ok(existsSync(out), "positive control: node must have written the output file in the first (no-approval) run");
    assert.ok(!(existsSync(out) ? readFileSync(out, "utf8") : "").includes("TOPSECRET-ENV"), "the credential env-var must not have reached the script");
    const approved: Capability[] = [{ kind: "env", target: "SECRET_API_KEY", evidence: [] }];
    new BubblewrapSandbox().run(cmd, { cwd: home, approved, homeDir: home, env: scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, approved) });
    assert.ok(readFileSync(out, "utf8").includes("TOPSECRET-ENV"), "an approved env var is passed through");
  });

  test("a filesystem approval relaxes the credential read deny (EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-fsapprove-")));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_rsa"), "APPROVED-SECRET");
    const out = join(home, "out.txt");
    const approved: Capability[] = [{ kind: "filesystem", target: ".ssh", evidence: [] }];
    new BubblewrapSandbox().run(`cat ${join(home, ".ssh", "id_rsa")} > ${out} 2>/dev/null || true`, { cwd: home, approved, homeDir: home });
    assert.ok(readFileSync(out, "utf8").includes("APPROVED-SECRET"), "an approved filesystem read must succeed");
  });

  test("a non-denied path stays readable and writable inside the sandbox (positive control)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-allow-")));
    writeFileSync(join(home, "data.txt"), "HELLO");
    const out = join(home, "copy.txt");
    new BubblewrapSandbox().run(`cat ${join(home, "data.txt")} > ${out}`, { cwd: home, approved: [], homeDir: home });
    assert.equal(readFileSync(out, "utf8").trim(), "HELLO", "non-denied read/write must work");
  });

  test("runLifecycleScripts runs a benign postinstall under bwrap", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "bw-run-")));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: "echo built > built.txt" } }));
    const r = runLifecycleScripts({ packageDir: dir, sandbox: new BubblewrapSandbox(), homeDir: process.env.HOME ?? "/root" });
    assert.equal(r.failed, false);
    assert.equal(readFileSync(join(dir, "built.txt"), "utf8").trim(), "built");
  });
});
