import assert from "node:assert/strict";
import net from "node:net";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, realpathSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { SeatbeltSandbox } from "../src/seatbelt.js";
import { runLifecycleScripts } from "../src/runner.js";
import { scrubEnv } from "../src/env.js";
import type { Capability } from "@sentinel/core";

const darwin = process.platform === "darwin";

describe("SeatbeltSandbox (fail-closed)", () => {
  test("non-darwin throws (we never run unsandboxed)", { skip: darwin ? "darwin: covered by enforcement tests" : false }, () => {
    assert.throws(() => new SeatbeltSandbox().run("echo hi", { cwd: tmpdir(), approved: [], homeDir: "/tmp" }), /unavailable/i);
  });
});

describe("SeatbeltSandbox enforcement", { skip: darwin ? false : "requires macOS sandbox-exec" }, () => {
  test("a denied credential read leaves the secret unobtained (assert on EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-read-")));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_rsa"), "TOPSECRET-XYZ");
    const out = join(home, "out.txt");
    new SeatbeltSandbox().run(`cat ${join(home, ".ssh", "id_rsa")} > ${out} 2>/dev/null || true`, { cwd: home, approved: [], homeDir: home });
    const got = existsSync(out) ? readFileSync(out, "utf8") : "";
    assert.ok(!got.includes("TOPSECRET-XYZ"), "the secret bytes must NOT have been obtained");
  });

  test("a denied network connection never lands (loopback listener)", async () => {
    const got: boolean[] = [];
    const server = net.createServer((s) => { got.push(true); s.destroy(); });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as net.AddressInfo).port;
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-net-")));
    new SeatbeltSandbox().run(`nc -z -G 2 127.0.0.1 ${port} || true`, { cwd: home, approved: [], homeDir: home });
    await new Promise((r) => setTimeout(r, 200));
    server.close();
    assert.equal(got.length, 0, "the sandboxed connection must not have reached the listener");
  });

  test("an unapproved credential env-var never reaches the script (assert on EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-env-")));
    const out = join(home, "leak.txt");
    const cmd = `node -e "require('fs').writeFileSync('${out}', String(process.env.SECRET_API_KEY||''))"`;
    const env = scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, []);
    new SeatbeltSandbox().run(cmd, { cwd: home, approved: [], homeDir: home, env });
    assert.ok(!(existsSync(out) ? readFileSync(out, "utf8") : "").includes("TOPSECRET-ENV"), "the credential env-var must not have reached the script");

    const approved: Capability[] = [{ kind: "env", target: "SECRET_API_KEY", evidence: [] }];
    const env2 = scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, approved);
    new SeatbeltSandbox().run(cmd, { cwd: home, approved, homeDir: home, env: env2 });
    assert.ok(readFileSync(out, "utf8").includes("TOPSECRET-ENV"), "an approved env var is passed through");
  });

  test("an unapproved write to a sensitive path is denied (planted file unchanged)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-write-")));
    const rc = join(home, ".zshrc");        // write-only persistence entry
    const allowed = join(home, "allowed.txt");
    writeFileSync(rc, "ORIGINAL");
    new SeatbeltSandbox().run(`echo OK > "${allowed}"; echo PWNED >> "${rc}" 2>/dev/null || true`, { cwd: home, approved: [], homeDir: home });
    assert.equal(readFileSync(allowed, "utf8").trim(), "OK", "script must have executed (positive control)");
    assert.equal(readFileSync(rc, "utf8"), "ORIGINAL", "the denied write must have been blocked");
  });

  test("a filesystem approval relaxes the write deny at the kernel level (criterion 3)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-fsapprove-")));
    const rc = join(home, ".zshrc");
    writeFileSync(rc, "ORIGINAL");
    new SeatbeltSandbox().run(`echo INJECTED >> "${rc}" 2>/dev/null || true`, { cwd: home, approved: [], homeDir: home });
    assert.equal(readFileSync(rc, "utf8"), "ORIGINAL", "unapproved write to ~/.zshrc must be blocked");
    const approved: Capability[] = [{ kind: "filesystem", target: ".zshrc", evidence: [] }];
    new SeatbeltSandbox().run(`echo INJECTED >> "${rc}"`, { cwd: home, approved, homeDir: home });
    assert.ok(readFileSync(rc, "utf8").includes("INJECTED"), "an approved filesystem write must succeed");
  });

  test("a denied credential read surfaces a confirmed runtime violation", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sentinel-home-")));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_rsa"), "TOPSECRET-XYZ");
    // A propagating probe: let the EPERM print to stderr and exit non-zero.
    const cmd = `node -e "require('fs').readFileSync(require('path').join(process.env.HOME,'.ssh','id_rsa'))"`;
    const r = new SeatbeltSandbox().run(cmd, { cwd: tmpdir(), approved: [], homeDir: home, env: { ...process.env, HOME: home } });
    assert.notEqual(r.exitCode, 0, "positive control: the denied read must fail the process");
    assert.equal(r.violation?.kind, "filesystem");
    assert.equal(r.violation?.confidence, "confirmed");
    assert.ok(r.violation?.target?.includes(".ssh"), "target must name the ssh path");
  });

  test("a write to the Install directory (cwd, the floor) succeeds — positive control", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-floor-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "sb-work-")));
    const inside = join(work, "build-output.txt");
    const r = new SeatbeltSandbox().run(`echo OK > "${inside}"`, { cwd: work, approved: [], homeDir: home });
    assert.equal(r.exitCode, 0);
    assert.equal(readFileSync(inside, "utf8").trim(), "OK", "a write inside the floor (cwd) must succeed");
  });

  test("a persistence write is denied by the carve-out even though the fake $HOME is under the floor's temp dir", () => {
    // NOTE: os.tmpdir() is in the write floor, and this fake $HOME lives under it,
    // so ~/.zshrc sits inside an allowed ancestor. It is still denied — the
    // SENSITIVE_PATHS write carve-out (emitted after the floor allow) re-denies it.
    // This is why the carve-out is load-bearing, not just attribution.
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-carve-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "sb-cwork-")));
    const rc = join(home, ".zshrc");
    writeFileSync(rc, "ORIGINAL");
    new SeatbeltSandbox().run(`echo PWNED >> "${rc}" 2>/dev/null || true`, { cwd: work, approved: [], homeDir: home });
    assert.equal(readFileSync(rc, "utf8"), "ORIGINAL", "the persistence write must be denied by the carve-out");
  });

  test("a real /dev/null redirect still works under write-deny", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-dev-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "sb-devwork-")));
    const r = new SeatbeltSandbox().run(`echo hi > /dev/null && echo DEVOK`, { cwd: work, approved: [], homeDir: home });
    assert.equal(r.exitCode, 0);
    assert.ok(r.stdout.includes("DEVOK"), "device writes must still work");
  });

  test("a $HOME read outside the read-allow list is denied; the project tree + a build stay readable", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-read-")));
    const proj = join(home, "app"); mkdirSync(join(proj, "node_modules", "dep"), { recursive: true });
    writeFileSync(join(proj, "node_modules", "dep", "index.js"), "module.exports=1");
    writeFileSync(join(home, "secret.txt"), "TOPSECRET");           // in $HOME, NOT in the allow list
    const cwd = join(proj, "node_modules", "pkg"); mkdirSync(cwd, { recursive: true });
    const r = new SeatbeltSandbox().run(
      `node -e "require('${join(proj, "node_modules", "dep", "index.js")}'); process.stdout.write('DEP_OK'); try{require('fs').readFileSync('${join(home, "secret.txt")}');process.stdout.write('LEAK')}catch(e){process.stdout.write('READ_DENIED')}"`,
      { cwd, approved: [], homeDir: home, projectRoot: proj },
    );
    assert.ok(r.stdout.includes("DEP_OK"), "the project tree must be readable (require resolves)");
    assert.ok(r.stdout.includes("READ_DENIED") && !r.stdout.includes("LEAK"), "a non-allow-listed $HOME read must be denied");
  });
});

describe("runLifecycleScripts", { skip: darwin ? false : "requires macOS sandbox-exec" }, () => {
  test("runs present hooks under the sandbox and a benign script succeeds", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "sb-run-")));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: "echo built > built.txt" } }));
    const r = runLifecycleScripts({ packageDir: dir, sandbox: new SeatbeltSandbox(), homeDir: process.env.HOME ?? "/tmp" });
    assert.equal(r.failed, false);
    assert.equal(r.results.length, 1);
    assert.equal(r.results[0]?.hook, "postinstall");
    assert.equal(readFileSync(join(dir, "built.txt"), "utf8").trim(), "built");
  });
});
