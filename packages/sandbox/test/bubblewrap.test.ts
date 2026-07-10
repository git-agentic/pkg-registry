import assert from "node:assert/strict";
import net from "node:net";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { BubblewrapSandbox } from "../src/bubblewrap.js";
import { runLifecycleScripts } from "../src/runner.js";
import { scrubEnv } from "../src/env.js";
import type { Capability } from "@sentinel/core";

// dist sibling of the compiled bubblewrap.js; in the source tree the helper lands in
// packages/sandbox/dist/landlock-exec after `npm run build`.
const HELPER_BUILT = existsSync(fileURLToPath(new URL("../dist/landlock-exec", import.meta.url)));
const skipNoHelper = HELPER_BUILT ? false : "requires the built landlock-exec helper (cc on Linux)";

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
    const work = realpathSync(mkdtempSync(join(tmpdir(), "bw-readwork-")));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_rsa"), "TOPSECRET-XYZ");
    const out = join(work, "out.txt"); // write to cwd (persists); $HOME is a read-denied tmpfs under Slice 2
    new BubblewrapSandbox().run(`cat ${join(home, ".ssh", "id_rsa")} > ${out} 2>/dev/null || true`, { cwd: work, approved: [], homeDir: home });
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
    const work = realpathSync(mkdtempSync(join(tmpdir(), "bw-network-")));
    const ran = join(work, "ran.txt"); // cwd (persists); $HOME is a read-denied tmpfs under Slice 2
    // Connect via node, not a /dev/tcp bashism — BubblewrapSandbox runs `/bin/sh -c`, which is
    // dash on Ubuntu (no /dev/tcp). Under --unshare-net the sandbox has its own netns, so this
    // 127.0.0.1 cannot reach the host listener; the assertion is on the listener side (EFFECT).
    // The script also writes a ran-marker so we can prove bwrap actually launched it.
    const connect = `node -e "require('fs').writeFileSync('${ran}','RAN');const s=require('net').connect(${port},'127.0.0.1');s.on('connect',()=>s.end());s.on('error',()=>{});setTimeout(()=>process.exit(0),400)"`;
    new BubblewrapSandbox().run(connect, { cwd: work, approved: [], homeDir: home });
    await new Promise((r) => setTimeout(r, 200));
    server.close();
    assert.ok(existsSync(ran), "positive control: the sandboxed script must have run");
    assert.equal(got.length, 0, "the sandboxed connection must not have reached the listener");
  });

  test("an unapproved write to a persistence path is denied (planted file unchanged)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-write-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "bw-writework-")));
    const rc = join(home, ".bashrc");
    const allowed = join(work, "allowed.txt"); // positive control in cwd (persists)
    writeFileSync(rc, "ORIGINAL");
    new BubblewrapSandbox().run(`echo OK > "${allowed}"; echo PWNED >> "${rc}" 2>/dev/null || true`, { cwd: work, approved: [], homeDir: home });
    assert.equal(readFileSync(allowed, "utf8").trim(), "OK", "script must have executed (positive control)");
    assert.equal(readFileSync(rc, "utf8"), "ORIGINAL", "the denied write must have been blocked");
  });

  test("an unapproved credential env-var never reaches the script; approval passes it through (EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-env-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "bw-envwork-")));
    const out = join(work, "leak.txt"); // cwd (persists); $HOME is a read-denied tmpfs under Slice 2
    const cmd = `node -e "require('fs').writeFileSync('${out}', String(process.env.SECRET_API_KEY||''))"`;
    new BubblewrapSandbox().run(cmd, { cwd: work, approved: [], homeDir: home, env: scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, []) });
    assert.ok(existsSync(out), "positive control: node must have written the output file in the first (no-approval) run");
    assert.ok(!(existsSync(out) ? readFileSync(out, "utf8") : "").includes("TOPSECRET-ENV"), "the credential env-var must not have reached the script");
    const approved: Capability[] = [{ kind: "env", target: "SECRET_API_KEY", evidence: [] }];
    new BubblewrapSandbox().run(cmd, { cwd: work, approved, homeDir: home, env: scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, approved) });
    assert.ok(readFileSync(out, "utf8").includes("TOPSECRET-ENV"), "an approved env var is passed through");
  });

  test("a filesystem approval relaxes the credential read deny (EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-fsapprove-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "bw-fsapprovework-")));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_rsa"), "APPROVED-SECRET");
    const out = join(work, "out.txt"); // cwd (persists); the approved read of $HOME/.ssh is re-allowed
    const approved: Capability[] = [{ kind: "filesystem", target: ".ssh", evidence: [] }];
    new BubblewrapSandbox().run(`cat ${join(home, ".ssh", "id_rsa")} > ${out} 2>/dev/null || true`, { cwd: work, approved, homeDir: home });
    assert.ok(readFileSync(out, "utf8").includes("APPROVED-SECRET"), "an approved filesystem read must succeed");
  });

  test("a non-denied path (the Install dir) stays readable and writable inside the sandbox (positive control)", () => {
    // Under Slice 2 an arbitrary $HOME path is read-DENIED; the read/write positive control uses
    // the Install directory (cwd), which is re-bound rw and stays fully readable+writable.
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-allow-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "bw-allowwork-")));
    writeFileSync(join(work, "data.txt"), "HELLO");
    const out = join(work, "copy.txt");
    new BubblewrapSandbox().run(`cat ${join(work, "data.txt")} > ${out}`, { cwd: work, approved: [], homeDir: home });
    assert.equal(readFileSync(out, "utf8").trim(), "HELLO", "non-denied read/write must work");
  });

  test("a write to the Install directory (cwd, the floor) succeeds — positive control", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-floor-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "bw-work-")));
    const inside = join(work, "build-output.txt");
    const r = new BubblewrapSandbox().run(`echo OK > "${inside}"`, { cwd: work, approved: [], homeDir: home });
    assert.equal(r.exitCode, 0);
    assert.equal(readFileSync(inside, "utf8").trim(), "OK", "a write inside the floor (cwd) must succeed");
  });

  test("a persistence write is denied by the carve-out even though the fake $HOME is under the floor's temp dir", () => {
    // NOTE: os.tmpdir() is in the write floor, and this fake $HOME lives under it,
    // so ~/.bashrc sits inside an allowed ancestor. It is still denied — the
    // SENSITIVE_PATHS write carve-out (emitted after the floor allow) re-denies it.
    // This is why the carve-out is load-bearing, not just attribution.
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-carve-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "bw-cwork-")));
    const rc = join(home, ".bashrc");
    writeFileSync(rc, "ORIGINAL");
    new BubblewrapSandbox().run(`echo PWNED >> "${rc}" 2>/dev/null || true`, { cwd: work, approved: [], homeDir: home });
    assert.equal(readFileSync(rc, "utf8"), "ORIGINAL", "the persistence write must be denied by the carve-out");
  });

  test("a real /dev/null redirect still works under write-deny", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-dev-")));
    const work = realpathSync(mkdtempSync(join(tmpdir(), "bw-devwork-")));
    const r = new BubblewrapSandbox().run(`echo hi > /dev/null && echo DEVOK`, { cwd: work, approved: [], homeDir: home });
    assert.equal(r.exitCode, 0);
    assert.ok(r.stdout.includes("DEVOK"), "device writes must still work");
  });

  test("runLifecycleScripts runs a benign postinstall under bwrap", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "bw-run-")));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: "echo built > built.txt" } }));
    const r = runLifecycleScripts({ packageDir: dir, sandbox: new BubblewrapSandbox(), homeDir: process.env.HOME ?? "/root" });
    assert.equal(r.failed, false, `postinstall failed under bwrap; child stderr: ${r.results.map((x) => x.stderr).join(" | ")}`);
    assert.equal(readFileSync(join(dir, "built.txt"), "utf8").trim(), "built");
  });

  test("a $HOME read outside the read-allow list is contained; the project tree stays readable", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-read-")));
    const proj = join(home, "app"); mkdirSync(join(proj, "node_modules", "dep"), { recursive: true });
    writeFileSync(join(proj, "node_modules", "dep", "index.js"), "module.exports=1");
    writeFileSync(join(home, "secret.txt"), "TOPSECRET");
    const cwd = join(proj, "node_modules", "pkg"); mkdirSync(cwd, { recursive: true });
    const r = new BubblewrapSandbox().run(
      `node -e "require('${join(proj, "node_modules", "dep", "index.js")}'); process.stdout.write('DEP_OK'); try{require('fs').readFileSync('${join(home, "secret.txt")}');process.stdout.write('LEAK')}catch(e){process.stdout.write('READ_DENIED')}"`,
      { cwd, approved: [], homeDir: home, projectRoot: proj },
    );
    const diag = ` [stdout=${JSON.stringify(r.stdout)} stderr=${JSON.stringify(r.stderr.slice(-400))}]`;
    assert.ok(r.stdout.includes("DEP_OK"), "the project tree must be readable" + diag);
    // Containment only — bwrap tmpfs → ENOENT, which classifyViolation does not classify
    // (the accepted Seatbelt/bwrap telemetry asymmetry; report is Seatbelt-only, ADR-0023).
    assert.ok(r.stdout.includes("READ_DENIED") && !r.stdout.includes("LEAK"), "the non-allow-listed $HOME read must be contained" + diag);
  });

  test("the curl carve-out is denied without a Grant and lifted by process:curl", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-exec-curl-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const out = join(proj, "curl-out.txt");
    // curl masked → exec fails; script writes nothing useful:
    new BubblewrapSandbox().run(`/usr/bin/curl --version > "${out}" 2>/dev/null || true`,
      { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    const denied = existsSync(out) ? readFileSync(out, "utf8") : "";
    assert.ok(!denied.includes("curl"), "curl must not run without a Grant");

    const approved: Capability[] = [{ kind: "process", target: "curl", evidence: [] }];
    new BubblewrapSandbox().run(`/usr/bin/curl --version > "${out}"`,
      { cwd: proj, approved, homeDir: home, projectRoot: proj });
    assert.ok(readFileSync(out, "utf8").includes("curl"), "an approved process:curl must run");
  });

  test("a PATH-form Grant (process:/usr/bin/curl) lifts the carve-out on merged-usr (issue #21)", () => {
    // ubuntu-latest is merged-usr (/bin -> /usr/bin): before the #21 fix, the
    // ungranted /bin/curl sibling resolved back to /usr/bin/curl and re-masked it.
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-exec-pathgrant-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const out = join(proj, "curl-out.txt");
    const approved: Capability[] = [{ kind: "process", target: "/usr/bin/curl", evidence: [] }];
    new BubblewrapSandbox().run(`/usr/bin/curl --version > "${out}"`,
      { cwd: proj, approved, homeDir: home, projectRoot: proj });
    assert.ok(readFileSync(out, "utf8").includes("curl"), "a path-form process Grant must lift the merged-usr carve-out");

    // The symlinked invocation form must work under the same grant too:
    new BubblewrapSandbox().run(`/bin/curl --version > "${out}"`,
      { cwd: proj, approved, homeDir: home, projectRoot: proj });
    assert.ok(readFileSync(out, "utf8").includes("curl"), "the /bin symlink invocation form must run under the same grant");
  });

  test("a denied curl exec surfaces a confirmed process violation", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-exec-viol-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const res = new BubblewrapSandbox().run(`/usr/bin/curl --version`,
      { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    assert.notEqual(res.exitCode, 0);
    assert.equal(res.violation?.kind, "process");
    assert.equal(res.violation?.confidence, "confirmed");
  });

  test("positive control: a node_modules/.bin shim and node still run (carve-out doesn't over-block)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-exec-pos-")));
    const proj = join(home, "proj"); mkdirSync(join(proj, "node_modules", ".bin"), { recursive: true });
    const shim = join(proj, "node_modules", ".bin", "hello");
    writeFileSync(shim, "#!/bin/sh\necho SHIM-OK\n", { mode: 0o755 });
    const res = new BubblewrapSandbox().run(`node -e "console.log('NODE-OK')" && "${shim}"`,
      { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    assert.equal(res.exitCode, 0, res.stderr);
    assert.match(res.stdout, /NODE-OK/);
    assert.match(res.stdout, /SHIM-OK/);
  });

  test("Landlock floor: a dropped /tmp binary is denied and surfaces a confirmed process violation", { skip: skipNoHelper }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-home-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const stash = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-stash-")));
    const marker = join(stash, "marker.txt");
    const cmd = `printf '#!/bin/sh\\necho PWNED > "${marker}"\\n' > "${stash}/payload" && chmod +x "${stash}/payload" && "${stash}/payload"`;
    const res = new BubblewrapSandbox().run(cmd, { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    assert.ok(existsSync(join(stash, "payload")), "payload write must succeed (writable location)");
    assert.ok(!existsSync(marker), "the dropped binary must NOT have executed (Landlock floor)");
    assert.notEqual(res.exitCode, 0);
    assert.equal(res.violation?.kind, "process");
    assert.equal(res.violation?.confidence, "confirmed");
  });

  test("Landlock floor: a floor binary (node) and a node_modules/.bin shim still run", { skip: skipNoHelper }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-pos-")));
    const proj = join(home, "proj"); mkdirSync(join(proj, "node_modules", ".bin"), { recursive: true });
    const shim = join(proj, "node_modules", ".bin", "hello");
    writeFileSync(shim, "#!/bin/sh\necho SHIM-OK\n", { mode: 0o755 });
    const res = new BubblewrapSandbox().run(`node -e "console.log('NODE-OK')" && "${shim}"`, { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    assert.equal(res.exitCode, 0, res.stderr);
    assert.match(res.stdout, /NODE-OK/);
    assert.match(res.stdout, /SHIM-OK/);
  });

  test("Landlock floor: a process: path grant outside the floor is --allow'ed and execs (issue #25)", { skip: skipNoHelper }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-grant-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const stash = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-vendor-")));
    const tool = join(stash, "tool");
    writeFileSync(tool, "#!/bin/sh\necho TOOL-OK\n", { mode: 0o755 });
    const res = new BubblewrapSandbox().run(`"${tool}"`, {
      cwd: proj, approved: [{ kind: "process", target: tool, evidence: [] }], homeDir: home, projectRoot: proj,
    });
    assert.equal(res.exitCode, 0, res.stderr);
    assert.match(res.stdout, /TOOL-OK/);
    assert.equal(res.violation, undefined);
  });

  test("Landlock floor: the same outside-floor exec WITHOUT the grant stays denied (confirmed exec-floor-deny)", { skip: skipNoHelper }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-nogrant-")));
    const proj = join(home, "proj"); mkdirSync(proj);
    const stash = realpathSync(mkdtempSync(join(tmpdir(), "bw-ll-vendor2-")));
    const tool = join(stash, "tool");
    writeFileSync(tool, "#!/bin/sh\necho TOOL-OK\n", { mode: 0o755 });
    const res = new BubblewrapSandbox().run(`"${tool}"`, { cwd: proj, approved: [], homeDir: home, projectRoot: proj });
    assert.notEqual(res.exitCode, 0);
    assert.doesNotMatch(res.stdout, /TOOL-OK/);
    assert.equal(res.violation?.kind, "process");
    assert.equal(res.violation?.confidence, "confirmed");
    assert.equal(res.violation?.deniedResource, "exec-floor-deny");
  });
});
