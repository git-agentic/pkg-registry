import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, realpathSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import * as enforce from "../src/enforce.js";

const { EnforceError, isRootScript } = enforce;
const assertIntegrityBinding = (...a: unknown[]) => (enforce as any).assertIntegrityBinding(...a);
import { enforceNpmEnv } from "../src/index.js";
import type { Manifest } from "../src/format.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHELL = join(HERE, "..", "src", "script-shell.ts");
const TSX = import.meta.resolve("tsx");

const SERVED = "sha512-SERVEDSERVEDSERVEDSERVEDSERVEDSERVEDSERVEDSERVEDSERVEDSERVEDSERVEDSERVEDSERVEDSERVEDSERVEDSERVEDSERVED==";
const OTHER = "sha512-OTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHEROTHER==";
const mk = (integrity: string): Manifest => ({
  meta: { name: "dep", version: "1.0.0", integrity },
  verdict: "allow", approvalState: "n-a", capabilities: [], approvalRequired: [], inheritedFrom: null,
});

describe("F11 isRootScript trusts only SENTINEL_ROOT (fail closed)", () => {
  test("cwd equal to SENTINEL_ROOT is the root project", () => {
    assert.equal(isRootScript("/proj", "/proj"), true);
  });
  test("a missing, empty or relative SENTINEL_ROOT is never root", () => {
    assert.equal(isRootScript("/proj", undefined), false);
    assert.equal(isRootScript("/proj", ""), false);
    assert.equal(isRootScript("/proj", "proj"), false);
  });
  test("a nested npm's own dir (e.g. a git dependency's prepare) is not root even when INIT_CWD was reset to it", () => {
    assert.equal(isRootScript("/tmp/cacache/git-clone", "/proj"), false);
  });
  test("cwd under node_modules is a dependency even if it equals the claimed root", () => {
    assert.equal(isRootScript("/proj/node_modules/dep", "/proj/node_modules/dep"), false);
  });
});

describe("F11 assertIntegrityBinding", () => {
  test("accepts an exactly matching integrity", () => {
    assert.doesNotThrow(() => assertIntegrityBinding(mk(SERVED), SERVED));
  });
  test("accepts a multi-token SRI when every same-algorithm token matches", () => {
    assert.doesNotThrow(() => assertIntegrityBinding(mk(SERVED), `sha1-AAAA ${SERVED}`));
  });
  test("a missing or blank integrity fails closed", () => {
    assert.throws(() => assertIntegrityBinding(mk(SERVED), undefined), EnforceError);
    assert.throws(() => assertIntegrityBinding(mk(SERVED), "  "), EnforceError);
  });
  test("a mismatched integrity fails closed", () => {
    assert.throws(() => assertIntegrityBinding(mk(SERVED), OTHER), EnforceError);
    assert.throws(() => assertIntegrityBinding(mk(SERVED), `${SERVED} ${OTHER}`), EnforceError);
  });
  test("an integrity in a different algorithm than the audited one cannot be compared: fail closed", () => {
    assert.throws(() => assertIntegrityBinding(mk(SERVED), "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="), EnforceError);
  });
  test("an unknown algorithm in the manifest fails closed", () => {
    assert.throws(() => assertIntegrityBinding(mk("md5-AAAA"), "md5-AAAA"), EnforceError);
  });
});

describe("F11 enforceNpmEnv pins SENTINEL_ROOT to the realpath of the install cwd", () => {
  test("sets SENTINEL_ROOT and overrides a pre-set value", () => {
    const env = enforceNpmEnv({ SENTINEL_ROOT: "/attacker" }, { proxy: "p", wrapperPath: "w", approve: [] });
    assert.equal(env.SENTINEL_ROOT, realpathSync(process.cwd()));
  });
});

// End-to-end through the real wrapper: a stub proxy serves the manifest; the wrapper must refuse
// (exit 70, command never run) unless the package identity is bound to the audited bytes.
const sandboxWorks = (() => {
  if (process.platform === "darwin") return true;
  if (process.platform !== "linux") return false;
  const r = spawnSync("bwrap", ["--ro-bind", "/", "/", "--dev", "/dev", "true"], { encoding: "utf8" });
  return !r.error && r.status === 0;
})();

describe("F11 script-shell (e2e, real wrapper)", () => {
  let server: Server; let proxy: string;
  before(async () => {
    server = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(mk(SERVED)));
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    proxy = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  after(() => server?.close());

  const runShell = (cwd: string, env: NodeJS.ProcessEnv) => new Promise<{ code: number | null; out: string }>((resolve) => {
    const child = spawn("node", ["--import", TSX, SHELL, "-c", "echo ran > marker.txt"], {
      cwd, env: { ...process.env, SENTINEL_ENFORCE: "1", ...env },
    });
    let out = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { out += d; });
    child.on("close", (code) => resolve({ code, out }));
  });
  const project = () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "enf-id-")));
    const dep = join(root, "node_modules", "dep");
    mkdirSync(dep, { recursive: true });
    return { root, dep };
  };

  test("dependency without npm_package_integrity is refused and the command never runs", async () => {
    const { root, dep } = project();
    const r = await runShell(dep, { SENTINEL_ROOT: root, SENTINEL_PROXY: proxy, npm_package_name: "dep", npm_package_version: "1.0.0" });
    assert.equal(r.code, 70, r.out);
    assert.match(r.out, /integrity/i);
    assert.ok(!existsSync(join(dep, "marker.txt")));
  });
  test("a package-declared name/version with a DIFFERENT integrity is refused", async () => {
    const { root, dep } = project();
    const r = await runShell(dep, { SENTINEL_ROOT: root, SENTINEL_PROXY: proxy, npm_package_name: "dep", npm_package_version: "1.0.0", npm_package_integrity: OTHER });
    assert.equal(r.code, 70, r.out);
    assert.ok(!existsSync(join(dep, "marker.txt")));
  });
  test("a nested npm's script outside node_modules (INIT_CWD reset to it) is NOT treated as root", async () => {
    const { root } = project();
    const gitDep = realpathSync(mkdtempSync(join(tmpdir(), "enf-gitdep-")));
    const r = await runShell(gitDep, { SENTINEL_ROOT: root, INIT_CWD: gitDep, SENTINEL_APPROVE: "" });
    assert.equal(r.code, 70, r.out);
    assert.ok(!existsSync(join(gitDep, "marker.txt")), "the script must not have run with root approvals");
  });
  test("with SENTINEL_ROOT missing, even a cwd equal to INIT_CWD is NOT root (fail closed)", async () => {
    const gitDep = realpathSync(mkdtempSync(join(tmpdir(), "enf-noroot-")));
    const r = await runShell(gitDep, { INIT_CWD: gitDep });
    assert.equal(r.code, 70, r.out);
    assert.ok(!existsSync(join(gitDep, "marker.txt")));
  });
  test("positive control: matching integrity runs the script under the sandbox", { skip: sandboxWorks ? false : "requires a working sandbox" }, async () => {
    const { root, dep } = project();
    const r = await runShell(dep, { SENTINEL_ROOT: root, SENTINEL_PROXY: proxy, npm_package_name: "dep", npm_package_version: "1.0.0", npm_package_integrity: SERVED });
    assert.equal(r.code, 0, r.out);
    assert.ok(existsSync(join(dep, "marker.txt")));
  });
  test("positive control: the root project's own script (cwd === SENTINEL_ROOT) still runs", { skip: sandboxWorks ? false : "requires a working sandbox" }, async () => {
    const { root } = project();
    const r = await runShell(root, { SENTINEL_ROOT: root, INIT_CWD: root });
    assert.equal(r.code, 0, r.out);
    assert.ok(existsSync(join(root, "marker.txt")));
  });
});
