import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import { writeAllowFloor } from "../src/write-floor.js";
import { generateProfile } from "../src/profile.js";
import { generateBwrapArgs } from "../src/bwrap.js";
import { readAllowList } from "../src/read-allow.js";
import { withPerRunDevdir } from "../src/devdir.js";
import { SeatbeltSandbox } from "../src/seatbelt.js";
import type { Capability } from "@git-agentic/sentinel-core";

const net: Capability = { kind: "network", target: "198.51.100.5", evidence: [] };
const OPTS = { homeDir: "/Users/x", cwd: "/work/pkg", tmpDir: "/var/folders/z/T", nodePrefix: "/usr/local", projectRoot: "/Users/x/app" };

describe("node-gyp header caches are read-only inside the sandbox", () => {
  test("the write floor no longer lists ~/.node-gyp or ~/.cache/node-gyp", () => {
    const floor = writeAllowFloor({ cwd: "/w", tmpDir: "/t" });
    assert.ok(!floor.some((p) => p.includes("node-gyp")), floor.join(","));
  });
  test("they stay READable (read-allow list)", () => {
    const ro = readAllowList({ nodePrefix: "/n", projectRoot: "/p" });
    assert.ok(ro.includes("~/.node-gyp") && ro.includes("~/.cache"));
  });
  test("seatbelt: the file-write allow does not cover the node-gyp caches", () => {
    const writeLine = generateProfile([], OPTS).split("\n").find((l) => l.startsWith("(allow file-write*"))!;
    assert.ok(writeLine && !writeLine.includes("node-gyp"), writeLine);
  });
  test("bwrap: the node-gyp caches are not re-bound read-write", () => {
    const args = generateBwrapArgs([], { ...OPTS, homeDir: "/home/x" });
    const rw = args.flatMap((a, i) => (a === "--bind" || a === "--bind-try" ? [args[i + 1]] : []));
    assert.ok(!rw.some((p) => p.includes("node-gyp")), rw.join(","));
  });
});

describe("withPerRunDevdir (network approved only; host-owned dir outside every write floor)", () => {
  const mkHome = () => mkdtempSync(join(tmpdir(), "gyp-home-"));
  test("without a network approval the env and grants are returned untouched", () => {
    const env = { PATH: "/usr/bin", npm_config_devdir: "/home/x/.cache/node-gyp" };
    const r = withPerRunDevdir(env, [], mkHome());
    assert.deepEqual(r.env, env);
    assert.deepEqual(r.approved, []);
    r.cleanup();
  });
  test("with a network approval: a fresh 0700 dir under <home>/.cache/sentinel-gyp, NOT under tmpdir", () => {
    const home = mkHome();
    const a = withPerRunDevdir({ PATH: "/usr/bin" }, [net], home);
    const b = withPerRunDevdir({ PATH: "/usr/bin" }, [net], home);
    const da = a.env.npm_config_devdir!;
    assert.ok(da && b.env.npm_config_devdir !== da, "unique per run");
    assert.equal(dirname(da), join(home, ".cache", "sentinel-gyp"));
    assert.equal(statSync(da).mode & 0o777, 0o700);
    assert.equal(statSync(dirname(da)).mode & 0o777, 0o700);
    assert.equal(a.env.PATH, "/usr/bin");
    a.cleanup(); b.cleanup();
    assert.ok(!existsSync(da));
  });
  test("read-write is granted on that one directory only, through an ordinary filesystem grant", () => {
    const home = mkHome();
    const r = withPerRunDevdir({}, [net], home);
    const grants = r.approved.filter((c) => c.kind === "filesystem");
    assert.deepEqual(grants.map((g) => g.target), [r.env.npm_config_devdir]);
    assert.ok(r.approved.includes(net), "the original approvals are kept");
    r.cleanup();
  });
  test("a bwrap argv built from the grant binds exactly that dir read-write", () => {
    const home = "/home/x";
    const dir = `${home}/.cache/sentinel-gyp/run-AbC`;
    const args = generateBwrapArgs([net, { kind: "filesystem", target: dir, evidence: [] }], { ...OPTS, homeDir: home });
    const rw = args.flatMap((a, i) => (a === "--bind" || a === "--bind-try" ? [args[i + 1]] : []));
    assert.ok(rw.includes(dir));
    assert.ok(!rw.includes(`${home}/.cache/sentinel-gyp`) && !rw.includes(`${home}/.cache`));
  });
  test("seatbelt: the profile write-allows that dir only (argument test)", () => {
    const dir = "/Users/x/.cache/sentinel-gyp/run-AbC";
    const line = generateProfile([net, { kind: "filesystem", target: dir, evidence: [] }], OPTS).split("\n").find((l) => l.startsWith("(allow file-write*"))!;
    assert.ok(line.includes(`(subpath "${dir}")`));
    assert.ok(!line.includes(`(subpath "/Users/x/.cache")`) && !line.includes('sentinel-gyp")'));
  });
  // The point of moving it: tmpdir is in EVERY sandbox's write floor, so a lingering process of an
  // earlier run could still write there. Real home OUTSIDE tmpdir so the floor does not mask the result.
  test("effect: only this run's grant can write the devdir; a sibling is unwritable (seatbelt)", { skip: process.platform === "darwin" ? false : "requires macOS sandbox-exec" }, () => {
    const home = realpathSync(mkdtempSync(join(process.cwd(), ".gyp-eff-")));
    try {
      const proj = join(home, "proj"); mkdirSync(proj);
      const r = withPerRunDevdir({ PATH: "/usr/bin:/bin" }, [net], home);
      const sibling = join(dirname(r.env.npm_config_devdir!), "old-run"); mkdirSync(sibling);
      const sb = new SeatbeltSandbox();
      const ok = sb.run('echo ok > "$npm_config_devdir/h.txt"; echo rc=$?; echo bad > "' + join(sibling, "p.txt") + '"; echo rc2=$?', { cwd: proj, approved: r.approved, homeDir: home, env: r.env });
      assert.match(ok.stdout, /rc=0/, ok.stderr);
      assert.match(ok.stdout, /rc2=[1-9]/, "a sibling devdir (an earlier run) must stay unwritable");
      assert.ok(existsSync(join(r.env.npm_config_devdir!, "h.txt")));
      assert.ok(!existsSync(join(sibling, "p.txt")));
      const without = sb.run('echo x > "$npm_config_devdir/n.txt"; echo rc=$?', { cwd: proj, approved: [net], homeDir: home, env: r.env });
      assert.match(without.stdout, /rc=[1-9]/, "without the grant the dir is not writable");
      r.cleanup();
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
});
