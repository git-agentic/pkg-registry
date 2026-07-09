import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateBwrapArgs } from "../src/bwrap.js";
import type { Capability } from "@sentinel/core";

const fs = (target: string): Capability => ({ kind: "filesystem", target, evidence: [] });
const net = (target: string): Capability => ({ kind: "network", target, evidence: [] });
const HOME = "/home/test";
const OPTS = { homeDir: HOME, cwd: "/work/pkg", tmpDir: "/tmp/build", nodePrefix: "/usr/local", projectRoot: "/work" };
const argv = (a: Capability[]) => generateBwrapArgs(a, OPTS).join(" ");

describe("generateBwrapArgs", () => {
  test("binds root read-only and sets up /dev and /proc", () => {
    assert.match(argv([]), /--ro-bind \/ \/ --dev \/dev --proc \/proc/);
  });
  test("masks credential DIRECTORIES with --tmpfs (subpath)", () => {
    assert.match(argv([]), /--tmpfs \/home\/test\/\.ssh/);
    assert.match(argv([]), /--tmpfs \/home\/test\/\.aws/);
  });
  test("masks credential FILES with --ro-bind /dev/null (literal)", () => {
    assert.match(argv([]), /--ro-bind \/dev\/null \/home\/test\/\.npmrc/);
    assert.match(argv([]), /--ro-bind \/dev\/null \/etc\/passwd/);  // no firmlink canonicalization on Linux
  });
  test("includes Linux persistence paths, not macOS ones", () => {
    const a = argv([]);
    assert.match(a, /--tmpfs \/home\/test\/\.config\/systemd\/user/);
    // /var/spool/cron/crontabs was removed (bwrap cannot create root-owned mountpoint unprivileged)
    assert.doesNotMatch(a, /\/var\/spool\/cron\/crontabs/);
    assert.doesNotMatch(a, /LaunchAgents/);
    assert.doesNotMatch(a, /var\/at\/tabs/);
  });
  test("denies all network with --unshare-net when no network approval", () => {
    assert.match(argv([]), /--unshare-net/);
  });
  test("an approved network capability omits --unshare-net", () => {
    assert.doesNotMatch(argv([net("api.example.com")]), /--unshare-net/);
  });
  test("a filesystem approval omits its deny (both read and write side)", () => {
    const a = argv([fs(".npmrc")]);
    // the ~/.npmrc mask is gone; the path is now rw-bound (Phase 25 Grant) instead of denied
    assert.doesNotMatch(a, /--ro-bind \/dev\/null \/home\/test\/\.npmrc/);
    assert.match(a, /--bind-try \/home\/test\/\.npmrc \/home\/test\/\.npmrc/);
    assert.match(a, /\.ssh/);                          // unrelated denies remain
  });
  test("filesystem coverage is path-segment-anchored, not substring", () => {
    assert.match(argv([fs("ssh")]), /--tmpfs \/home\/test\/\.ssh/);  // 'ssh' must NOT cancel '.ssh'
    assert.doesNotMatch(argv([fs(".ssh")]), /--tmpfs \/home\/test\/\.ssh/);  // exact segment cancels
  });
  test("deterministic for the same inputs", () => {
    assert.deepEqual(generateBwrapArgs([net("x")], OPTS), generateBwrapArgs([net("x")], OPTS));
  });
});

/** Find the source path of a --bind/--ro-bind/--bind-try pair in the flat argv. */
function binds(args: string[], flag: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) if (args[i] === flag) out.push(args[i + 1]!);
  return out;
}

const OPTS2 = { homeDir: "/home/x", cwd: "/work/pkg", tmpDir: "/tmp/build", nodePrefix: "/usr/local", projectRoot: "/work" };

describe("generateBwrapArgs — write-deny (Phase 25)", () => {
  test("root is mounted read-only (reads work, writes denied)", () => {
    const args = generateBwrapArgs([], OPTS2);
    assert.deepEqual(binds(args, "--ro-bind").slice(0, 1), ["/"], "first mount is --ro-bind / /");
    assert.ok(!binds(args, "--bind").includes("/"), "root is NOT rw-bound");
  });
  test("the write floor is re-bound read-write (bind-try tolerates missing cache dirs)", () => {
    const args = generateBwrapArgs([], OPTS2);
    const rw = [...binds(args, "--bind"), ...binds(args, "--bind-try")];
    for (const p of ["/work/pkg", "/tmp/build", "/home/x/.node-gyp", "/home/x/.npm/_logs"]) {
      assert.ok(rw.includes(p), `floor path ${p} must be re-bound rw`);
    }
  });
  test("an approved filesystem capability is re-bound read-write", () => {
    const approved: Capability[] = [{ kind: "filesystem", target: ".config/app", evidence: [] }];
    const rw = [...binds(generateBwrapArgs(approved, OPTS2), "--bind"),
                ...binds(generateBwrapArgs(approved, OPTS2), "--bind-try")];
    assert.ok(rw.includes("/home/x/.config/app"), "approved fs target is rw-bound");
  });
  test("pure — same inputs, identical argv", () => {
    assert.deepEqual(generateBwrapArgs([], OPTS2), generateBwrapArgs([], OPTS2));
  });
  test("host /dev is NOT re-bound rw — bwrap's isolated --dev /dev provides /dev (no host device re-exposure)", () => {
    const args = generateBwrapArgs([], OPTS2);
    const rwSources = [...binds(args, "--bind"), ...binds(args, "--bind-try")];
    assert.ok(!rwSources.includes("/dev"), "host /dev must not be rw-bound over the isolated devtmpfs");
    assert.ok(args.includes("--dev"), "the isolated --dev /dev mount is still present");
  });
  test("a '..' filesystem target is NOT rw-bound (fail-closed escape guard)", () => {
    const approved: Capability[] = [{ kind: "filesystem", target: "..", evidence: [] }];
    const args = generateBwrapArgs(approved, OPTS2);
    const rw = [...binds(args, "--bind"), ...binds(args, "--bind-try")];
    assert.ok(!rw.includes("/home/x/.."), "the parent-of-home escape must not be rw-bound");
  });
  test("a bare '/' filesystem target is NOT rw-bound beyond the read-only root (fail-closed escape guard)", () => {
    const approved: Capability[] = [{ kind: "filesystem", target: "/", evidence: [] }];
    const args = generateBwrapArgs(approved, OPTS2);
    const rw = [...binds(args, "--bind"), ...binds(args, "--bind-try")];
    assert.ok(!rw.includes("/"), "bare root must not be granted rw");
  });
  test("a SENSITIVE mask is skipped when pathExists reports the target absent (bwrap can't mkdir a mount point under a read-only parent)", () => {
    const ssh = "/home/x/.ssh";
    const withSsh = binds(generateBwrapArgs([], { ...OPTS2, pathExists: () => true }), "--tmpfs");
    const withoutSsh = binds(generateBwrapArgs([], { ...OPTS2, pathExists: (p) => p !== ssh }), "--tmpfs");
    assert.ok(withSsh.includes(ssh), "an existing sensitive path (subpath → --tmpfs) IS masked");
    assert.ok(!withoutSsh.includes(ssh), "an absent sensitive path is NOT masked");
    // Other sensitive paths that still 'exist' remain masked — only the absent one is dropped.
    assert.ok(withoutSsh.includes("/home/x/.aws"), "unrelated existing masks are unaffected");
  });
  test("with no pathExists predicate, all SENSITIVE masks are emitted (pure/deterministic default)", () => {
    const tmpfs = binds(generateBwrapArgs([], OPTS2), "--tmpfs");
    assert.ok(tmpfs.includes("/home/x/.ssh") && tmpfs.includes("/home/x/.aws"), "default emits every subpath mask");
  });
});

const OPTS3 = { homeDir: "/home/x", cwd: "/home/x/app/node_modules/pkg", tmpDir: "/tmp/build", nodePrefix: "/home/x/.nvm/versions/node/v24/prefix", projectRoot: "/home/x/app" };

describe("generateBwrapArgs — $HOME-read-deny (Phase 25 Slice 2)", () => {
  test("masks $HOME with a tmpfs, then re-binds the node prefix + project root read-only", () => {
    const args = generateBwrapArgs([], OPTS3);
    assert.ok(binds(args, "--tmpfs").includes("/home/x"), "$HOME is tmpfs-masked (reads denied)");
    const ro = binds(args, "--ro-bind-try"); // node prefix / project root are bound with -try (may be absent)
    assert.ok(ro.includes("/home/x/.nvm/versions/node/v24/prefix"), "node prefix re-bound read-only (node-under-$HOME)");
    assert.ok(ro.includes("/home/x/app"), "project root re-bound read-only (require resolves)");
  });
  test("mount order: $HOME tmpfs, THEN the ro read-allow, THEN the rw cwd on top (cwd stays writable)", () => {
    const args = generateBwrapArgs([], OPTS3);
    const tmpfsHome = args.indexOf("/home/x");                       // --tmpfs <home>
    const roProj = args.indexOf("/home/x/app");                      // --ro-bind-try <projectRoot>
    const rwCwd = args.indexOf("/home/x/app/node_modules/pkg");      // --bind-try <cwd>
    assert.ok(tmpfsHome !== -1 && roProj > tmpfsHome, "ro read-allow comes after the $HOME tmpfs");
    assert.ok(rwCwd > roProj, "the rw cwd bind comes AFTER the ro project bind, so cwd stays writable");
  });
  test("write-deny (slice 1) root is still read-only", () => {
    assert.deepEqual(binds(generateBwrapArgs([], OPTS3), "--ro-bind").slice(0, 1), ["/"]);
  });
  test("projectRoot === homeDir does not re-open $HOME for reads (guard drops it); the tmpfs mask stays", () => {
    const opts = { ...OPTS3, projectRoot: OPTS3.homeDir };
    const args = generateBwrapArgs([], opts);
    const ro = binds(args, "--ro-bind-try");
    assert.ok(!ro.includes("/home/x"), "the guard must drop $HOME itself from the ro read-allow binds");
    assert.ok(binds(args, "--tmpfs").includes("/home/x"), "the --tmpfs $HOME mask is still present");
  });
  test("$HOME under tmpDir: the tmpDir rw bind precedes the $HOME tmpfs so the tmpfs wins (containment preserved)", () => {
    // A hermetic test's fake $HOME lives under os.tmpdir(), which the floor binds rw. If that
    // tmpDir bind came AFTER `--tmpfs $HOME` it would overmount and re-expose $HOME's contents.
    const opts = { homeDir: "/tmp/build/h", cwd: "/tmp/build/h/app/node_modules/pkg", tmpDir: "/tmp/build", nodePrefix: "/usr/local", projectRoot: "/tmp/build/h/app" };
    const args = generateBwrapArgs([], opts);
    const tmpDirBind = args.indexOf("/tmp/build");   // --bind-try <tmpDir> (non-home floor, before the tmpfs)
    const tmpfsHome = args.indexOf("/tmp/build/h");  // --tmpfs <home>
    assert.ok(tmpDirBind !== -1 && tmpfsHome !== -1, "both the tmpDir rw bind and the $HOME tmpfs are present");
    assert.ok(tmpDirBind < tmpfsHome, "the tmpDir rw bind must come BEFORE --tmpfs $HOME so the tmpfs wins for the home subtree");
    // cwd (under $HOME) is re-bound rw AFTER the tmpfs, so it stays writable.
    assert.ok(args.indexOf("/tmp/build/h/app/node_modules/pkg") > tmpfsHome, "cwd is re-bound rw after the tmpfs");
  });
  test("cwd NOT under $HOME with projectRoot===cwd: cwd's rw bind comes AFTER its ro read-allow bind (cwd stays writable)", () => {
    // The enforce/runLifecycleScripts default: projectRoot falls back to cwd, and cwd is a temp
    // dir NOT under the real $HOME. cwd is ro-bound (as projectRoot) then must be rw-bound after.
    const opts = { homeDir: "/home/runner", cwd: "/tmp/bw-run/pkg", tmpDir: "/tmp", nodePrefix: "/usr/local", projectRoot: "/tmp/bw-run/pkg" };
    const args = generateBwrapArgs([], opts);
    const roIdx = args.findIndex((a, i) => a === "--ro-bind-try" && args[i + 1] === "/tmp/bw-run/pkg");
    const rwIdx = args.findIndex((a, i) => a === "--bind-try" && args[i + 1] === "/tmp/bw-run/pkg");
    assert.ok(roIdx !== -1, "cwd is ro-bound as the projectRoot read-allow");
    assert.ok(rwIdx !== -1, "cwd is also rw-bound by the write floor");
    assert.ok(rwIdx > roIdx, "the rw cwd bind must come AFTER the ro projectRoot bind, so cwd stays writable");
  });
});
