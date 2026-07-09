import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateBwrapArgs } from "../src/bwrap.js";
import type { Capability } from "@sentinel/core";

const fs = (target: string): Capability => ({ kind: "filesystem", target, evidence: [] });
const net = (target: string): Capability => ({ kind: "network", target, evidence: [] });
const HOME = "/home/test";
const OPTS = { homeDir: HOME, cwd: "/work/pkg", tmpDir: "/tmp/build" };
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

const OPTS2 = { homeDir: "/home/x", cwd: "/work/pkg", tmpDir: "/tmp/build" };

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
});
