import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateBwrapArgs } from "../src/bwrap.js";
import type { Capability } from "@sentinel/core";

const fs = (target: string): Capability => ({ kind: "filesystem", target, evidence: [] });
const net = (target: string): Capability => ({ kind: "network", target, evidence: [] });
const HOME = "/home/test";
const argv = (a: Capability[]) => generateBwrapArgs(a, { homeDir: HOME }).join(" ");

describe("generateBwrapArgs", () => {
  test("binds root read-write and sets up /dev and /proc", () => {
    assert.match(argv([]), /--bind \/ \/ --dev \/dev --proc \/proc/);
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
    assert.match(a, /--tmpfs \/var\/spool\/cron\/crontabs/);
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
    assert.doesNotMatch(a, /\/home\/test\/\.npmrc/);   // the ~/.npmrc mask is gone
    assert.match(a, /\.ssh/);                          // unrelated denies remain
  });
  test("filesystem coverage is path-segment-anchored, not substring", () => {
    assert.match(argv([fs("ssh")]), /--tmpfs \/home\/test\/\.ssh/);  // 'ssh' must NOT cancel '.ssh'
    assert.doesNotMatch(argv([fs(".ssh")]), /--tmpfs \/home\/test\/\.ssh/);  // exact segment cancels
  });
  test("deterministic for the same inputs", () => {
    assert.deepEqual(generateBwrapArgs([net("x")], { homeDir: HOME }), generateBwrapArgs([net("x")], { homeDir: HOME }));
  });
});
