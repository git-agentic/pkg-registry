import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Capability } from "@sentinel/core";
import { computeDenySet, isSafeGrantTarget } from "../src/deny-set.js";
import { generateProfile } from "../src/profile.js";

const HOME = "/Users/test";
const fsCap = (target: string): Capability => ({ kind: "filesystem", target, evidence: [] });
const netCap = (): Capability => ({ kind: "network", target: "*", evidence: [] });

describe("computeDenySet", () => {
  test("no approvals: denies sensitive paths and network", () => {
    const ds = computeDenySet([], { homeDir: HOME, platform: "darwin" });
    assert.ok(ds.networkDenied);
    assert.ok(ds.deniedPaths.some((p) => p.includes(".ssh")), "ssh must be denied");
    assert.ok(ds.deniedPaths.every((p) => !p.startsWith("~")), "paths must be home-expanded");
  });

  test("an approved network capability lifts networkDenied", () => {
    assert.equal(computeDenySet([netCap()], { homeDir: HOME, platform: "darwin" }).networkDenied, false);
  });

  test("an approved filesystem capability covering ~/.ssh removes it from deniedPaths", () => {
    const ds = computeDenySet([fsCap("~/.ssh")], { homeDir: HOME, platform: "darwin" });
    assert.ok(!ds.deniedPaths.some((p) => p.includes(".ssh")), "approved ssh must not be denied");
  });

  test("darwin canonicalizes /etc to /private/etc", () => {
    const ds = computeDenySet([], { homeDir: HOME, platform: "darwin" });
    assert.ok(ds.deniedPaths.includes("/private/etc/passwd"), "must canonicalize /etc → /private/etc");
  });

  test("non-drift: every deniedPath appears in the generated Seatbelt profile", () => {
    const approved: Capability[] = [fsCap("~/.aws")];
    const ds = computeDenySet(approved, { homeDir: HOME, platform: "darwin" });
    const profile = generateProfile(approved, { homeDir: HOME, cwd: "/work/pkg", tmpDir: "/private/tmp/tmpdir-x" });
    for (const p of ds.deniedPaths) {
      assert.ok(profile.includes(p), `profile must deny ${p} (deny-set/profile drift)`);
    }
  });
});

describe("isSafeGrantTarget", () => {
  test("safe targets are allowed", () => {
    assert.ok(isSafeGrantTarget(".zshrc"));
    assert.ok(isSafeGrantTarget(".config/app"));
    assert.ok(isSafeGrantTarget("/home/x/ok"));
  });

  test("empty, wildcard, and bare-root targets are rejected", () => {
    assert.ok(!isSafeGrantTarget(""));
    assert.ok(!isSafeGrantTarget("*"));
    assert.ok(!isSafeGrantTarget("/"));
  });

  test("any '..' path-traversal segment is rejected", () => {
    assert.ok(!isSafeGrantTarget(".."));
    assert.ok(!isSafeGrantTarget("../escape"));
    assert.ok(!isSafeGrantTarget("a/../b"));
  });
});
