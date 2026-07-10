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
    const profile = generateProfile(approved, { homeDir: HOME, cwd: "/work/pkg", tmpDir: "/private/tmp/tmpdir-x", nodePrefix: "/usr/local", projectRoot: "/work/pkg" });
    for (const p of ds.deniedPaths) {
      assert.ok(profile.includes(p), `profile must deny ${p} (deny-set/profile drift)`);
    }
  });
});

const procCap = (target: string): Capability => ({ kind: "process", target, evidence: [] });
const EXEC_OPTS = { homeDir: HOME, platform: "darwin" as const, nodePrefix: "/usr/local", projectRoot: "/work/pkg", cwd: "/work/pkg", tmpDir: "/private/tmp/tmpdir-x" };

describe("computeDenySet — exec (Phase 28)", () => {
  test("darwin with exec opts: execDenied, floor in execAllowedPaths, carve-out in execDeniedPaths", () => {
    const ds = computeDenySet([], EXEC_OPTS);
    assert.equal(ds.execDenied, true);
    assert.ok(ds.execAllowedPaths!.includes("/bin"));
    assert.ok(ds.execAllowedPaths!.includes("/work/pkg"));
    assert.ok(ds.execDeniedPaths!.includes("/usr/bin/curl"));
    assert.ok(ds.writeAllowedPaths!.includes("/work/pkg"));
    assert.ok(ds.writeAllowedPaths!.some((p) => p.startsWith("/private/tmp")));
  });

  test("without exec opts (legacy callers / linux): exec fields absent", () => {
    const ds = computeDenySet([], { homeDir: HOME, platform: "linux" });
    assert.equal(ds.execDenied, undefined);
    assert.equal(ds.execDeniedPaths, undefined);
  });

  test("a command Grant removes its carve-out entries; a path Grant lands in execAllowedPaths", () => {
    const ds = computeDenySet([procCap("curl"), procCap("~/tools")], EXEC_OPTS);
    assert.ok(!ds.execDeniedPaths!.some((p) => p.endsWith("/curl")));
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/wget")));
    assert.ok(ds.execAllowedPaths!.includes("/Users/test/tools"));
  });

  test("non-drift: every execDeniedPath and execAllowedPath appears in the generated profile", () => {
    const approved: Capability[] = [procCap("curl"), procCap("~/tools")];
    const ds = computeDenySet(approved, EXEC_OPTS);
    const profile = generateProfile(approved, { homeDir: HOME, cwd: "/work/pkg", tmpDir: "/private/tmp/tmpdir-x", nodePrefix: "/usr/local", projectRoot: "/work/pkg" });
    for (const p of ds.execDeniedPaths!) assert.ok(profile.includes(`(literal "${p}")`), `profile must carve out ${p}`);
    for (const p of ds.execAllowedPaths!) assert.ok(profile.includes(`(subpath "${p}")`), `profile must exec-allow ${p}`);
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
