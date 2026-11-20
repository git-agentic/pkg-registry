import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { describe, test } from "node:test";
import { writeAllowFloor } from "../src/write-floor.js";
import { generateProfile } from "../src/profile.js";
import { generateBwrapArgs } from "../src/bwrap.js";
import { readAllowList } from "../src/read-allow.js";
import { withPerRunDevdir } from "../src/devdir.js";
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

describe("withPerRunDevdir (network approved only)", () => {
  test("without a network approval the env is returned untouched", () => {
    const env = { PATH: "/usr/bin", npm_config_devdir: "/home/x/.cache/node-gyp" };
    const r = withPerRunDevdir(env, []);
    assert.deepEqual(r.env, env);
    r.cleanup();
  });
  test("with a network approval npm_config_devdir is a fresh per-run dir under tmpdir, removed on cleanup", () => {
    const a = withPerRunDevdir({ PATH: "/usr/bin" }, [net]);
    const b = withPerRunDevdir({ PATH: "/usr/bin" }, [net]);
    const da = a.env.npm_config_devdir!;
    assert.ok(da && b.env.npm_config_devdir !== da, "unique per run");
    assert.ok(da.startsWith(tmpdir()) || da.startsWith(tmpdir().replace(/^\/var/, "/private/var")), da);
    assert.ok(existsSync(da));
    assert.equal(a.env.PATH, "/usr/bin");
    a.cleanup(); b.cleanup();
    assert.ok(!existsSync(da));
  });
});
