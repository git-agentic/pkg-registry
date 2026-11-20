import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { describe, test } from "node:test";
import { generateProfile } from "../src/profile.js";
import { execAllowFloor, linuxExecFloor } from "../src/exec-floor.js";
import { normalizeRunPaths } from "../src/run-paths.js";
import { SeatbeltSandbox } from "../src/seatbelt.js";

const OPTS = { homeDir: "/Users/x", cwd: "/work/pkg", tmpDir: "/var/folders/z/T", nodePrefix: "/usr/local", projectRoot: "/Users/x/app" };

describe("a projectRoot of / must not re-allow everything", () => {
  test("seatbelt: no (subpath \"/\") read re-allow, so the $HOME read deny stays in force", () => {
    const p = generateProfile([], { ...OPTS, projectRoot: "/" });
    assert.ok(!p.includes('(subpath "/")'), p);   // covers the read re-allow AND the exec floor
  });
  test("the exec floors (macOS and Linux/Landlock) drop a / projectRoot", () => {
    assert.ok(!execAllowFloor({ nodePrefix: "/usr/local", projectRoot: "/" }).includes("/"));
    assert.ok(!linuxExecFloor({ nodePrefix: "/usr/local", projectRoot: "/" }).includes("/"));
  });
});

describe("cwd and projectRoot are normalized at the sandbox entry points", () => {
  test("relative and dotted paths become absolute and canonical", () => {
    const r = normalizeRunPaths({ cwd: "pkg/../pkg", projectRoot: ".." });
    assert.ok(isAbsolute(r.cwd) && isAbsolute(r.projectRoot));
    assert.ok(!r.cwd.includes("..") && !r.projectRoot.includes(".."));
    assert.equal(r.projectRoot, join(r.cwd, ".."));
  });
  test("projectRoot defaults to the (normalized) cwd", () => {
    assert.equal(normalizeRunPaths({ cwd: "/a/b/./c" }).projectRoot, "/a/b/c");
  });
  test("a projectRoot that resolves to / falls back to cwd", () => {
    assert.equal(normalizeRunPaths({ cwd: "/work/pkg", projectRoot: "/" }).projectRoot, "/work/pkg");
    assert.equal(normalizeRunPaths({ cwd: "/work/pkg", projectRoot: "/work/pkg/../.." }).projectRoot, "/work/pkg");
  });
  test("seatbelt run with a RELATIVE cwd still confines and writes inside it (effect test)", { skip: process.platform === "darwin" ? false : "requires macOS sandbox-exec" }, () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "sb-rel-")));
    const rel = relative(process.cwd(), dir);
    assert.ok(!isAbsolute(rel));
    const r = new SeatbeltSandbox().run("echo ok > out.txt", { cwd: rel, approved: [], homeDir: dir });
    assert.equal(r.exitCode, 0, r.stderr);
    assert.ok(existsSync(join(dir, "out.txt")) && readFileSync(join(dir, "out.txt"), "utf8").includes("ok"));
  });
});
