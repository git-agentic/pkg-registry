import assert from "node:assert/strict";
import { existsSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { generateBwrapArgs } from "../src/bwrap.js";
import { generateProfile } from "../src/profile.js";
import { normalizeRunPaths } from "../src/run-paths.js";
import { SeatbeltSandbox } from "../src/seatbelt.js";
import { BubblewrapSandbox } from "../src/bubblewrap.js";

// `sentinel exec` from `/` would put the filesystem root into the write floor (cwd is always
// writable), turning "writes closed except the floor" into "writes open everywhere".
const OPTS = { homeDir: "/home/x", tmpDir: "/tmp", nodePrefix: "/usr/local", projectRoot: "/work" };
const UNSUPPORTED = /enforcement unavailable.*working directory/s;

describe("a working directory that resolves to / is refused (fail closed)", () => {
  test("normalizeRunPaths throws for / and for paths that resolve to /", () => {
    for (const cwd of ["/", "/.", "/a/..", "//"]) assert.throws(() => normalizeRunPaths({ cwd }), UNSUPPORTED, cwd);
  });
  test("generateProfile (Seatbelt) refuses cwd / before emitting a profile", () => {
    assert.throws(() => generateProfile([], { ...OPTS, cwd: "/", homeDir: "/Users/x" }), UNSUPPORTED);
  });
  test("generateBwrapArgs refuses cwd / before emitting argv", () => {
    assert.throws(() => generateBwrapArgs([], { ...OPTS, cwd: "/" }), UNSUPPORTED);
  });
  test("a real Seatbelt run with cwd / refuses and runs nothing (effect test)", { skip: process.platform === "darwin" ? false : "requires macOS sandbox-exec" }, () => {
    const marker = join(realpathSync(mkdtempSync(join(tmpdir(), "sb-rootcwd-"))), "marker");
    assert.throws(() => new SeatbeltSandbox().run(`echo x > "${marker}"`, { cwd: "/", approved: [], homeDir: tmpdir() }), UNSUPPORTED);
    assert.throws(() => new SeatbeltSandbox().runArgv("/usr/bin/touch", [marker], { cwd: "/", approved: [], homeDir: tmpdir() }), UNSUPPORTED);
    assert.ok(!existsSync(marker));
  });
  test("a real bwrap run with cwd / refuses (Linux only)", { skip: process.platform === "linux" ? false : "requires Linux bwrap" }, () => {
    assert.throws(() => new BubblewrapSandbox().run("true", { cwd: "/", approved: [], homeDir: tmpdir() }), UNSUPPORTED);
  });
  test("a normal cwd is unaffected", () => {
    assert.equal(normalizeRunPaths({ cwd: "/work/pkg" }).cwd, "/work/pkg");
  });
});
