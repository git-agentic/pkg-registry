import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync } from "node:fs";
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

// path.resolve() is lexical: a cwd that is a SYMLINK to / used to pass the guard. The runtime
// entry points follow symlinks (realpath); the pure generators stay lexical.
describe("a symlink to / or to a project dir is followed at the entry points", () => {
  const mk = () => realpathSync(mkdtempSync(join(tmpdir(), "sb-symcwd-")));
  const linkTo = (target: string) => {
    const base = mk();
    const link = join(base, "link");
    symlinkSync(target, link);
    return { base, link };
  };

  test("normalizeRunPaths refuses a symlinked cwd that resolves to /", () => {
    const { link } = linkTo("/");
    assert.throws(() => normalizeRunPaths({ cwd: link }), UNSUPPORTED);
    assert.throws(() => normalizeRunPaths({ cwd: join(link, "tmp", "..") }), UNSUPPORTED);
  });
  test("a symlinked cwd / projectRoot is replaced by its realpath", () => {
    const base = mk();
    const real = join(base, "real"); mkdirSync(real);
    const link = join(base, "link"); symlinkSync(real, link);
    assert.deepEqual(normalizeRunPaths({ cwd: link, projectRoot: link }), { cwd: real, projectRoot: real });
  });
  test("a projectRoot symlink to / falls back to the cwd", () => {
    const { base, link } = linkTo("/");
    assert.equal(normalizeRunPaths({ cwd: base, projectRoot: link }).projectRoot, base);
  });
  test("a cwd that does not exist is left lexical (fails later exactly as before)", () => {
    assert.equal(normalizeRunPaths({ cwd: "/definitely/not/here/./x" }).cwd, "/definitely/not/here/x");
  });
  test("a real Seatbelt run from a symlink to / throws and writes nothing (effect test)", { skip: process.platform === "darwin" ? false : "requires macOS sandbox-exec" }, () => {
    const { base, link } = linkTo("/");
    const marker = join(base, "marker");
    assert.throws(() => new SeatbeltSandbox().run(`echo x > "${marker}"`, { cwd: link, approved: [], homeDir: tmpdir() }), UNSUPPORTED);
    assert.throws(() => new SeatbeltSandbox().runArgv("/usr/bin/touch", [marker], { cwd: link, approved: [], homeDir: tmpdir() }), UNSUPPORTED);
    assert.ok(!existsSync(marker));
  });
  test("a real Seatbelt run from a symlinked project dir still works (effect test)", { skip: process.platform === "darwin" ? false : "requires macOS sandbox-exec" }, () => {
    const base = mk();
    const real = join(base, "real"); mkdirSync(real);
    const link = join(base, "link"); symlinkSync(real, link);
    const r = new SeatbeltSandbox().run("echo ok > out.txt", { cwd: link, approved: [], homeDir: join(base, "nohome") });
    assert.equal(r.exitCode, 0, r.stderr);
    assert.ok(existsSync(join(real, "out.txt")));
  });
  test("the profile built from the normalized cwd carries the realpath; the pure generator stays lexical", () => {
    const base = mk();
    const real = join(base, "real"); mkdirSync(real);
    const link = join(base, "link"); symlinkSync(real, link);
    const o = { homeDir: "/Users/x", tmpDir: "/var/folders/z/T", nodePrefix: "/usr/local" };
    const n = normalizeRunPaths({ cwd: link });
    const p = generateProfile([], { ...o, cwd: n.cwd, projectRoot: n.projectRoot });
    assert.ok(p.includes(`(subpath "${real}")`) && !p.includes(`(subpath "${link}")`));
    assert.ok(generateProfile([], { ...o, cwd: link, projectRoot: link }).includes(`(subpath "${link}")`));
  });
});
