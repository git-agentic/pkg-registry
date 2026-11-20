import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateBwrapArgs } from "../src/bwrap.js";
import type { Capability } from "@git-agentic/sentinel-core";

// These are ARGUMENT tests: they pin the bwrap argv. The kernel effect (pid namespace,
// masked sockets) is only exercisable on Linux CI and is NOT verified on this host.

const net = (target: string): Capability => ({ kind: "network", target, evidence: [] });
const fsCap = (target: string): Capability => ({ kind: "filesystem", target, evidence: [] });
const OPTS = { homeDir: "/home/x", cwd: "/work/pkg", tmpDir: "/tmp/build", nodePrefix: "/usr/local", projectRoot: "/work" };

/** Every `<flag> <src> <dst>` triple for a 2-arg mount flag. */
const mounts = (args: string[], flag: string) =>
  args.flatMap((a, i) => (a === flag ? [[args[i + 1], args[i + 2]]] : []));

describe("F8 bwrap separates the pid namespace and session", () => {
  test("adds --unshare-pid and --new-session (no --die-with-parent), before --proc /proc", () => {
    assert.ok(!generateBwrapArgs([], OPTS).includes("--die-with-parent"));
    const args = generateBwrapArgs([], OPTS);
    for (const f of ["--unshare-pid", "--new-session"]) {
      assert.ok(args.includes(f), `${f} must be present`);
    }
    assert.ok(args.indexOf("--unshare-pid") < args.indexOf("--proc"), "pid namespace before the /proc mount");
  });
  test("present when network is approved too (not tied to --unshare-net)", () => {
    const args = generateBwrapArgs([net("198.51.100.5")], OPTS);
    for (const f of ["--unshare-pid", "--new-session"]) assert.ok(args.includes(f), f);
    assert.ok(!args.includes("--unshare-net"));
  });
});

describe("F9 unix sockets are unreachable without a network approval", () => {
  const withFs = (existing: string[], extra: Record<string, unknown> = {}) => ({
    ...OPTS, uid: 1000, pathExists: (p: string) => existing.includes(p), ...extra,
  });

  test("masks existing docker sockets with /dev/null and tmpfs-es /run/user/<uid>", () => {
    const args = generateBwrapArgs([], withFs(["/var/run/docker.sock", "/run/docker.sock", "/run/user/1000"]));
    const nulls = mounts(args, "--ro-bind").filter(([s]) => s === "/dev/null").map(([, d]) => d);
    assert.ok(nulls.includes("/var/run/docker.sock"));
    assert.ok(nulls.includes("/run/docker.sock"));
    assert.ok(mounts(args, "--tmpfs").length > 0);
    assert.ok(args.join(" ").includes("--tmpfs /run/user/1000"));
  });
  test("a /var/run -> /run symlink is resolved so the same socket is masked once", () => {
    const realpath = (p: string) => p.replace(/^\/var\/run\//, "/run/");
    const args = generateBwrapArgs([], withFs(["/var/run/docker.sock", "/run/docker.sock"], { realpath }));
    const nulls = mounts(args, "--ro-bind").filter(([s, d]) => s === "/dev/null" && d.endsWith("docker.sock"));
    assert.deepEqual(nulls.map(([, d]) => d), ["/run/docker.sock"]);
  });
  test("every new mount is existence-guarded: nothing is emitted for an absent path", () => {
    const args = generateBwrapArgs([], withFs([]));
    assert.ok(!args.join(" ").includes("docker.sock"));
    assert.ok(!args.join(" ").includes("/run/user"));
  });
  test("a network approval means the network, not local IPC: the masks are STILL applied", () => {
    const args = generateBwrapArgs([net("198.51.100.5")], withFs(["/var/run/docker.sock", "/run/docker.sock", "/run/user/1000"]));
    assert.ok(args.join(" ").includes("--ro-bind /dev/null /run/docker.sock"));
    assert.ok(args.join(" ").includes("--tmpfs /run/user/1000"));
    assert.ok(!args.includes("--unshare-net"));
  });
  test("an approved filesystem grant covering the socket lifts the mask", () => {
    const args = generateBwrapArgs([fsCap("/run/docker.sock")], withFs(["/run/docker.sock"]));
    assert.ok(!args.join(" ").includes("--ro-bind /dev/null /run/docker.sock"));
  });
  test("mask mounts come AFTER the root bind and BEFORE --unshare-net", () => {
    const args = generateBwrapArgs([], withFs(["/run/docker.sock"]));
    const mask = args.indexOf("/run/docker.sock");
    assert.ok(mask > args.indexOf("--ro-bind") && mask < args.indexOf("--unshare-net"));
  });
});

describe("project root / must not re-allow everything", () => {
  test("bwrap: a projectRoot of / is not re-bound inside the emptied $HOME", () => {
    const args = generateBwrapArgs([], { ...OPTS, projectRoot: "/" });
    const reBound = [...mounts(args, "--ro-bind-try"), ...mounts(args, "--ro-bind")]
      .filter(([s, d]) => s === "/" && d === "/");
    // exactly the initial `--ro-bind / /`, and no `--ro-bind-try / /` after the tmpfs home
    assert.equal(mounts(args, "--ro-bind-try").filter(([s]) => s === "/").length, 0);
    assert.equal(reBound.length, 1);
  });
});
