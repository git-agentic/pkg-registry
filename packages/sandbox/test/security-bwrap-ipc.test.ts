import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateBwrapArgs } from "../src/bwrap.js";
import { SENSITIVE_EXECUTABLES } from "../src/sensitive-executables.js";
import type { Capability } from "@git-agentic/sentinel-core";

// ARGUMENT tests: they pin the bwrap argv. The kernel effect is only exercisable on Linux CI.

const net: Capability = { kind: "network", target: "198.51.100.5", evidence: [] };
const fsCap = (target: string): Capability => ({ kind: "filesystem", target, evidence: [] });
const OPTS = { homeDir: "/home/x", cwd: "/work/pkg", tmpDir: "/tmp", nodePrefix: "/usr/local", projectRoot: "/work", uid: 1000 };
const SOCKETS = [
  "/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
  "/run/podman/podman.sock", "/run/crio/crio.sock", "/run/dbus/system_bus_socket",
];
const X11 = "/tmp/.X11-unix";
const lists = (dirs: Record<string, string[]>) => (p: string) => dirs[p] ?? [];
const exists = (list: string[]) => (p: string) => list.includes(p);
const joined = (a: string[]) => a.join(" ");

describe("local IPC masks apply with AND without a network approval", () => {
  for (const [label, caps] of [["no network", []], ["network approved", [net]]] as const) {
    test(`${label}: every existing IPC socket is /dev/null-masked and /run/user/<uid> is a tmpfs`, () => {
      const args = generateBwrapArgs([...caps], { ...OPTS, pathExists: exists([...SOCKETS, "/run/user/1000"]) });
      const j = joined(args);
      for (const s of ["/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock", "/run/crio/crio.sock", "/run/dbus/system_bus_socket"]) {
        assert.ok(j.includes(`--ro-bind /dev/null ${s}`), s);
      }
      assert.ok(j.includes("--tmpfs /run/user/1000"));
      assert.equal(args.includes("--unshare-net"), caps.length === 0);
    });
  }
  test("every mount is existence-guarded", () => {
    const j = joined(generateBwrapArgs([net], { ...OPTS, pathExists: exists([]) }));
    for (const s of [...SOCKETS, "/run/user", X11, "/tmp/ssh-"]) assert.ok(!j.includes(s), s);
  });
  test("an explicit filesystem grant covering a path lifts only that mask", () => {
    const j = joined(generateBwrapArgs([fsCap("/run/docker.sock")], { ...OPTS, pathExists: exists(SOCKETS) }));
    assert.ok(!j.includes("--ro-bind /dev/null /run/docker.sock"));
    assert.ok(j.includes("--ro-bind /dev/null /run/podman/podman.sock"));
  });
  test("a grant covering /run/user/<uid> lifts the tmpfs", () => {
    const j = joined(generateBwrapArgs([fsCap("/run/user/1000")], { ...OPTS, pathExists: exists(["/run/user/1000"]) }));
    assert.ok(!j.includes("--tmpfs /run/user/1000"));
  });
});

describe("/tmp X11 and ssh-agent socket directories", () => {
  const opts = (extra: Record<string, unknown> = {}) => ({
    ...OPTS, pathExists: exists([X11, "/tmp/ssh-AbC123", "/tmp/ssh-Zz"]),
    listDirs: lists({ "/tmp": [".X11-unix", "ssh-AbC123", "ssh-Zz", "other"] }), ...extra,
  });
  test("tmpfs over /tmp/.X11-unix and every /tmp/ssh-* directory, and nothing else under /tmp", () => {
    const args = generateBwrapArgs([], opts());
    const tmpfs = args.flatMap((a, i) => (a === "--tmpfs" ? [args[i + 1]] : []));
    for (const d of [X11, "/tmp/ssh-AbC123", "/tmp/ssh-Zz"]) assert.ok(tmpfs.includes(d), d);
    assert.ok(!tmpfs.includes("/tmp/other"));
  });
  test("they come AFTER the /tmp read-write bind (an earlier tmpfs would be overmounted)", () => {
    const args = generateBwrapArgs([], opts());
    const bindTmp = args.findIndex((a, i) => a === "--bind-try" && args[i + 1] === "/tmp");
    assert.ok(bindTmp !== -1, "/tmp is rw-bound");
    for (const d of [X11, "/tmp/ssh-AbC123"]) assert.ok(args.lastIndexOf(d) > bindTmp, d);
  });
  test("applies with network approved too", () => {
    assert.ok(joined(generateBwrapArgs([net], opts())).includes("--tmpfs /tmp/ssh-AbC123"));
  });
  test("a mask that would hide the cwd or project root is skipped", () => {
    const j = joined(generateBwrapArgs([], opts({ cwd: "/tmp/ssh-AbC123/pkg", projectRoot: "/tmp/ssh-AbC123/pkg" })));
    assert.ok(!j.includes("--tmpfs /tmp/ssh-AbC123"));
    assert.ok(j.includes("--tmpfs /tmp/ssh-Zz"));
  });
  test("a filesystem grant covering the directory lifts the mask", () => {
    assert.ok(!joined(generateBwrapArgs([fsCap("/tmp/.X11-unix")], opts())).includes("--tmpfs /tmp/.X11-unix"));
  });
});

describe("systemd/dbus clients are exec-denied", () => {
  test("SENSITIVE_EXECUTABLES lists systemd-run, busctl, dbus-send and gdbus", () => {
    for (const c of ["systemd-run", "busctl", "dbus-send", "gdbus"]) assert.ok(SENSITIVE_EXECUTABLES.includes(c), c);
  });
  test("bwrap masks them with /dev/null when present", () => {
    const present = ["/usr/bin/systemd-run", "/usr/bin/busctl", "/usr/bin/dbus-send", "/usr/bin/gdbus"];
    const j = joined(generateBwrapArgs([], { ...OPTS, pathExists: exists(present) }));
    for (const p of present) assert.ok(j.includes(`--ro-bind /dev/null ${p}`), p);
  });
});
