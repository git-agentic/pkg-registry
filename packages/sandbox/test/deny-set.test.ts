import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Capability } from "@git-agentic/sentinel-core";
import { computeDenySet, isSafeGrantTarget, landlockAllowPaths } from "../src/deny-set.js";
import { generateProfile } from "../src/profile.js";
import { generateBwrapArgs } from "../src/bwrap.js";
import { SENSITIVE_EXECUTABLES } from "../src/sensitive-executables.js";
import { linuxExecFloor } from "../src/exec-floor.js";

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

  test("darwin without exec opts (legacy callers): exec fields absent; linux now has carve-out", () => {
    const dsDarwin = computeDenySet([], { homeDir: HOME, platform: "darwin" });
    assert.equal(dsDarwin.execDenied, undefined);
    assert.equal(dsDarwin.execDeniedPaths, undefined);
    // Linux now returns the carve-out even without the full exec opts (Phase 29)
    const dsLinux = computeDenySet([], { homeDir: HOME, platform: "linux" });
    assert.ok(Array.isArray(dsLinux.execDeniedPaths), "Linux carve-out is always available");
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

describe("computeDenySet — Linux carve-out (Phase 29)", () => {
  const L = { homeDir: "/home/test", platform: "linux" as const, nodePrefix: "/usr", projectRoot: "/work/pkg", cwd: "/work/pkg", tmpDir: "/tmp/x" };

  test("lists the carve-out literals as execDeniedPaths, sets execDenied, and models NO floor", () => {
    const ds = computeDenySet([], L);
    assert.equal(ds.execDenied, true);
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/curl")), "curl literal denied");
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/wget")), "wget literal denied");
    assert.equal(ds.execAllowedPaths, undefined, "Linux has NO exec floor");
    assert.equal(ds.writeAllowedPaths, undefined, "Linux has NO write floor in the exec model");
  });

  test("a command Grant removes that command's literals; a path Grant removes a covered literal", () => {
    const ds = computeDenySet([procCap("curl"), procCap("/bin/wget")], L);
    assert.ok(!ds.execDeniedPaths!.some((p) => p.endsWith("/curl")), "process:curl lifts curl");
    assert.ok(!ds.execDeniedPaths!.includes("/bin/wget"), "path grant lifts /bin/wget");
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/nc")), "nc stays denied");
  });

  test("the * Grant empties the carve-out and clears execDenied", () => {
    const ds = computeDenySet([procCap("*")], L);
    assert.deepEqual(ds.execDeniedPaths, []);
    assert.equal(ds.execDenied, false);
  });

  test("Linux paths are NOT firmlink-canonicalized (no /private rewrite)", () => {
    const ds = computeDenySet([], L);
    assert.ok(ds.execDeniedPaths!.every((p) => !p.startsWith("/private/")), "no macOS canon on linux");
  });

  test("legacy Linux call without exec opts still returns the base shape unchanged", () => {
    const ds = computeDenySet([], { homeDir: "/home/test", platform: "linux" });
    assert.ok(ds.deniedPaths.length >= 0);
    // exec fields may be present (carve-out needs no nodePrefix), but must be internally consistent:
    if (ds.execDenied) assert.ok(Array.isArray(ds.execDeniedPaths));
  });
});

describe("computeDenySet ↔ generateBwrapArgs Linux non-drift (Phase 29)", () => {
  const L = { homeDir: "/home/test", platform: "linux" as const, nodePrefix: "/usr", projectRoot: "/work/pkg", cwd: "/work/pkg", tmpDir: "/tmp/x" };

  test("every exec carve-out literal /dev/null-masked in the argv is in execDeniedPaths", () => {
    const approved: Capability[] = [procCap("curl")]; // curl lifted, others masked
    const ds = computeDenySet(approved, L);
    const argv = generateBwrapArgs(approved, {
      homeDir: L.homeDir, cwd: L.cwd, tmpDir: L.tmpDir, nodePrefix: L.nodePrefix,
      projectRoot: L.projectRoot, pathExists: () => true,
    });
    const masks: string[] = [];
    for (let i = 0; i < argv.length - 2; i++) {
      if (argv[i] === "--ro-bind" && argv[i + 1] === "/dev/null") {
        const mask = argv[i + 2];
        // Filter to only exec carve-out masks (paths ending with a command name from SENSITIVE_EXECUTABLES)
        if (SENSITIVE_EXECUTABLES.some((cmd) => mask.endsWith("/" + cmd))) {
          masks.push(mask);
        }
      }
    }
    for (const m of masks) assert.ok(ds.execDeniedPaths!.includes(m), `deny set must include exec-carve-out masked ${m}`);
  });

  test("non-drift under live merged-usr path resolution (Phase 29)", () => {
    // Inject a realpath that simulates merged-usr: /bin/<x> → /usr/bin/<x>
    const mergedUsrResolve = (p: string): string => {
      if (p.startsWith("/bin/")) return "/usr/bin/" + p.slice(5);
      return p; // leave other paths unchanged
    };

    const approved: Capability[] = [procCap("wget")]; // wget lifted, others masked
    const ds = computeDenySet(approved, L);
    const argv = generateBwrapArgs(approved, {
      homeDir: L.homeDir, cwd: L.cwd, tmpDir: L.tmpDir, nodePrefix: L.nodePrefix,
      projectRoot: L.projectRoot, pathExists: () => true,
      realpath: mergedUsrResolve, // inject resolution
    });
    const masks: string[] = [];
    for (let i = 0; i < argv.length - 2; i++) {
      if (argv[i] === "--ro-bind" && argv[i + 1] === "/dev/null") {
        const mask = argv[i + 2];
        // Filter to only exec carve-out masks (paths ending with a command name from SENSITIVE_EXECUTABLES)
        if (SENSITIVE_EXECUTABLES.some((cmd) => mask.endsWith("/" + cmd))) {
          masks.push(mask);
        }
      }
    }
    // Even with live resolution, every masked path must be in execDeniedPaths (the deny set enumerates all candidates)
    for (const m of masks) assert.ok(ds.execDeniedPaths!.includes(m), `deny set must include resolved exec-carve-out masked ${m}`);
  });

  test("merged-usr: a path grant excludes BOTH sibling literals from execDeniedPaths (issue #21)", () => {
    const mergedUsrResolve = (p: string): string => (p.startsWith("/bin/") ? "/usr/bin/" + p.slice(5) : p);
    const ds = computeDenySet([procCap("/usr/bin/curl")], { ...L, realpath: mergedUsrResolve });
    assert.ok(!ds.execDeniedPaths!.includes("/usr/bin/curl"), "the granted literal is lifted");
    assert.ok(!ds.execDeniedPaths!.includes("/bin/curl"), "the merged-usr sibling literal is lifted too");
    assert.ok(ds.execDeniedPaths!.includes("/usr/bin/wget"), "other commands stay denied");
    assert.ok(ds.execDeniedPaths!.includes("/bin/wget"), "…in BOTH literal forms (invocation-form matching)");
  });

  test("non-drift under live merged-usr path resolution with a PATH grant (issue #21)", () => {
    const mergedUsrResolve = (p: string): string => (p.startsWith("/bin/") ? "/usr/bin/" + p.slice(5) : p);
    const approved: Capability[] = [procCap("/usr/bin/curl")];
    const ds = computeDenySet(approved, { ...L, realpath: mergedUsrResolve });
    const argv = generateBwrapArgs(approved, {
      homeDir: L.homeDir, cwd: L.cwd, tmpDir: L.tmpDir, nodePrefix: L.nodePrefix,
      projectRoot: L.projectRoot, pathExists: () => true, realpath: mergedUsrResolve,
    });
    const masks: string[] = [];
    for (let i = 0; i < argv.length - 2; i++) {
      if (argv[i] === "--ro-bind" && argv[i + 1] === "/dev/null") {
        const mask = argv[i + 2];
        if (SENSITIVE_EXECUTABLES.some((cmd) => mask.endsWith("/" + cmd))) masks.push(mask);
      }
    }
    assert.ok(!masks.includes("/usr/bin/curl") && !masks.includes("/bin/curl"), "the generator lifts both curl siblings");
    for (const m of masks) assert.ok(ds.execDeniedPaths!.includes(m), `deny set must include exec-carve-out masked ${m}`);
  });
});

describe("computeDenySet — Linux Landlock floor mode (Phase 2)", () => {
  const L = { homeDir: "/home/test", platform: "linux" as const, nodePrefix: "/usr", projectRoot: "/work/pkg", cwd: "/work/pkg", tmpDir: "/tmp/x" };

  test("landlockFloor populates execAllowedPaths (linuxExecFloor) + sets execFloorMode + execDenied", () => {
    const ds = computeDenySet([], { ...L, landlockFloor: true });
    assert.equal(ds.execFloorMode, "linux-landlock");
    assert.equal(ds.execDenied, true);
    assert.ok(ds.execAllowedPaths!.includes("/bin"), "floor has /bin");
    assert.ok(ds.execAllowedPaths!.includes("/lib64"), "floor has the lib dirs");
    assert.ok(ds.execAllowedPaths!.includes("/work/pkg"), "floor has projectRoot");
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/curl")), "carve-out literals still present");
  });

  test("execDenied is true even when all carve-out is granted away (the floor still denies)", () => {
    const ds = computeDenySet([procCap("*")], { ...L, landlockFloor: true });
    assert.equal(ds.execDenied, true);
    assert.deepEqual(ds.execDeniedPaths, []);
    assert.ok((ds.execAllowedPaths?.length ?? 0) > 0);
  });

  test("without landlockFloor: EXACT Phase 29 shape (no floor, no execFloorMode)", () => {
    const ds = computeDenySet([], L);
    assert.equal(ds.execFloorMode, undefined);
    assert.equal(ds.execAllowedPaths, undefined);
    assert.ok(ds.execDeniedPaths!.some((p) => p.endsWith("/curl")));
  });

  test("Landlock floor mode shares the merged-usr path-grant filter (issue #21)", () => {
    const mergedUsrResolve = (p: string): string => (p.startsWith("/bin/") ? "/usr/bin/" + p.slice(5) : p);
    const ds = computeDenySet([procCap("/usr/bin/curl")], { ...L, landlockFloor: true, realpath: mergedUsrResolve });
    assert.equal(ds.execFloorMode, "linux-landlock");
    assert.ok(!ds.execDeniedPaths!.includes("/bin/curl"), "the sibling literal is lifted in floor mode too");
  });

  // Issue #25: approved process: PATH grants join the floor in execAllowedPaths —
  // the Linux mirror of the darwin floor+grants pattern.
  test("a safe process: path grant outside the floor lands in execAllowedPaths (issue #25)", () => {
    const ds = computeDenySet([procCap("/opt/vendor/bin/tool")], { ...L, landlockFloor: true });
    assert.ok(ds.execAllowedPaths!.includes("/opt/vendor/bin/tool"));
    assert.ok(ds.execAllowedPaths!.includes("/bin"), "floor entries still present");
  });
  test("a ~-form path grant expands against homeDir", () => {
    // runtime visibility: fixed by #28 — generateBwrapArgs re-exposes under-$HOME
    // grants inside the tmpfs (see the bubblewrap "re-exposed and execs" effect test).
    const ds = computeDenySet([procCap("~/tools/bin/x")], { ...L, landlockFloor: true });
    assert.ok(ds.execAllowedPaths!.includes("/home/test/tools/bin/x"));
  });
  test("unsafe path-grant targets never widen the floor", () => {
    const floorOnly = computeDenySet([], { ...L, landlockFloor: true }).execAllowedPaths;
    const ds = computeDenySet([procCap("/"), procCap("/opt/a/../b")], { ...L, landlockFloor: true });
    assert.deepEqual(ds.execAllowedPaths, floorOnly);
  });
  test("command and wildcard grants open no paths (carve-out lift only)", () => {
    const floorOnly = computeDenySet([], { ...L, landlockFloor: true }).execAllowedPaths;
    const ds = computeDenySet([procCap("curl"), procCap("*")], { ...L, landlockFloor: true });
    assert.deepEqual(ds.execAllowedPaths, floorOnly);
  });
  test("non-drift: Landlock execAllowedPaths equals landlockAllowPaths for the same inputs", () => {
    const caps = [procCap("/opt/vendor/bin/tool"), procCap("curl"), procCap("~/tools/bin/x")];
    const ds = computeDenySet(caps, { ...L, landlockFloor: true });
    assert.deepEqual(
      ds.execAllowedPaths,
      landlockAllowPaths(caps, { homeDir: L.homeDir, nodePrefix: L.nodePrefix, projectRoot: L.projectRoot }),
    );
  });
  test("landlockAllowPaths: floor-only with no grants", () => {
    assert.deepEqual(
      landlockAllowPaths([], { homeDir: "/home/test", nodePrefix: "/usr", projectRoot: "/work/pkg" }),
      linuxExecFloor({ nodePrefix: "/usr", projectRoot: "/work/pkg" }),
    );
  });

  test("landlockAllowPaths: a bare '~' grant is dropped (floor-only result, #28)", () => {
    assert.deepEqual(
      landlockAllowPaths([procCap("~")], { homeDir: "/home/test", nodePrefix: "/usr", projectRoot: "/work/pkg" }),
      linuxExecFloor({ nodePrefix: "/usr", projectRoot: "/work/pkg" }),
    );
  });

  test("landlockAllowPaths: a normalizing grant shape ('~//') is dropped (floor-only result, #28)", () => {
    assert.deepEqual(
      landlockAllowPaths([procCap("~//")], { homeDir: "/home/test", nodePrefix: "/usr", projectRoot: "/work/pkg" }),
      linuxExecFloor({ nodePrefix: "/usr", projectRoot: "/work/pkg" }),
    );
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

  test("bare '~' and '~/' are rejected — they expand to all of $HOME (#28)", () => {
    assert.ok(!isSafeGrantTarget("~"));
    assert.ok(!isSafeGrantTarget("~/"));
    assert.ok(isSafeGrantTarget("~/tools/bin/x"), "a ~-prefixed real path stays allowed");
  });

  test("segments that normalize to an ancestor are rejected — trailing '/', '//', '.' (#28)", () => {
    assert.ok(!isSafeGrantTarget("~//"));
    assert.ok(!isSafeGrantTarget("~/."));
    assert.ok(!isSafeGrantTarget("/home/x/"));
    assert.ok(!isSafeGrantTarget("/home/x/."));
    assert.ok(!isSafeGrantTarget("a/./b"));
    assert.ok(!isSafeGrantTarget("."));
    assert.ok(isSafeGrantTarget("/home/x/ok"), "a plain absolute path stays allowed");
    assert.ok(isSafeGrantTarget("~/tools/bin/x"), "a plain ~-form path stays allowed");
  });
});
