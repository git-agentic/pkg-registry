import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { classifyViolation } from "../src/violation.js";
import type { DenySet } from "../src/deny-set.js";
import type { SandboxResult } from "../src/types.js";

const denySet: DenySet = { deniedPaths: ["/Users/test/.ssh", "/private/etc/passwd"], networkDenied: true };
const ok = (over: Partial<SandboxResult>): SandboxResult => ({ exitCode: 0, stdout: "", stderr: "", ...over });

describe("classifyViolation", () => {
  test("confirmed filesystem: EPERM on a denied path", () => {
    const r = ok({ exitCode: 1, stderr: "Error: EPERM: operation not permitted, open '/Users/test/.ssh/id_rsa'" });
    const v = classifyViolation(r, denySet);
    assert.equal(v?.kind, "filesystem");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.target, "/Users/test/.ssh/id_rsa");
    assert.equal(v?.deniedResource, "/Users/test/.ssh");
  });

  test("confirmed network: connect EPERM under network-denied", () => {
    const r = ok({ exitCode: 1, stderr: "Error: connect EPERM 198.51.100.7:443" });
    const v = classifyViolation(r, denySet);
    assert.equal(v?.kind, "network");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.target, "198.51.100.7:443");
    assert.equal(v?.deniedResource, "network");
  });

  test("none: ambient EPERM on a NON-denied path is not a violation (false-positive guard)", () => {
    const r = ok({ exitCode: 1, stderr: "EPERM: operation not permitted, open '/build/cache/x'" });
    assert.equal(classifyViolation(r, denySet), null);
  });

  test("suspected: network EPERM with no parseable host, under network-denied", () => {
    const r = ok({ exitCode: 1, stderr: "Error: connect EPERM (address hidden)" });
    const v = classifyViolation(r, denySet);
    assert.equal(v?.confidence, "suspected");
    assert.equal(v?.kind, "network");
    assert.equal(v?.target, null);
  });

  test("none: non-zero exit with no permission-error signature (ordinary build failure)", () => {
    assert.equal(classifyViolation(ok({ exitCode: 2, stderr: "SyntaxError: unexpected token" }), denySet), null);
  });

  test("none: exit 0 (a swallowed denial leaves no signal — documented limitation)", () => {
    assert.equal(classifyViolation(ok({ exitCode: 0, stderr: "EPERM: operation not permitted, open '/Users/test/.ssh/id_rsa'" }), denySet), null);
  });

  test("none: network EPERM but network was approved (not denied)", () => {
    const r = ok({ exitCode: 1, stderr: "connect EPERM 198.51.100.7:443" });
    assert.equal(classifyViolation(r, { deniedPaths: [], networkDenied: false }), null);
  });

  test("linux EACCES on a denied path is confirmed", () => {
    const r = ok({ exitCode: 1, stderr: "Error: EACCES: permission denied, open '/Users/test/.ssh/config'" });
    assert.equal(classifyViolation(r, denySet)?.confidence, "confirmed");
  });

  test("stderrExcerpt is truncated to <= 200 chars", () => {
    const long = "EPERM: operation not permitted, open '/Users/test/.ssh/id_rsa' " + "x".repeat(500);
    const v = classifyViolation(ok({ exitCode: 1, stderr: long }), denySet);
    assert.ok((v?.evidence.stderrExcerpt.length ?? 0) <= 200);
  });

  test("network target and excerpt come from the same line", () => {
    const r = ok({
      exitCode: 1,
      stderr: "Error: connect EPERM (address hidden)\nError: connect EPERM 198.51.100.7:443",
    });
    const v = classifyViolation(r, { deniedPaths: [], networkDenied: true });
    assert.equal(v?.target, "198.51.100.7:443");
    assert.ok(v?.evidence.stderrExcerpt.includes("198.51.100.7:443"));
  });

  test("does not throw on a malformed deny set", () => {
    assert.doesNotThrow(() =>
      classifyViolation(
        { exitCode: 1, stdout: "", stderr: "EPERM: operation not permitted, open '/x/.ssh/id_rsa'" },
        { networkDenied: false } as any,
      ),
    );
  });
});

// Phase 28: exec-denial shapes, probe-verified (task-2-report.md). Real macOS Seatbelt
// denials of a process-exec* deny come through /bin/sh in TWO distinct shapes — a
// shebang/interpreter-resolution wrapper (payload has a #!/bin/sh line) vs. a direct
// binary exec — plus a separate node spawnSync/execFileSync EPERM shape. All three
// carry the UNRESOLVED /var/folders/... form of a temp path on this host (never the
// resolved /private/var/... realpath) — but computeDenySet's path arrays are always
// canonicalized (firmlink roots collapsed to /private/...), matching what a real
// DenySet from computeDenySet would contain (see the final-review fix note below).
const EXEC_DS: DenySet = {
  deniedPaths: ["/Users/test/.ssh"],
  networkDenied: true,
  execDenied: true,
  execAllowedPaths: ["/bin", "/usr/bin", "/usr/local", "/work/pkg", "/Library/Developer"],
  execDeniedPaths: ["/usr/bin/curl", "/opt/homebrew/bin/curl"],
  writeAllowedPaths: ["/work/pkg", "/private/var/folders/vl/tmp.S6oZE9G04A", "/private/tmp", "/dev"],
};
const fail = (stderr: string): SandboxResult => ok({ exitCode: 126, stderr });

describe("classifyViolation — exec (Phase 28)", () => {
  test("a denied carve-out exec (direct binary shape) is a confirmed process violation", () => {
    // Probe (c): direct binary exec, no shebang indirection.
    const v = classifyViolation(fail("/bin/sh: /usr/bin/curl: Operation not permitted"), EXEC_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "/usr/bin/curl");
  });

  test("a shebang-script exec denial (bad interpreter shape) in a WRITABLE location is confirmed exec-default-deny", () => {
    // Probe (b): shebang script exec denied — the "bad interpreter" wrapper sits
    // BETWEEN the path and "Operation not permitted", which is exactly why the
    // plan's naive "path immediately followed by : Operation not permitted" regex
    // fails here. This is the shape Task 8's dropped-executable effect test relies on.
    const v = classifyViolation(
      fail("/bin/sh: /var/folders/vl/tmp.S6oZE9G04A/payload: /bin/sh: bad interpreter: Operation not permitted"),
      EXEC_DS,
    );
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "exec-default-deny");
    assert.equal(v?.target, "/var/folders/vl/tmp.S6oZE9G04A/payload");
  });

  test("a perm error outside both the exec floor and the write floor is only suspected (exec/write ambiguity)", () => {
    const v = classifyViolation(fail("/bin/sh: /usr/share/thing: Operation not permitted"), EXEC_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "suspected");
  });

  test("an unquoted perm error on a SENSITIVE path is attributed as a filesystem violation (fs precedence)", () => {
    const v = classifyViolation(fail("/bin/sh: /Users/test/.ssh/id_rsa: Operation not permitted"), EXEC_DS);
    assert.equal(v?.kind, "filesystem");
    assert.equal(v?.confidence, "confirmed");
  });

  test("a perm error where exec IS allowed is ambient — null", () => {
    assert.equal(classifyViolation(fail("/bin/sh: /usr/bin/some-tool: Operation not permitted"), EXEC_DS), null);
  });

  test("node's spawnSync EPERM on a non-floor path is a suspected process violation", () => {
    // Probe (d): label is spawnSync (execFileSync reports through it), not spawn.
    // Uses a different temp dir than the WRITABLE-location test above, so this path
    // falls outside both the exec-allow and write-allow floors (genuine ambiguity).
    const v = classifyViolation(fail("spawnSync /var/folders/vl/other-tmp.XYZ/payload EPERM"), EXEC_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "suspected");
    assert.equal(v?.target, "/var/folders/vl/other-tmp.XYZ/payload");
  });

  test("node's pathless spawn EPERM is a suspected process violation with no target", () => {
    const v = classifyViolation(fail("Error: spawn EPERM"), EXEC_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "suspected");
    assert.equal(v?.target, null);
  });

  test("without execDenied (legacy DenySet / linux) the exec branch never fires", () => {
    const legacy: DenySet = { deniedPaths: [], networkDenied: true };
    assert.equal(classifyViolation(fail("/bin/sh: /private/tmp/x: Operation not permitted"), legacy), null);
  });

  // Final-review regression (Finding 1): the deny-set path arrays are canonicalized
  // to the /private/... firmlink form, but the shell/node print the UNRESOLVED
  // /var/folders/... form in stderr. Before the fix, comparing the raw target against
  // a canonicalized writeAllowedPaths entry never matched — a binary dropped in
  // $TMPDIR and exec'd (the phase's headline scenario) wrongly classified as
  // "suspected" / deniedResource: null instead of "confirmed" / "exec-default-deny",
  // which meant SENTINEL_AUTO_QUARANTINE would never fire on a real dropped-binary exec.
  test("a dropped-$TMPDIR-binary exec (unresolved /var/folders path) against a canonicalized writeAllowedPaths entry is confirmed exec-default-deny (shebang shape)", () => {
    const v = classifyViolation(
      fail("/bin/sh: /var/folders/vl/tmp.S6oZE9G04A/payload: /bin/sh: bad interpreter: Operation not permitted"),
      EXEC_DS,
    );
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "exec-default-deny");
    assert.equal(v?.target, "/var/folders/vl/tmp.S6oZE9G04A/payload");
  });

  test("a dropped-$TMPDIR-binary exec (unresolved /var/folders path) against a canonicalized writeAllowedPaths entry is confirmed exec-default-deny (spawnSync shape)", () => {
    const v = classifyViolation(
      fail("spawnSync /var/folders/vl/tmp.S6oZE9G04A/payload EPERM"),
      EXEC_DS,
    );
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "exec-default-deny");
    assert.equal(v?.target, "/var/folders/vl/tmp.S6oZE9G04A/payload");
  });
});

const LINUX_DS = {
  deniedPaths: ["/home/test/.ssh"],
  networkDenied: true,
  execDenied: true,
  execDeniedPaths: ["/usr/bin/curl", "/bin/curl", "/usr/bin/wget"],
  // NO execAllowedPaths, NO writeAllowedPaths → Linux carve-out mode
};
const failL = (stderr: string) => ({ exitCode: 126, stdout: "", stderr });

describe("classifyViolation — Linux carve-out (Phase 29)", () => {
  test("a denied masked-literal exec (dash EACCES shape) is a confirmed process violation", () => {
    const v = classifyViolation(failL("/bin/sh: 1: /usr/bin/curl: Permission denied"), LINUX_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "/usr/bin/curl");
  });

  test("also handles the no-lineno shell shape", () => {
    const v = classifyViolation(failL("/bin/sh: /usr/bin/wget: Permission denied"), LINUX_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.deniedResource, "/usr/bin/wget");
  });

  test("a Permission-denied error on a NON-masked path is not a process violation (no floor to guess)", () => {
    // /usr/bin/make is not in execDeniedPaths → falls through, no process attribution
    const v = classifyViolation(failL("/bin/sh: 1: /usr/bin/make: Permission denied"), LINUX_DS);
    assert.ok(v === null || v.kind !== "process", "must not fabricate a process violation off the floor");
  });

  test("never emits suspected/exec-default-deny on Linux (no floor)", () => {
    const v = classifyViolation(failL("/bin/sh: 1: /tmp/dropped: Permission denied"), LINUX_DS);
    assert.ok(v === null || v.confidence !== "suspected", "Linux never guesses a floor denial");
    assert.notEqual(v?.deniedResource, "exec-default-deny");
  });

  test("exit 0 (swallowed) stays null", () => {
    assert.equal(classifyViolation({ exitCode: 0, stdout: "", stderr: "" }, LINUX_DS), null);
  });

  // Final-review Finding 1: a spawn-shaped permission error (no shell prefix, so
  // firstLinuxExecLine can't see it) used to fall through into the macOS exec
  // branch below, which still fires because execDenied is true, and reach the
  // terminal arm's "suspected" fallback — a false positive, since Linux carve-out
  // mode has no floor to guess a write-vs-exec ambiguity from. The terminal arm's
  // noFloorModeled guard must return null here instead.
  test("a spawn-shape ambient EACCES (no shell prefix, non-masked path) classifies null, not suspected", () => {
    const v = classifyViolation(failL("spawnSync /tmp/dropped EACCES"), LINUX_DS);
    assert.equal(v, null);
  });

  // Same spawn shape, but on a masked literal — the pre-existing macOS branch's
  // `carved` check (which precedes the terminal arm) must still confirm it. The
  // Finding 1 guard lives strictly after that check and must not break this path.
  test("a spawn-shape masked-literal EACCES still classifies confirmed via the carved check", () => {
    const v = classifyViolation(failL("spawnSync /usr/bin/curl EACCES"), LINUX_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "/usr/bin/curl");
  });
});

const LL_DS = {
  deniedPaths: ["/home/test/.ssh"],
  networkDenied: true,
  execDenied: true,
  execFloorMode: "linux-landlock" as const,
  execAllowedPaths: ["/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib", "/usr/lib64", "/work/pkg"],
  execDeniedPaths: ["/usr/bin/curl", "/bin/curl"],
};
const failLL = (stderr: string) => ({ exitCode: 126, stdout: "", stderr });

describe("classifyViolation — Linux Landlock floor mode (Phase 2)", () => {
  test("a floor-OUTSIDE exec denial (dropped /tmp binary) is confirmed exec-floor-deny", () => {
    const v = classifyViolation(failLL("/bin/sh: 1: /tmp/spikestash/payload: Permission denied"), LL_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "exec-floor-deny");
    assert.equal(v?.target, "/tmp/spikestash/payload");
  });
  test("a masked carve-out literal is confirmed on the literal (curl under an allowed /usr/bin)", () => {
    const v = classifyViolation(failLL("/bin/sh: 1: /usr/bin/curl: Permission denied"), LL_DS);
    assert.equal(v?.kind, "process");
    assert.equal(v?.confidence, "confirmed");
    assert.equal(v?.deniedResource, "/usr/bin/curl");
  });
  test("a denial UNDER the floor is ambient null (exec allowed there)", () => {
    assert.equal(classifyViolation(failLL("/bin/sh: 1: /usr/bin/make: Permission denied"), LL_DS), null);
  });
  test("does not fire without execFloorMode (a macOS DenySet is untouched)", () => {
    const macDs = { deniedPaths: [], networkDenied: true, execDenied: true, execAllowedPaths: ["/bin"], execDeniedPaths: ["/usr/bin/curl"] };
    // a macOS 'Permission denied' fs line must NOT be classified as an exec-floor violation
    assert.equal(classifyViolation(failLL("/bin/sh: /home/x/.ssh/id: Permission denied"), macDs as any)?.deniedResource, undefined);
  });
});
