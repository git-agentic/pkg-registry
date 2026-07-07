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
});
