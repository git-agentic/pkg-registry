import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { SENSITIVE_EXECUTABLES, execCarveOutPaths, classifyProcessTarget } from "../src/sensitive-executables.js";

describe("SENSITIVE_EXECUTABLES", () => {
  test("covers the exfil-capable set from the spec", () => {
    for (const cmd of ["curl", "wget", "nc", "ncat", "socat", "osascript", "scp", "sftp"]) {
      assert.ok(SENSITIVE_EXECUTABLES.includes(cmd), `must include ${cmd}`);
    }
  });

  test("execCarveOutPaths expands one command across the floor's bin dirs", () => {
    const paths = execCarveOutPaths("curl");
    assert.deepEqual(paths, ["/bin/curl", "/usr/bin/curl", "/opt/homebrew/bin/curl", "/usr/local/bin/curl"]);
  });
});

describe("classifyProcessTarget", () => {
  test("a bare word is a command name", () => {
    assert.equal(classifyProcessTarget("curl"), "command");
    assert.equal(classifyProcessTarget("node-gyp"), "command");
  });
  test("a target containing / or starting with ~ is a path", () => {
    assert.equal(classifyProcessTarget("/opt/tools/foo"), "path");
    assert.equal(classifyProcessTarget("~/bin/tool"), "path");
    assert.equal(classifyProcessTarget("tools/foo"), "path");
  });
  test("* is the wildcard", () => {
    assert.equal(classifyProcessTarget("*"), "wildcard");
  });
});
