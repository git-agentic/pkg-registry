import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { execAllowFloor } from "../src/exec-floor.js";

describe("execAllowFloor", () => {
  const floor = execAllowFloor({ nodePrefix: "/Users/x/.nvm/versions/node/v24.1.0", projectRoot: "/work/pkg" });

  test("contains the system, toolchain, and Homebrew prefixes", () => {
    for (const p of ["/bin", "/usr/bin", "/usr/sbin", "/Library/Developer", "/Applications/Xcode.app", "/opt/homebrew", "/usr/local"]) {
      assert.ok(floor.includes(p), `floor must include ${p}`);
    }
  });

  test("contains the node prefix and the project root", () => {
    assert.ok(floor.includes("/Users/x/.nvm/versions/node/v24.1.0"));
    assert.ok(floor.includes("/work/pkg"));
  });

  test("does NOT contain the writable staging areas (tmp, $HOME, /dev)", () => {
    for (const p of ["/tmp", "/private/tmp", "/dev"]) {
      assert.ok(!floor.includes(p), `floor must not include ${p}`);
    }
  });

  test("deterministic for the same inputs", () => {
    assert.deepEqual(floor, execAllowFloor({ nodePrefix: "/Users/x/.nvm/versions/node/v24.1.0", projectRoot: "/work/pkg" }));
  });
});
