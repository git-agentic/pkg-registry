import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { writeAllowFloor } from "../src/write-floor.js";

describe("writeAllowFloor", () => {
  test("includes the install dir, temp, /tmp, /dev and the node build caches", () => {
    const floor = writeAllowFloor({ cwd: "/work/pkg", tmpDir: "/var/folders/x/T" });
    assert.deepEqual(floor, [
      "/work/pkg",
      "/var/folders/x/T",
      "/tmp",
      "/dev",
      "~/.node-gyp",
      "~/.cache/node-gyp",
      "~/.npm/_logs",
    ]);
  });
  test("is pure — same inputs give the same list", () => {
    const a = writeAllowFloor({ cwd: "/a", tmpDir: "/b" });
    const b = writeAllowFloor({ cwd: "/a", tmpDir: "/b" });
    assert.deepEqual(a, b);
  });
});
