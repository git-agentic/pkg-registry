import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { pathCovers, segments } from "../src/path-cover.js";

describe("pathCovers", () => {
  test("segment-anchored, not substring: 'ssh' does NOT cover '.ssh'", () => {
    assert.equal(pathCovers("ssh", "~/.ssh"), false);
  });
  test("an exact segment covers its own deny path", () => {
    assert.equal(pathCovers(".ssh", "~/.ssh"), true);
  });
  test("the dynamic '*' target covers nothing", () => {
    assert.equal(pathCovers("*", "~/.npmrc"), false);
  });
  test("ancestor covers descendant and vice-versa (shared prefix to shorter)", () => {
    assert.equal(pathCovers("/etc/passwd", "/etc/passwd"), true);
    assert.equal(segments("~/.aws/credentials").join("/"), ".aws/credentials");
  });
});
