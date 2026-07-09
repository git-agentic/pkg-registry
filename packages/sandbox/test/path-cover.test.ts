import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { pathCovers } from "../src/path-cover.js";

describe("pathCovers (directional — approval covers at-or-below only)", () => {
  test("an ancestor approval covers a descendant deny", () => {
    assert.equal(pathCovers("~/.ssh", "~/.ssh/id_rsa"), true);
  });
  test("an equal path covers itself", () => {
    assert.equal(pathCovers("~/.npmrc", "~/.npmrc"), true);
  });
  test("a descendant approval does NOT cover an ancestor deny (the Phase 25 fix)", () => {
    assert.equal(pathCovers("~/.ssh/config", "~/.ssh"), false);
  });
  test("unrelated paths never cover", () => {
    assert.equal(pathCovers("~/.aws", "~/.ssh"), false);
    assert.equal(pathCovers("ssh", ".ssh"), false); // segment-anchored, not substring
  });
  test("the dynamic '*' target covers nothing", () => {
    assert.equal(pathCovers("*", "~/.ssh"), false);
  });
});
