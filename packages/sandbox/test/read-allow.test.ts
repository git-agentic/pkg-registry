import assert from "node:assert/strict";
import { existsSync, mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { readAllowList, nodeInstallPrefix, resolveProjectRoot } from "../src/read-allow.js";

describe("readAllowList", () => {
  test("includes the node prefix, project root, and the build caches", () => {
    assert.deepEqual(readAllowList({ nodePrefix: "/usr/local", projectRoot: "/work/app" }), [
      "/usr/local",
      "/work/app",
      "~/.node-gyp",
      "~/.cache",
    ]);
  });
  test("is pure", () => {
    const a = readAllowList({ nodePrefix: "/n", projectRoot: "/p" });
    assert.deepEqual(a, readAllowList({ nodePrefix: "/n", projectRoot: "/p" }));
  });
});

describe("nodeInstallPrefix", () => {
  test("strips bin/node to the install prefix", () => {
    assert.equal(nodeInstallPrefix("/usr/local/bin/node"), "/usr/local");
  });
  test("handles a node-under-$HOME version-manager layout", () => {
    assert.equal(nodeInstallPrefix("/home/x/.nvm/versions/node/v24.0.0/bin/node"), "/home/x/.nvm/versions/node/v24.0.0");
  });
});

describe("resolveProjectRoot", () => {
  test("uses INIT_CWD when it is an absolute path", () => {
    assert.equal(resolveProjectRoot("/work/app/node_modules/pkg", "/work/app"), "/work/app");
  });
  test("ignores a blank/relative INIT_CWD and walks up to the nearest package.json", () => {
    const root = mkdtempSync(join(tmpdir(), "pr-"));
    writeFileSync(join(root, "package.json"), "{}");
    const deep = join(root, "node_modules", "pkg", "lib");
    mkdirSync(deep, { recursive: true });
    assert.equal(resolveProjectRoot(deep, ""), root);
    assert.equal(resolveProjectRoot(deep, "relative/path"), root);
  });
  test("falls back to cwd when no ancestor package.json exists", () => {
    const bare = mkdtempSync(join(tmpdir(), "bare-"));
    assert.equal(resolveProjectRoot(bare, undefined), bare);
  });
  test("does not require the caller to have created any file for the INIT_CWD path", () => {
    assert.ok(!existsSync("/nonexistent-x")); // sanity; INIT_CWD is trusted as-is when absolute
    assert.equal(resolveProjectRoot("/a/b", "/nonexistent-x"), "/nonexistent-x");
  });
});
