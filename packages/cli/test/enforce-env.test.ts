// packages/cli/test/enforce-env.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { enforceNpmEnv } from "../src/index.js";

describe("enforceNpmEnv", () => {
  test("injects script-shell + enforce env, preserving the base env", () => {
    const env = enforceNpmEnv({ PATH: "/usr/bin", HOME: "/h" }, {
      proxy: "http://localhost:4873", wrapperPath: "/abs/dist/script-shell.js", approve: ["network:api.example.com"],
    });
    assert.equal(env.npm_config_script_shell, "/abs/dist/script-shell.js");
    assert.equal(env.SENTINEL_ENFORCE, "1");
    assert.equal(env.SENTINEL_PROXY, "http://localhost:4873");
    assert.equal(env.SENTINEL_APPROVE, "network:api.example.com");
    assert.equal(env.PATH, "/usr/bin", "base env preserved");
    assert.equal(env.HOME, "/h");
  });
  test("empty approvals yield an empty SENTINEL_APPROVE", () => {
    assert.equal(enforceNpmEnv({}, { proxy: "p", wrapperPath: "w", approve: [] }).SENTINEL_APPROVE, "");
  });
});
