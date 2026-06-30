import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { scrubEnv, ENV_ALLOWLIST } from "../src/env.js";
import type { Capability } from "@sentinel/core";

const envCap = (target: string): Capability => ({ kind: "env", target, evidence: [] });

describe("scrubEnv (fail-closed allowlist)", () => {
  const src = {
    PATH: "/usr/bin", HOME: "/Users/x", npm_config_cache: "/c", npm_package_name: "p",
    LC_ALL: "en_US", NODE_OPTIONS: "--x",
    NPM_TOKEN: "SEKRET", AWS_SECRET_ACCESS_KEY: "SEKRET2", SSH_AUTH_SOCK: "/tmp/agent.sock",
    NODE_AUTH_TOKEN: "SEKRET3", HONCHO_API_KEY: "SEKRET4", MY_PROD_CREDENTIAL: "SEKRET5",
  };

  test("passes allowlisted vars and prefixes", () => {
    const out = scrubEnv(src, []);
    assert.equal(out.PATH, "/usr/bin");
    assert.equal(out.HOME, "/Users/x");
    assert.equal(out.npm_config_cache, "/c");      // npm_ prefix
    assert.equal(out.npm_package_name, "p");
    assert.equal(out.LC_ALL, "en_US");             // LC_ prefix
    assert.equal(out.NODE_OPTIONS, "--x");         // exact
  });

  test("drops every credential — incl. novel-named and NODE_AUTH_TOKEN", () => {
    const out = scrubEnv(src, []);
    for (const k of ["NPM_TOKEN", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "NODE_AUTH_TOKEN", "HONCHO_API_KEY", "MY_PROD_CREDENTIAL"]) {
      assert.equal(out[k], undefined, `${k} must be dropped (fail-closed)`);
    }
  });

  test("an approved env capability lets exactly that var through", () => {
    const out = scrubEnv(src, [envCap("NPM_TOKEN")]);
    assert.equal(out.NPM_TOKEN, "SEKRET");
    assert.equal(out.AWS_SECRET_ACCESS_KEY, undefined); // unrelated secret still dropped
  });

  test("deterministic for the same inputs", () => {
    assert.deepEqual(scrubEnv(src, [envCap("NPM_TOKEN")]), scrubEnv(src, [envCap("NPM_TOKEN")]));
  });

  test("NODE allowlist is exact, not a prefix (guards NODE_AUTH_TOKEN)", () => {
    assert.ok(!ENV_ALLOWLIST.exact.has("NODE_AUTH_TOKEN"));
    assert.ok(!ENV_ALLOWLIST.prefixes.some((p) => "NODE_AUTH_TOKEN".startsWith(p)));
  });
});
