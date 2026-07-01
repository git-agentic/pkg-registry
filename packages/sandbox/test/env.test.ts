import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { scrubEnv, ENV_ALLOWLIST, CREDENTIAL_ENV_RE } from "../src/env.js";
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

describe("scrubEnv npm narrowing + credential-screen", () => {
  const scrub = (e: Record<string, string>) => scrubEnv(e, []);
  test("keeps benign npm-injected vars a lifecycle script needs", () => {
    const out = scrub({
      npm_package_name: "p", npm_package_version: "1.0.0", npm_lifecycle_event: "postinstall",
      npm_node_execpath: "/n/bin/node", npm_command: "install", npm_execpath: "/n/npm-cli.js",
      npm_config_cache: "/c", npm_config_user_agent: "npm/11", npm_config_node_gyp: "/g",
      INIT_CWD: "/proj", PATH: "/proj/node_modules/.bin:/usr/bin",
    });
    for (const k of ["npm_package_name","npm_lifecycle_event","npm_node_execpath","npm_command","npm_execpath","npm_config_cache","npm_config_user_agent","INIT_CWD","PATH"])
      assert.ok(out[k] !== undefined, `${k} must be kept`);
  });
  test("drops credential-shaped npm_config_* keys (any npm version)", () => {
    const out = scrub({
      "npm_config__auth": "BASIC", "npm_config__authToken": "T", "npm_config__password": "P",
      "npm_config_//registry.npmjs.org/:_authToken": "SCOPED", "npm_config_registry_secret": "S",
      npm_config_cache: "/c",
    });
    assert.equal(out["npm_config__auth"], undefined);
    assert.equal(out["npm_config__authToken"], undefined);
    assert.equal(out["npm_config__password"], undefined);
    assert.equal(out["npm_config_//registry.npmjs.org/:_authToken"], undefined);
    assert.equal(out["npm_config_registry_secret"], undefined);
    assert.equal(out["npm_config_cache"], "/c", "benign config still kept");
  });
  test("drops unknown npm_ vars outside the narrowed sub-groups (fail-closed narrowing)", () => {
    assert.equal(scrub({ npm_mystery: "x" })["npm_mystery"], undefined);
  });
  test("an approved env: capability still passes its exact var through", () => {
    const out = scrubEnv({ MY_TOKEN: "v" }, [{ kind: "env", target: "MY_TOKEN", evidence: [] }]);
    assert.equal(out["MY_TOKEN"], "v");
  });
  test("CREDENTIAL_ENV_RE matches auth/token/password/secret shapes, not benign", () => {
    for (const k of ["npm_config__authToken","FOO_SECRET","x_password","MY_AUTHTOKEN","registry_token"]) assert.ok(CREDENTIAL_ENV_RE.test(k), k);
    for (const k of ["npm_config_cache","PATH","npm_package_name"]) assert.ok(!CREDENTIAL_ENV_RE.test(k), k);
  });
});
