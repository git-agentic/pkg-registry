import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { scrubEnv } from "../src/env.js";
import { classifyViolation } from "../src/violation.js";
import { computeDenySet } from "../src/deny-set.js";

describe("npm_config_* values that embed URL credentials are dropped", () => {
  const scrub = (e: Record<string, string>) => scrubEnv(e, []);
  test("https_proxy / registry with user:pass@ are dropped, plain ones are kept", () => {
    const out = scrub({
      npm_config_https_proxy: "http://user:pass@proxy.example:3128",
      npm_config_registry: "https://bob@registry.example/",
      npm_config_proxy: "http://proxy.example:3128",
      npm_config_cache: "/c",
    });
    assert.equal(out.npm_config_https_proxy, undefined);
    assert.equal(out.npm_config_registry, undefined);
    assert.equal(out.npm_config_proxy, "http://proxy.example:3128");
    assert.equal(out.npm_config_cache, "/c");
  });
  test("only npm_config_* values are screened (other allowlisted vars are untouched)", () => {
    assert.equal(scrub({ npm_package_repository_url: "git+https://u:p@h/x.git" }).npm_package_repository_url, "git+https://u:p@h/x.git");
  });
});

describe("control characters never reach a reported violation", () => {
  const deny = computeDenySet([], { homeDir: "/home/x", platform: "linux" });
  test("filesystem target / deniedResource / excerpt are stripped of C0 and C1 controls", () => {
    const evil = "/home/x/.ssh/id_rsa\u001b[31m\u009b\u0007";
    const v = classifyViolation(
      { exitCode: 1, stdout: "", stderr: `Error: EACCES: permission denied, open '${evil}'` },
      deny,
    );
    assert.ok(v, "a violation is still reported");
    assert.equal(v.target, "/home/x/.ssh/id_rsa[31m");
    assert.doesNotMatch(`${v.target}${v.deniedResource}${v.evidence.stderrExcerpt}`, /[\u0000-\u001f\u007f-\u009f]/);
  });
});
