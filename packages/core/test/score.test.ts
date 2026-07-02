import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { runAudit, score, DEFAULT_POLICY, matchPackage, type EnterprisePolicy } from "../src/index.js";
import { ensureFixtures, tarball } from "./helpers.js";

const baseMeta = {
  author: null, maintainers: [] as string[], license: null,
  hasInstallScripts: false, signature: "verified" as const, provenance: "present" as const,
};
const auditOf = (name: string, version: string, baseline?: string) =>
  runAudit({ meta: { name, version, ...baseMeta }, tarball: tarball(name, version),
    baselineTarball: baseline ? tarball(name, baseline) : undefined });

function policy(over: Partial<EnterprisePolicy> = {}): EnterprisePolicy {
  return { ...DEFAULT_POLICY, version: "test", ...over };
}

describe("matchPackage glob", () => {
  test("exact and prefix match, anchored", () => {
    assert.equal(matchPackage("esbuild", "esbuild"), true);
    assert.equal(matchPackage("esbuild", "esbuild-wasm"), false);   // anchored, not substring
    assert.equal(matchPackage("evilcorp-*", "evilcorp-utils"), true);
    assert.equal(matchPackage("@acme/*", "@acme/payments"), true);
    assert.equal(matchPackage("@acme/*", "@other/x"), false);
    assert.equal(matchPackage("a.b", "axb"), false);                // '.' is literal, not regex
  });
});

describe("score under policies", () => {
  before(() => ensureFixtures());

  test("default policy blocks the malicious fixture (regression)", async () => {
    const r = score(await auditOf("color-stream", "1.4.1", "1.4.0"), DEFAULT_POLICY);
    assert.equal(r.verdict, "block");
    assert.equal(r.score, 0);
    assert.equal(r.policy.version, "default");
    assert.match(r.policy.hash, /^sha256-/);
  });

  test("same bytes, two policies → different verdicts", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    const strict = score(audit, DEFAULT_POLICY);
    const lax = score(audit, policy({
      rules: { disabled: ["secret-exfil", "install-scripts", "network-egress", "obfuscation"] },
    }));
    assert.equal(strict.verdict, "block");
    assert.equal(lax.verdict, "allow");           // all rules disabled → nothing scores or hard-blocks
    assert.equal(lax.score, 100);
  });

  test("allow waiver clears a finding from score AND hard-block, keeps it visible", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    // Waive every rule that fires, for this package only.
    const waived = score(audit, policy({
      allow: [{ package: "color-stream", rules: ["secret-exfil", "install-scripts", "network-egress", "obfuscation"], reason: "test" }],
    }));
    assert.equal(waived.verdict, "allow", "no non-waived critical remains to hard-block");
    assert.ok(waived.findings.length > 0, "findings still present");
    assert.ok(waived.findings.every((f) => f.waived), "all marked waived");
    assert.ok(waived.findings[0]?.waivedBy?.startsWith("allow: color-stream"));
  });

  test("deny forces block on an otherwise-clean package", async () => {
    const clean = await auditOf("leftpad-lite", "1.0.1");
    const denied = score(clean, policy({ deny: [{ package: "leftpad-lite", reason: "blocked" }] }));
    assert.equal(denied.verdict, "block");
    const allowed = score(clean, DEFAULT_POLICY);
    assert.equal(allowed.verdict, "allow");
  });

  test("threshold + weight overrides change the verdict", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    const lenient = score(audit, policy({
      scoring: { ...DEFAULT_POLICY.scoring, hardBlockSeverity: "critical", severityWeight: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, thresholds: { allow: 0, warn: 0 } },
    }));
    // hardBlock still fires on the (non-waived) critical severity regardless of zeroed weights
    assert.equal(lenient.verdict, "block");
  });

  test("scoring is deterministic for a fixed policy", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    const a = score(audit, DEFAULT_POLICY);
    const b = score(audit, DEFAULT_POLICY);
    assert.deepEqual(a.findings.map((f) => [f.ruleId, f.weight, f.waived]), b.findings.map((f) => [f.ruleId, f.weight, f.waived]));
    assert.equal(a.verdict, b.verdict);
  });
});
