import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { remediate, remediationHint } from "../src/remediation.js";
import type { AuditReport, Finding } from "../src/types.js";

function finding(over: Partial<Finding> = {}): Finding {
  return { ruleId: "install-scripts", category: "capability", severity: "high", message: "runs a postinstall", onChangedFile: false, evidence: [], ...over } as Finding;
}
function report(over: Partial<AuditReport> = {}): AuditReport {
  return {
    schema: 3,
    meta: { name: "acme", version: "2.0.0", integrity: "sha512-x", author: null, maintainers: [], license: "MIT", hasInstallScripts: true, signature: "unsigned", provenance: "absent" },
    score: 40, verdict: "block", findings: [finding()],
    ...over,
  } as unknown as AuditReport;
}

describe("remediate", () => {
  test("maps a known ruleId to summary + action", () => {
    const r = remediate(report());
    assert.equal(r.items.length, 1);
    assert.equal(r.items[0]!.ruleId, "install-scripts");
    assert.match(r.items[0]!.action, /approve|manifest|alternative/i);
  });

  test("orders items worst-severity first", () => {
    const r = remediate(report({ findings: [
      finding({ ruleId: "provenance", severity: "low", message: "no provenance" }),
      finding({ ruleId: "install-scripts", severity: "high", message: "postinstall" }),
    ] }));
    assert.deepEqual(r.items.map((i) => i.ruleId), ["install-scripts", "provenance"]);
  });

  test("block verdict yields a waiver with the correct coordinates + payload", () => {
    const r = remediate(report());
    assert.ok(r.waiver);
    assert.equal(r.waiver!.name, "acme");
    assert.equal(r.waiver!.version, "2.0.0");
    assert.equal(r.waiver!.requestPayload.integrity, "sha512-x");
    assert.match(r.waiver!.approveCommand, /^sentinel approve acme 2\.0\.0/);
  });

  test("allow verdict yields no waiver", () => {
    assert.equal(remediate(report({ verdict: "allow", score: 100, findings: [] })).waiver, null);
  });

  test("unknown ruleId falls back to a generic action, never throws", () => {
    const r = remediate(report({ findings: [finding({ ruleId: "brand-new-rule", category: "metadata" })] }));
    assert.equal(r.items.length, 1);
    assert.ok(r.items[0]!.action.length > 0);
  });

  test("remediationHint returns a short action string for a known ruleId", () => {
    assert.ok(remediationHint("release-anomaly").length > 0);
    assert.ok(remediationHint("nonexistent").length > 0); // generic fallback
  });

  test("deterministic — same report yields the same remediation", () => {
    assert.deepEqual(remediate(report()), remediate(report()));
  });
});
