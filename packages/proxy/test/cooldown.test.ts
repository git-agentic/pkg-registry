import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { cooldownDecision, resolvePublishTime, applyCooldown, blockOverlay } from "../src/cooldown.js";
import type { EnterprisePolicy, AuditReport } from "@agentic-sentinel/core";

const NOW = Date.parse("2026-07-12T00:00:00Z");

const pol = (cd?: object): EnterprisePolicy =>
  ({
    schema: 1,
    version: "t",
    scoring: {
      severityWeight: { info: 0, low: 4, medium: 12, high: 25, critical: 55 },
      diffMultiplier: 1.6,
      thresholds: { allow: 80, warn: 50 },
      hardBlockSeverity: "critical",
    },
    rules: { disabled: [] },
    allow: [],
    deny: [],
    privateNamespaces: [],
    ...(cd ? { releaseCooldown: cd } : {}),
  }) as EnterprisePolicy;

describe("cooldownDecision", () => {
  test("fresh non-exempt version → block", () => {
    const d = cooldownDecision({ policy: pol({ hours: 72 }), name: "x", publishTime: "2026-07-11T22:00:00Z", now: NOW });
    assert.equal(d.block, true);
  });
  test("version older than window → serve", () => {
    const d = cooldownDecision({ policy: pol({ hours: 72 }), name: "x", publishTime: "2026-07-01T00:00:00Z", now: NOW });
    assert.equal(d.block, false);
  });
  test("exempt package (matchPackage) bypasses even when fresh", () => {
    const d = cooldownDecision({
      policy: pol({ hours: 72, exempt: ["@acme/*"] }),
      name: "@acme/tool",
      publishTime: "2026-07-11T23:00:00Z",
      now: NOW,
    });
    assert.equal(d.block, false);
  });
  test("missing publish time on a matching non-exempt package → fail closed (block)", () => {
    const d = cooldownDecision({ policy: pol({ hours: 72 }), name: "x", publishTime: null, now: NOW });
    assert.equal(d.block, true);
  });
  test("no cooldown policy → never block", () => {
    assert.equal(cooldownDecision({ policy: pol(), name: "x", publishTime: null, now: NOW }).block, false);
  });
});

describe("resolvePublishTime", () => {
  test("public uses packument time", () =>
    assert.equal(resolvePublishTime({ isPrivate: false, publicTime: "2026-01-01T00:00:00Z" }), "2026-01-01T00:00:00Z"));
  test("private uses StoredVersion.publishedAt, not packument time map", () =>
    assert.equal(resolvePublishTime({ isPrivate: true, privatePublishedAt: "2026-02-02T00:00:00Z" }), "2026-02-02T00:00:00Z"));
  test("missing → null", () => assert.equal(resolvePublishTime({ isPrivate: false }), null));
});

describe("applyCooldown", () => {
  const rep = (): AuditReport => ({ verdict: "allow", score: 100, findings: [], meta: { integrity: "sha512-x" } }) as unknown as AuditReport;
  test("block overlays verdict + finding without mutating input", () => {
    const r = rep();
    const out = applyCooldown(r, { block: true, reason: "fresh release" });
    assert.equal(out.verdict, "block");
    assert.ok(out.findings.some((f) => f.ruleId === "release-cooldown"));
    assert.equal(r.verdict, "allow", "input report must be unmutated");
  });
  test("no block → returned unchanged", () => {
    const r = rep();
    assert.equal(applyCooldown(r, { block: false }).verdict, "allow");
  });
});

describe("blockOverlay", () => {
  const rep = (): AuditReport => ({ verdict: "allow", score: 100, findings: [], meta: { integrity: "sha512-x" } }) as unknown as AuditReport;
  const finding = {
    ruleId: "runtime-violation", category: "install-script" as const, severity: "critical" as const,
    message: "test finding", onChangedFile: false, evidence: [], weight: 0, waived: false,
  };
  test("returns a new object with verdict block and the finding prepended", () => {
    const r = rep();
    const out = blockOverlay(r, finding);
    assert.equal(out.verdict, "block");
    assert.deepEqual(out.findings[0], finding);
    assert.notEqual(out, r, "must return a new object");
  });
  test("does not mutate the input report", () => {
    const r = rep();
    blockOverlay(r, finding);
    assert.equal(r.verdict, "allow");
    assert.deepEqual(r.findings, []);
  });
});
