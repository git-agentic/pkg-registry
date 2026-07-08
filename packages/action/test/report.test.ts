import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { renderPrComment, REPORT_MARKER } from "../src/report.js";
import type { TreeAuditResult } from "@sentinel/core";

const result: TreeAuditResult = {
  aggregate: {
    verdict: "block", gated: true,
    counts: { allow: 1, warn: 1, block: 1, error: 0 },
    provenance: { verified: 1, invalid: 0, absent: 2, unknown: 0 },
    integrityMismatch: 0,
  },
  packages: [
    { name: "evil-pkg", version: "2.0.0", status: "block", score: 10, topFinding: "changed hands: possible takeover", topFindingRuleId: "release-anomaly", error: null, provenance: "absent", integrityMismatch: false },
    { name: "warny", version: "1.2.0", status: "warn", score: 60, topFinding: "network egress", topFindingRuleId: "network-egress", error: null, provenance: "absent", integrityMismatch: false },
    { name: "fine", version: "1.0.0", status: "allow", score: 100, topFinding: null, topFindingRuleId: null, error: null, provenance: "verified", integrityMismatch: false },
  ],
};

describe("renderPrComment", () => {
  const md = renderPrComment(result, { now: "2026-07-08T00:00:00Z" });
  test("begins with the hidden idempotency marker", () => {
    assert.ok(md.startsWith(REPORT_MARKER));
  });
  test("shows the aggregate verdict and counts", () => {
    assert.match(md, /BLOCK/);
    assert.match(md, /1 allow/);
    assert.match(md, /1 block/);
  });
  test("lists the worst offenders (block before warn) with finding text", () => {
    const iEvil = md.indexOf("evil-pkg");
    const iWarn = md.indexOf("warny");
    assert.ok(iEvil > 0 && iWarn > 0 && iEvil < iWarn, "block row should precede warn row");
    assert.match(md, /changed hands/);
  });
  test("does not list allow rows in the offenders table", () => {
    // 'fine' (allow) should not appear as an offender row
    assert.equal(md.includes("| fine@1.0.0"), false);
  });
  test("escapes a pipe in the package coordinate so it can't break the table", () => {
    const evilResult: TreeAuditResult = {
      aggregate: {
        verdict: "block", gated: true,
        counts: { allow: 0, warn: 0, block: 1, error: 0 },
        provenance: { verified: 0, invalid: 0, absent: 1, unknown: 0 },
        integrityMismatch: 0,
      },
      packages: [
        { name: "evil|name", version: "1.0.0", status: "block", score: 5, topFinding: "malicious", topFindingRuleId: null, error: null, provenance: "absent", integrityMismatch: false },
      ],
    };
    const evilMd = renderPrComment(evilResult, { now: "2026-07-08T00:00:00Z" });
    assert.match(evilMd, /evil\\\|name@1\.0\.0/);
    assert.equal(evilMd.includes("| evil|name@"), false);
  });
  test("shows a remediation hint per offender and an explain pointer", () => {
    const withRule: TreeAuditResult = {
      aggregate: { verdict: "block", gated: true, counts: { allow: 0, warn: 0, block: 1, error: 0 }, provenance: { verified: 0, invalid: 0, absent: 1, unknown: 0 }, integrityMismatch: 0 },
      packages: [{ name: "evil", version: "2.0.0", status: "block", score: 10, topFinding: "changed hands", topFindingRuleId: "release-anomaly", error: null, provenance: "absent", integrityMismatch: false }],
    };
    const md = renderPrComment(withRule, { now: "2026-07-08T00:00:00Z" });
    assert.match(md, /pin to|known-good|earlier version/i); // release-anomaly hint text
    assert.match(md, /sentinel explain/);
  });
});
