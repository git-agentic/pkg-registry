import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { lintPolicy } from "../src/policy-lint.js";
import { DEFAULT_POLICY } from "../src/policy.js";
import type { EnterprisePolicy } from "../src/policy.js";

function pol(mut: (p: EnterprisePolicy) => void): EnterprisePolicy {
  const p = structuredClone(DEFAULT_POLICY);
  mut(p);
  return p;
}
const codes = (fs: { code: string }[]) => fs.map((f) => f.code);

describe("lintPolicy", () => {
  test("DEFAULT_POLICY is clean (no errors, no warnings)", () => {
    const r = lintPolicy(DEFAULT_POLICY);
    assert.deepEqual(r.errors, []);
    assert.deepEqual(r.warnings, []);
  });

  test("inverted thresholds (allow < warn) → error", () => {
    const r = lintPolicy(pol((p) => { p.scoring.thresholds = { allow: 40, warn: 80 }; }));
    assert.ok(codes(r.errors).includes("threshold-inverted"));
  });

  test("threshold out of 0–100 → error", () => {
    assert.ok(codes(lintPolicy(pol((p) => { p.scoring.thresholds.allow = 140; })).errors).includes("threshold-range"));
  });

  test("bad hardBlockSeverity → error", () => {
    assert.ok(codes(lintPolicy(pol((p) => { (p.scoring as { hardBlockSeverity: string }).hardBlockSeverity = "boom"; })).errors).includes("bad-hard-block-severity"));
  });

  test("negative severityWeight → error", () => {
    assert.ok(codes(lintPolicy(pol((p) => { p.scoring.severityWeight.high = -5; })).errors).includes("bad-severity-weight"));
  });

  test("diffMultiplier <= 0 → error", () => {
    assert.ok(codes(lintPolicy(pol((p) => { p.scoring.diffMultiplier = 0; })).errors).includes("diff-multiplier-nonpositive"));
  });

  test("a package in both deny and allow → error", () => {
    const r = lintPolicy(pol((p) => { p.deny = [{ package: "evil" }]; p.allow = [{ package: "evil", rules: [] }]; }));
    assert.ok(codes(r.errors).includes("deny-allow-conflict"));
  });

  test("non-monotonic severityWeight (low >= high) → warning", () => {
    const r = lintPolicy(pol((p) => { p.scoring.severityWeight.low = 99; }));
    assert.ok(codes(r.warnings).includes("non-monotonic-weights"));
    assert.deepEqual(r.errors, []); // legal, just suspicious
  });

  test("diffMultiplier < 1 → warning", () => {
    assert.ok(codes(lintPolicy(pol((p) => { p.scoring.diffMultiplier = 0.5; })).warnings).includes("diff-multiplier-weak"));
  });

  test("aggressive hardBlockSeverity (low) → warning", () => {
    assert.ok(codes(lintPolicy(pol((p) => { p.scoring.hardBlockSeverity = "low"; })).warnings).includes("aggressive-hard-block"));
  });

  test("threshold-too-low: a lone critical still scores allow → warning", () => {
    // allow so low that (100 - critical weight) >= allow
    const r = lintPolicy(pol((p) => { p.scoring.thresholds = { allow: 10, warn: 5 }; }));
    assert.ok(codes(r.warnings).includes("threshold-too-low"));
  });

  test("requireProvenance with an empty-string entry → malformed-list-entry error", () => {
    const r = lintPolicy(pol((p) => { p.requireProvenance = [""]; }));
    assert.ok(codes(r.errors).includes("malformed-list-entry"));
  });
});
