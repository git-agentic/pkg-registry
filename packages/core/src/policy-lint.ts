import type { EnterprisePolicy } from "./policy.js";
import type { Severity } from "./types.js";

export interface LintFinding { code: string; message: string }

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

/**
 * Structural + semantic lint of an EnterprisePolicy. Pure. Errors mark a dangerously-broken
 * policy (an operator should not sign it); warnings are suspicious-but-legal values. Never scores.
 */
export function lintPolicy(policy: EnterprisePolicy): { errors: LintFinding[]; warnings: LintFinding[] } {
  const errors: LintFinding[] = [];
  const warnings: LintFinding[] = [];
  const s = policy.scoring;

  // Thresholds.
  const { allow, warn } = s.thresholds;
  for (const [name, v] of [["allow", allow], ["warn", warn]] as const) {
    if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 100) {
      errors.push({ code: "threshold-range", message: `thresholds.${name} (${v}) must be a number in 0–100.` });
    }
  }
  if (Number.isFinite(allow) && Number.isFinite(warn) && allow < warn) {
    errors.push({ code: "threshold-inverted", message: `thresholds.allow (${allow}) is below thresholds.warn (${warn}) — a package could out-score "allow" yet be classed "warn".` });
  }

  // hardBlockSeverity.
  if (!SEVERITIES.includes(s.hardBlockSeverity)) {
    errors.push({ code: "bad-hard-block-severity", message: `hardBlockSeverity "${s.hardBlockSeverity}" is not one of ${SEVERITIES.join("|")}.` });
  } else if (s.hardBlockSeverity === "info" || s.hardBlockSeverity === "low") {
    warnings.push({ code: "aggressive-hard-block", message: `hardBlockSeverity "${s.hardBlockSeverity}" hard-blocks on trivial findings.` });
  }

  // severityWeight: presence + non-negative + finite.
  for (const sev of SEVERITIES) {
    const w = s.severityWeight[sev];
    if (typeof w !== "number" || !Number.isFinite(w) || w < 0) {
      errors.push({ code: "bad-severity-weight", message: `severityWeight.${sev} (${w}) must be a finite number ≥ 0.` });
    }
  }
  // Monotonicity (only when all weights are valid numbers).
  const weightsOk = SEVERITIES.every((sev) => Number.isFinite(s.severityWeight[sev]) && s.severityWeight[sev] >= 0);
  if (weightsOk) {
    for (let i = 1; i < SEVERITIES.length; i++) {
      const lower = SEVERITIES[i - 1]!, higher = SEVERITIES[i]!;
      if (s.severityWeight[lower] > s.severityWeight[higher]) {
        warnings.push({ code: "non-monotonic-weights", message: `severityWeight.${lower} (${s.severityWeight[lower]}) outweighs severityWeight.${higher} (${s.severityWeight[higher]}).` });
      }
    }
    // A lone critical finding still allows?
    if (Number.isFinite(allow) && 100 - s.severityWeight.critical >= allow) {
      warnings.push({ code: "threshold-too-low", message: `thresholds.allow (${allow}) is low enough that a single critical finding still scores "allow".` });
    }
    // Nothing but a perfect score can be allow?
    if (Number.isFinite(allow) && allow >= 100) {
      warnings.push({ code: "threshold-too-high", message: `thresholds.allow (${allow}) means only a finding-free package can be "allow".` });
    }
  }

  // diffMultiplier.
  if (typeof s.diffMultiplier !== "number" || !Number.isFinite(s.diffMultiplier) || s.diffMultiplier <= 0) {
    errors.push({ code: "diff-multiplier-nonpositive", message: `scoring.diffMultiplier (${s.diffMultiplier}) must be > 0.` });
  } else if (s.diffMultiplier < 1) {
    warnings.push({ code: "diff-multiplier-weak", message: `scoring.diffMultiplier (${s.diffMultiplier}) < 1 weakens the changed-in-this-release signal.` });
  }

  // List hygiene: malformed entries + deny/allow conflict.
  const badEntry = (arr: unknown[], field: string) =>
    arr.some((x) => typeof x !== "string" || x.trim() === "") &&
    errors.push({ code: "malformed-list-entry", message: `${field} has a non-string or empty entry.` });
  badEntry(policy.privateNamespaces ?? [], "privateNamespaces");
  badEntry(policy.requireSignature ?? [], "requireSignature");
  badEntry(policy.requireProvenance ?? [], "requireProvenance");
  if ((policy.allow ?? []).some((a) => typeof a.package !== "string" || a.package.trim() === "")) {
    errors.push({ code: "malformed-list-entry", message: "allow has an entry with a non-string or empty package." });
  }
  if ((policy.deny ?? []).some((d) => typeof d.package !== "string" || d.package.trim() === "")) {
    errors.push({ code: "malformed-list-entry", message: "deny has an entry with a non-string or empty package." });
  }
  const denySet = new Set((policy.deny ?? []).map((d) => d.package));
  for (const a of policy.allow ?? []) {
    if (denySet.has(a.package)) {
      errors.push({ code: "deny-allow-conflict", message: `"${a.package}" is in both allow and deny.` });
    }
  }

  return { errors, warnings };
}
