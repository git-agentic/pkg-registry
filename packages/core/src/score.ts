import type { Finding, Severity, Verdict } from "./types.js";

/**
 * Scoring policy. Centralised so Phase 2 can make these per-enterprise tunable
 * without touching rule or proxy code.
 */
export const POLICY = {
  /** Points deducted per finding, before any rule/diff multiplier. */
  severityWeight: {
    info: 0,
    low: 4,
    medium: 12,
    high: 25,
    critical: 55,
  } satisfies Record<Severity, number>,

  /** Files added/changed in this release are weighted more heavily. */
  diffMultiplier: 1.6,

  /** Verdict thresholds on the 0–100 score. */
  thresholds: { allow: 80, warn: 50 },

  /** Any finding at/above this severity forces a `block`, ignoring the score. */
  hardBlockSeverity: "critical" as Severity,
} as const;

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** Deterministically reduce findings to a 0–100 score. */
export function scoreFindings(findings: Finding[]): number {
  const penalty = findings.reduce((sum, f) => sum + Math.max(0, f.weight), 0);
  return clamp(Math.round(100 - penalty), 0, 100);
}

/** Map a score + findings to a verdict, honouring the hard-block override. */
export function verdictFor(score: number, findings: Finding[]): Verdict {
  const hardBlock = findings.some(
    (f) => severityRank(f.severity) >= severityRank(POLICY.hardBlockSeverity),
  );
  if (hardBlock) return "block";
  if (score >= POLICY.thresholds.allow) return "allow";
  if (score >= POLICY.thresholds.warn) return "warn";
  return "block";
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}
