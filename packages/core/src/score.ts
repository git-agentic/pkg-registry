import type { Audit, AuditReport, ScoredFinding, Severity, Verdict } from "./types.js";
import { DEFAULT_POLICY, matchPackage, policyHashOf, type EnterprisePolicy } from "./policy.js";

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/**
 * Apply an EnterprisePolicy to a policy-independent {@link Audit}, producing the
 * scored {@link AuditReport}. Pure: same (audit, policy) ⇒ same report. Waived
 * findings stay visible but are excluded from BOTH the penalty sum and the
 * hard-block check.
 */
export function score(
  audit: Audit,
  policy: EnterprisePolicy = DEFAULT_POLICY,
  hash: string = policyHashOf(policy),
): AuditReport {
  const disabled = new Set(policy.rules.disabled);
  const scored: ScoredFinding[] = audit.findings.map((f) => {
    let waived = false;
    let waivedBy: string | undefined;
    if (disabled.has(f.ruleId)) {
      waived = true;
      waivedBy = `rule disabled: ${f.ruleId}`;
    } else {
      const allow = policy.allow.find(
        (a) => matchPackage(a.package, audit.meta.name) && a.rules.some((r) => r === f.ruleId || r === f.category),
      );
      if (allow) {
        waived = true;
        waivedBy = `allow: ${allow.package}${allow.reason ? ` — ${allow.reason}` : ""}`;
      }
    }
    const base = policy.scoring.severityWeight[f.severity];
    const weight = waived ? 0 : Math.round(base * (f.onChangedFile ? policy.scoring.diffMultiplier : 1));
    return { ...f, weight, waived, waivedBy };
  });

  const penalty = scored.reduce((s, f) => s + Math.max(0, f.weight), 0);
  const value = clamp(Math.round(100 - penalty), 0, 100);
  const denied = policy.deny.some((d) => matchPackage(d.package, audit.meta.name));
  const hardBlock = scored.some(
    (f) => !f.waived && severityRank(f.severity) >= severityRank(policy.scoring.hardBlockSeverity),
  );

  let verdict: Verdict;
  if (denied || hardBlock) verdict = "block";
  else if (value >= policy.scoring.thresholds.allow) verdict = "allow";
  else if (value >= policy.scoring.thresholds.warn) verdict = "warn";
  else verdict = "block";

  return {
    schema: 3,
    meta: audit.meta,
    score: value,
    verdict,
    findings: scored.sort((a, b) => b.weight - a.weight),
    capabilities: audit.capabilities,
    capabilityDelta: audit.capabilityDelta,
    engine: { ...audit.engine, llm: null },
    llmSummary: null,
    auditedAt: audit.auditedAt,
    durationMs: audit.durationMs,
    policy: { version: policy.version, hash },
  };
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}
