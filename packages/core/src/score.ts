import type { Audit, AuditReport, ProvenanceIdentity, ScoredFinding, Severity, Verdict } from "./types.js";
import { DEFAULT_POLICY, matchPackage, policyHashOf, type EnterprisePolicy, type ProvenanceIdentityRequirement } from "./policy.js";
import { canonical, typosquatMatch, normalizeName } from "./name-distance.js";
import type { Finding } from "./types.js";

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

/** Findings that score() SYNTHESIZES from the policy (not from runRules): the
 *  `dependency-confusion` finding built in dependencyConfusion() below and the
 *  `provenance-identity` finding pushed onto `scored` in score(). A re-score of a
 *  stored AuditReport (e.g. the policy-preview route) must strip these from
 *  `report.findings` first, or they double-count — re-synthesized AND re-appended
 *  on top of the copy already baked into the stored report. Keep in sync with the
 *  synthesis sites below. */
export const POLICY_SYNTHESIZED_RULE_IDS: ReadonlySet<string> = new Set([
  "dependency-confusion",
  "provenance-identity",
]);

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
  const dcFinding = dependencyConfusion(audit.meta.name, policy.privateNamespaces ?? []);
  const rawFindings = dcFinding ? [...audit.findings, dcFinding] : audit.findings;
  const scored: ScoredFinding[] = rawFindings.map((f) => {
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
  const reqSig = (policy.requireSignature ?? []).some((p) => matchPackage(p, audit.meta.name)) && audit.meta.signature !== "verified";
  const reqProv = (policy.requireProvenance ?? []).some((p) => matchPackage(p, audit.meta.name)) && (audit.meta.provenance !== "verified" || !audit.meta.provenanceIdentity);

  // Identity gate (ADR-0022): every matching entry must be satisfied (fail-closed
  // AND). "unknown" is exempt — an outage must not block ordinary installs; the
  // requireProvenance gate is the opt-in fail-closed lever for that case.
  let idViolation: string | null = null;
  const idEntries = (policy.provenanceIdentities ?? []).filter((e) => matchPackage(e.pattern, audit.meta.name));
  if (idEntries.length > 0 && audit.meta.provenance !== "unknown") {
    if (audit.meta.provenance !== "verified") {
      idViolation = `provenance is ${audit.meta.provenance}, policy requires verified provenance`;
    } else {
      const id = audit.meta.provenanceIdentity ?? null;
      for (const e of idEntries) {
        const v = identityViolation(e, id);
        if (v) { idViolation = v; break; }
      }
    }
  }
  if (idViolation) {
    scored.push({
      ruleId: "provenance-identity", category: "provenance", severity: "critical",
      message: `provenance identity policy violation — ${idViolation}`,
      onChangedFile: false, evidence: [], weight: 0, waived: false,
    });
  }

  let verdict: Verdict;
  if (denied || hardBlock || reqSig || reqProv || idViolation !== null) verdict = "block";
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

/**
 * Dependency-confusion detection (ADR-0026): a PUBLIC package whose name is a
 * confusable look-alike of a namespace the operator explicitly claimed
 * (policy.privateNamespaces). Never flags the legitimate claimed package itself
 * (it matches the claim via matchPackage). Pure; guarded against a malformed name.
 */
function dependencyConfusion(name: string, privateNamespaces: string[]): Finding | null {
  if (!name || privateNamespaces.length === 0) return null;
  // The real private package legitimately matches its own claim — never flag it.
  if (privateNamespaces.some((c) => matchPackage(c, name))) return null;
  const nc = canonical(name);
  for (const claim of privateNamespaces) {
    const scope = normalizeName(claim); // "@acme/*" → "acme"; "internal-tool" → "internaltool"
    if (scope.length < 3) continue;
    if (nc === scope || nc.startsWith(scope) || typosquatMatch(nc, scope)) {
      return {
        ruleId: "dependency-confusion", category: "metadata", severity: "high",
        message: `\`${name}\` resembles your claimed private namespace \`${claim}\` — possible dependency confusion.`,
        onChangedFile: false, evidence: [],
      };
    }
  }
  return null;
}

function identityViolation(
  e: ProvenanceIdentityRequirement,
  id: ProvenanceIdentity | null,
): string | null {
  const checks: [string, string | undefined, string | null, boolean][] = [
    ["repository", e.repository, id?.sourceRepository ?? null, true],
    ["issuer", e.issuer, id?.issuer ?? null, false],
    ["workflowRef", e.workflowRef, id?.workflow ?? null, true],
    ["builder", e.builder, id?.builder ?? null, true],
  ];
  for (const [label, want, actual, glob] of checks) {
    if (want === undefined) continue;
    const ok = actual !== null && (glob ? matchPackage(want, actual) : want === actual);
    if (!ok) return `${label} is ${actual ?? "unknown"}, policy requires ${want}`;
  }
  return null;
}
