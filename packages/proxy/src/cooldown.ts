import { matchPackage, type AuditReport, type EnterprisePolicy, type ScoredFinding } from "@git-agentic/sentinel-core";

const HOUR_MS = 3_600_000;

/**
 * Authoritative publish timestamp per resolution origin.
 * Public origin: the packument's `time[version]`. Private origin: the private
 * store's `StoredVersion.publishedAt` — never the (attacker-writable) public
 * packument time map.
 */
export function resolvePublishTime(args: {
  isPrivate: boolean;
  publicTime?: string;
  privatePublishedAt?: string;
}): string | null {
  const t = args.isPrivate ? args.privatePublishedAt : args.publicTime;
  return t ?? null;
}

/**
 * Decide whether the release-cooldown overlay should block this version.
 * Fail-closed: a matching, non-exempt package with a missing or unparseable
 * publish time is blocked rather than served.
 */
export function cooldownDecision(args: {
  policy: EnterprisePolicy;
  name: string;
  publishTime: string | null;
  now: number;
}): { block: boolean; reason?: string } {
  const cd = args.policy.releaseCooldown;
  if (!cd) return { block: false };
  if ((cd.exempt ?? []).some((p) => matchPackage(p, args.name))) return { block: false };

  const windowMs = cd.hours * HOUR_MS;

  if (args.publishTime === null) {
    return { block: true, reason: `release-cooldown: no authoritative publish time for ${args.name}; cooldown fails closed` };
  }
  const t = Date.parse(args.publishTime);
  if (Number.isNaN(t)) {
    return { block: true, reason: `release-cooldown: unparseable publish time for ${args.name}; cooldown fails closed` };
  }

  const ageMs = args.now - t;
  if (ageMs < windowMs) {
    const remainH = Math.ceil((windowMs - ageMs) / HOUR_MS);
    return { block: true, reason: `release-cooldown: version is younger than the ${cd.hours}h cooldown (~${remainH}h remaining)` };
  }
  return { block: false };
}

/**
 * Immutable overlay: returns a NEW report with `verdict: "block"` and `finding`
 * prepended to `report.findings`. The input report is never mutated.
 */
export function blockOverlay(report: AuditReport, finding: ScoredFinding): AuditReport {
  return { ...report, verdict: "block", findings: [finding, ...report.findings] };
}

/**
 * Immutable overlay: on block, returns a NEW report with `verdict: "block"`
 * and a prepended `release-cooldown` critical finding. The cached report
 * passed in is never mutated; when not blocking, it's returned unchanged.
 */
export function applyCooldown(report: AuditReport, decision: { block: boolean; reason?: string }): AuditReport {
  if (!decision.block) return report;
  const finding: ScoredFinding = {
    ruleId: "release-cooldown",
    category: "metadata" as const,
    severity: "critical" as const,
    message: decision.reason ?? "release-cooldown: held by policy",
    onChangedFile: false,
    evidence: [],
    weight: 0,
    waived: false,
  };
  return blockOverlay(report, finding);
}
