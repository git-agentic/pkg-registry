import type { CapabilityDelta, Finding, ReleaseContext } from "../types.js";
import { mkFinding } from "./util.js";

const DANGEROUS = new Set(["network", "process"]);

/**
 * Signal 4 (Phase 16): a dangerous capability (network/process) present in this release that
 * the PREVIOUS published version did not have. Sourced from the audit's already-computed
 * `capabilityDelta.added` — emitted in `buildAudit`, not the rule pipeline (the delta is
 * computed after `runRules`). Pure, total, deterministic. Inert without a predecessor or delta.
 * Weighted `metadata` finding; compounds with the release-anomaly rule.
 */
export function capabilityNoveltyFindings(delta: CapabilityDelta | null, rc: ReleaseContext | undefined): Finding[] {
  if (!delta || !rc?.previousVersion) return [];
  const novel = delta.added.filter((c) => DANGEROUS.has(c.kind));
  if (novel.length === 0) return [];
  const kinds = [...new Set(novel.map((c) => c.kind))].join(", ");
  return [mkFinding({
    ruleId: "capability-novelty",
    category: "metadata",
    severity: "medium",
    message: `\`(release)\` added a ${kinds} capability that version ${rc.previousVersion} did not have — a newly dangerous behavior.`,
    evidence: novel.flatMap((c) => c.evidence).slice(0, 3),
    files: [],
  })];
}
