import type { AuditInput, Finding, Rule } from "../types.js";
import { mkFinding } from "./util.js";

const DORMANCY_DAYS = 365;
const DAY_MS = 86_400_000;

/** Days between two ISO timestamps, or null if either is missing/unparseable. Pure — parses
 *  GIVEN immutable timestamps, never reads the clock (invariant #1). */
function daysBetween(a?: string, b?: string): number | null {
  if (!a || !b) return null;
  const ta = Date.parse(a), tb = Date.parse(b);
  if (Number.isNaN(ta) || Number.isNaN(tb)) return null;
  return (tb - ta) / DAY_MS;
}

/**
 * Flags a release that is anomalous relative to the package's OWN history: a changed
 * maintainer set, dormancy resurrection, or a first-version package that already runs
 * install scripts. Pure, policy-blind, deterministic (immutable packument data only — no
 * wall-clock). Inert without a `releaseContext`. Weighted `metadata` findings that compound;
 * never a standalone hard block.
 */
export const releaseAnomalyRule: Rule = {
  id: "release-anomaly",
  category: "metadata",
  run(input: AuditInput): Finding[] {
    const rc = input.releaseContext;
    if (!rc) return [];
    const out: Finding[] = [];
    const mk = (severity: Finding["severity"], message: string): Finding =>
      mkFinding({ ruleId: this.id, category: this.category, severity, message, evidence: [], files: input.files });

    // Signal 1 — maintainer change (only when a predecessor's maintainers are known).
    if (rc.previousMaintainers && rc.previousMaintainers.length > 0) {
      const prev = new Set(rc.previousMaintainers);
      const cur = new Set(input.meta.maintainers);
      const anyPrevRemains = [...prev].some((m) => cur.has(m));
      const anyNew = [...cur].some((m) => !prev.has(m));
      if (!anyPrevRemains && cur.size > 0) {
        out.push(mk("high", `\`${input.meta.name}\` changed hands: none of the previous maintainers (${[...prev].join(", ")}) remain — possible account/ownership takeover.`));
      } else if (anyNew) {
        const added = [...cur].filter((m) => !prev.has(m));
        out.push(mk("low", `\`${input.meta.name}\` added a new maintainer (${added.join(", ")}) since ${rc.previousVersion ?? "the prior version"}.`));
      }
    }

    // Signal 2 — dormancy resurrection.
    const gap = daysBetween(rc.previousPublishedAt, rc.currentPublishedAt);
    if (gap !== null && gap >= DORMANCY_DAYS) {
      out.push(mk("low", `\`${input.meta.name}\` was dormant ~${Math.round(gap)} days before this release — a resurrected package is a supply-chain risk.`));
    }

    // Signal 3 — first-version package that already runs install scripts.
    if (rc.versionCount === 1 && input.meta.hasInstallScripts) {
      out.push(mk("medium", `\`${input.meta.name}\` is a first published version that already runs install scripts — throwaway/fresh-package risk.`));
    }

    return out;
  },
};
