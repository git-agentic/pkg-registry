import type { AuditInput, Finding, Rule } from "../types.js";
import { mkFinding } from "./util.js";
import { KNOWN_ADVISORIES, buildAdvisoryIndex, type Advisory } from "../advisory-corpus.js";

// Prebuilt index over the bundled corpus (built once). Operator advisories are merged per-call.
const BUNDLED_INDEX = buildAdvisoryIndex(KNOWN_ADVISORIES);

/**
 * Flags a package version listed as KNOWN-MALICIOUS in a bundled advisory corpus (∪ operator-supplied
 * `input.advisories`). Pure, deterministic, offline (static corpus, never fetched). An exact
 * (name, version) match ⇒ a critical `metadata` finding (hard-blocks under the default policy).
 */
export const knownAdvisoryRule: Rule = {
  id: "known-advisory",
  category: "metadata",
  run(input: AuditInput): Finding[] {
    const { name, version } = input.meta;
    const candidates: Advisory[] = [
      ...(BUNDLED_INDEX.get(name) ?? []),
      ...((input.advisories ?? []).filter((a) => a.name === name)),
    ];
    const hit = candidates.find((a) => a.version === version);
    if (!hit) return [];
    const message = hit.kind === "retraction"
      ? `\`${hit.name}@${hit.version}\` was retracted (${hit.reason}) in advisory ${hit.id} — do not install this version.`
      : `\`${hit.name}@${hit.version}\` is listed as known-malicious in advisory ${hit.id}${hit.reference ? ` (${hit.reference})` : ""} — do not install this version.`;
    return [mkFinding({
      ruleId: this.id, category: this.category, severity: hit.severity ?? "critical",
      message,
      evidence: [], files: input.files,
    })];
  },
};
