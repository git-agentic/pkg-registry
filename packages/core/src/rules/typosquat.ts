import type { AuditInput, Finding, Rule } from "../types.js";
import { mkFinding } from "./util.js";
import { canonical, typosquatMatch } from "../name-distance.js";
import { POPULAR_NPM_NAMES } from "../typosquat-corpus.js";

// Length-bucketed corpus (by canonical length) so a lookup only compares against
// nearby-length names — bounded, cheap (invariant #3). Built once at module load.
const CORPUS = POPULAR_NPM_NAMES.map((n) => n.toLowerCase());
const CORPUS_SET = new Set(CORPUS);
const BY_LEN = new Map<number, string[]>();
for (const n of CORPUS) {
  const len = canonical(n).length;
  for (const l of [len - 2, len - 1, len, len + 1, len + 2]) {
    (BY_LEN.get(l) ?? BY_LEN.set(l, []).get(l)!).push(n);
  }
}

/**
 * Flags a package whose name is a likely typosquat of a popular package. Pure and
 * policy-blind: name vs a bundled static corpus. FP controls: never flag a name that
 * IS in the corpus; skip names < 4 chars; the matched target must be distinct.
 */
export const typosquatRule: Rule = {
  id: "typosquat",
  category: "metadata",
  run(input: AuditInput): Finding[] {
    const name = input.meta.name.toLowerCase();
    if (name.length < 4 || CORPUS_SET.has(name)) return [];
    const candidates = BY_LEN.get(canonical(name).length) ?? [];
    for (const target of candidates) {
      if (typosquatMatch(name, target)) {
        return [mkFinding({
          ruleId: this.id, category: this.category, severity: "medium",
          message: `\`${input.meta.name}\` resembles the popular package \`${target}\` — possible typosquat.`,
          evidence: [], files: input.files,
        })];
      }
    }
    return [];
  },
};
