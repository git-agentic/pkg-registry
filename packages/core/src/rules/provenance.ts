import type { AuditInput, Finding, Rule } from "../types.js";
import { mkFinding } from "./util.js";

/**
 * Surfaces the verified registry-signature and provenance status as findings.
 * The verification itself runs in the audit-assembly path (offline); this rule
 * only reads the already-verified `meta` and never sets the score directly —
 * severity weights + the policy gate decide impact.
 */
export const provenanceRule: Rule = {
  id: "provenance",
  category: "provenance",
  run(input: AuditInput): Finding[] {
    const { signature, provenance } = input.meta;
    const out: Finding[] = [];
    const add = (severity: Finding["severity"], message: string) =>
      out.push(mkFinding({ ruleId: "provenance", category: "provenance", severity, message, evidence: [], files: input.files }));

    if (signature === "invalid") add("critical", "registry signature failed verification — possible tampering");
    else if (signature === "unsigned") add("low", "package has no registry signature");
    else if (signature === "unknown") add("info", "registry signature present but no trusted key to verify it");

    if (provenance === "absent") add("info", "no build provenance attestation");
    return out;
  },
};
