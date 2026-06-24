import type { AuditInput, Evidence, Finding, Rule } from "../types.js";
import { codeFiles, mkFinding, scanLines, truncate } from "./util.js";

const PATTERNS = [
  { re: /\beval\s*\(/, sev: "high" as const, why: "uses eval()" },
  { re: /new\s+Function\s*\(/, sev: "high" as const, why: "uses the Function constructor" },
  { re: /\batob\s*\(|Buffer\.from\([^)]*['"]base64['"]\)/, sev: "medium" as const, why: "base64-decodes at runtime" },
  { re: /\bunescape\s*\(|decodeURIComponent\(escape/, sev: "medium" as const, why: "uses unescape-style decoding" },
  { re: /(\\x[0-9a-f]{2}){6,}/i, sev: "medium" as const, why: "contains \\xNN-encoded string runs" },
  { re: /String\.fromCharCode\(|charCodeAt\(/, sev: "low" as const, why: "char-code string assembly" },
  { re: /require\s*\(\s*(atob|Buffer\.from|_0x|[a-z]\([^)]*\))/i, sev: "high" as const, why: "dynamic require of a computed string" },
];

/** Long base64/hex blobs are a strong obfuscation signal on their own. */
const BLOB = /['"`][A-Za-z0-9+/=]{120,}['"`]/;

export const obfuscationRule: Rule = {
  id: "obfuscation",
  category: "obfuscation",
  run(input: AuditInput): Finding[] {
    const findings: Finding[] = [];
    for (const file of codeFiles(input)) {
      for (const p of PATTERNS) {
        const ev: Evidence[] = scanLines(file, p.re, 2);
        if (ev.length === 0) continue;
        findings.push(
          mkFinding({
            ruleId: this.id,
            category: this.category,
            severity: p.sev,
            message: `Obfuscation: ${p.why}.`,
            evidence: ev,
            files: input.files,
          }),
        );
      }

      const blob = BLOB.exec(file.content);
      if (blob) {
        findings.push(
          mkFinding({
            ruleId: this.id,
            category: this.category,
            severity: "medium",
            message: "Contains a large encoded blob (≥120 chars) consistent with packed/obfuscated payloads.",
            evidence: [{ file: file.path, snippet: truncate(blob[0], 80) }],
            files: input.files,
          }),
        );
      }
    }
    return findings;
  },
};
