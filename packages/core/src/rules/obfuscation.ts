import type { AuditInput, Evidence, Finding, PackageFile, Rule } from "../types.js";
import { codeFiles, mkFinding, scanLines } from "./util.js";

const PATTERNS = [
  // A property called `eval` is an ordinary method, not JavaScript's direct
  // evaluator. Matching `.eval(` misattributes domain/runtime APIs as code
  // execution (for example WebAssembly N-API shims). Explicit global-object
  // access still reaches the language evaluator and must remain covered.
  {
    re: /(?:(?<![.$\w])eval|(?:globalThis|global|window|self)\s*(?:(?:\?\.|\.)\s*eval|\[\s*['"]eval['"]\s*\]))\s*\(/,
    sev: "high" as const,
    why: "uses JavaScript eval()",
  },
  { re: /require\s*\(\s*(atob|Buffer\.from|_0x|[a-z]\([^)]*\))/i, sev: "high" as const, why: "dynamic require of a computed string" },
];

const DECODED_ASSIGNMENT = /\b(?:const|let|var)\s+([$A-Z_a-z][$\w]*)\s*=\s*(?:atob\s*\(|Buffer\.from\s*\([^;\n]*?['"]base64['"])/g;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Find decoded source that is subsequently executed by the Function constructor. */
function decodedFunctionEvidence(file: PackageFile): Evidence[] {
  const evidence = scanLines(
    file,
    /new\s+Function\s*\(\s*(?:atob\s*\(|Buffer\.from\s*\([^;\n]*?['"]base64['"])/i,
    2,
  );
  if (evidence.length >= 2) return evidence;

  DECODED_ASSIGNMENT.lastIndex = 0;
  for (const match of file.content.matchAll(DECODED_ASSIGNMENT)) {
    const variable = match[1];
    if (!variable) continue;
    const usesDecodedSource = new RegExp(`new\\s+Function\\s*\\(\\s*${escapeRegExp(variable)}\\b`);
    evidence.push(...scanLines(file, usesDecodedSource, 2 - evidence.length));
    if (evidence.length >= 2) break;
  }
  return evidence;
}

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

      const dynamicFunction = decodedFunctionEvidence(file);
      if (dynamicFunction.length > 0) {
        findings.push(
          mkFinding({
            ruleId: this.id,
            category: this.category,
            severity: "high",
            message: "Obfuscation: executes decoded source with the Function constructor.",
            evidence: dynamicFunction,
            files: input.files,
          }),
        );
      }
    }
    return findings;
  },
};
