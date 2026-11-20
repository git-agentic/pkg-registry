import type { AuditInput, Evidence, Finding, PackageFile, Rule } from "../types.js";
import { codeFiles, headsWithTail, lineLocator, mkFinding, scanLines, truncate } from "./util.js";

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
  // `[a-z]\(` has no unbounded tail: a `[^)]*\)` here rescanned the line from every `require(a(`.
  { re: /require\s*\(\s*(atob|Buffer\.from|_0x|[a-z]\()/i, sev: "high" as const, why: "dynamic require of a computed string" },
];

// A base64 decode is `atob(...)`, or `Buffer.from(...)` with a base64 marker
// before the statement ends. The Buffer form is matched with `headsWithTail`
// (linear); a `[^;\n]*?` gap rescanned the statement from every head.
const DECODED_ASSIGNMENT_ATOB = /\b(?:const|let|var)\s+([$A-Z_a-z][$\w]*)\s*=\s*atob\s*\(/g;
const DECODED_ASSIGNMENT_BUFFER = /\b(?:const|let|var)\s+([$A-Z_a-z][$\w]*)\s*=\s*Buffer\.from\s*\(/g;
const FUNCTION_ATOB = /new\s+Function\s*\(\s*atob\s*\(/gi;
const FUNCTION_BUFFER = /new\s+Function\s*\(\s*Buffer\.from\s*\(/gi;
const FUNCTION_ON_NAME = /new\s+Function\s*\(\s*([$\w]+)/g;
const BASE64 = /['"]base64['"]/g;
const STATEMENT_END = "[;\\n]";
const MAX_EVIDENCE = 2;

function decodeMatches(content: string, atob: RegExp, buffer: RegExp): RegExpMatchArray[] {
  const out = [...content.matchAll(atob), ...headsWithTail(content, buffer, STATEMENT_END, BASE64)];
  return out.sort((a, b) => a.index! - b.index!);
}

/** Find decoded source that is subsequently executed by the Function constructor. */
function decodedFunctionEvidence(file: PackageFile): Evidence[] {
  const { content } = file;
  const evidence: Evidence[] = [];
  let lines: string[] | undefined;
  let lineAt: ((pos: number) => number) | undefined;
  const add = (pos: number) => {
    lines ??= content.split(/\r?\n/);
    lineAt ??= lineLocator(content);
    const line = lineAt(pos);
    if (evidence.some((e) => e.line === line)) return;
    evidence.push({ file: file.path, line, snippet: truncate((lines[line - 1] ?? "").trim(), 160) });
  };

  for (const m of decodeMatches(content, FUNCTION_ATOB, FUNCTION_BUFFER)) {
    if (evidence.length >= MAX_EVIDENCE) return evidence;
    add(m.index!);
  }
  if (evidence.length >= MAX_EVIDENCE) return evidence;

  // One pass over the collected names, not one full-file scan per assignment.
  const names = new Set(decodeMatches(content, DECODED_ASSIGNMENT_ATOB, DECODED_ASSIGNMENT_BUFFER).map((m) => m[1]!));
  if (names.size === 0) return evidence;
  for (const m of content.matchAll(FUNCTION_ON_NAME)) {
    if (evidence.length >= MAX_EVIDENCE) break;
    if (names.has(m[1]!)) add(m.index!);
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
