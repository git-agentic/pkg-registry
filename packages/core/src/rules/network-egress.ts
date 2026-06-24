import type { AuditInput, Evidence, Finding, Rule } from "../types.js";
import { codeFiles, mkFinding, scanLines } from "./util.js";

const PATTERNS = [
  { re: /require\(['"](https?|net|dgram|dns|tls)['"]\)|from\s+['"](node:)?(https?|net|dgram|dns|tls)['"]/, sev: "medium" as const, why: "imports a raw networking module" },
  { re: /\b(fetch|axios)\s*\(/, sev: "low" as const, why: "makes an HTTP request" },
  { re: /\bnew\s+WebSocket\b|navigator\.sendBeacon/, sev: "medium" as const, why: "opens a websocket / beacon" },
  { re: /https?:\/\/\d{1,3}(\.\d{1,3}){3}/, sev: "high" as const, why: "connects to a hardcoded IP address" },
  { re: /https?:\/\/[\w.-]+\.(ru|tk|top|xyz|cc|gq|ml|ga)\b/i, sev: "medium" as const, why: "connects to a suspicious TLD" },
  { re: /\b(curl|wget)\b/, sev: "high" as const, why: "shells out to curl/wget" },
];

/** Detects code that can move data off the machine. */
export const networkEgressRule: Rule = {
  id: "network-egress",
  category: "network",
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
            message: `Network egress: ${p.why}.`,
            evidence: ev,
            files: input.files,
          }),
        );
      }
    }
    return findings;
  },
};
