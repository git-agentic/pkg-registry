import type { AuditInput, Finding, Rule } from "../types.js";
import { codeFiles, mkFinding, scanLines } from "./util.js";

/** Reads of sensitive material. */
const SECRET_READS = [
  { re: /process\.env\s*\[/, what: "dynamic environment-variable enumeration" },
  { re: /\b(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN)\b/, what: "AWS credentials" },
  { re: /\b(NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN)\b/, what: "CI/registry tokens" },
  { re: /\.npmrc|_authToken/, what: "npm auth token (~/.npmrc)" },
  { re: /\.aws\/credentials|\.aws\\credentials/, what: "AWS credentials file" },
  { re: /\.ssh\/id_|id_rsa|id_ed25519/, what: "SSH private keys" },
  { re: /\/etc\/passwd|\/etc\/shadow/, what: "system account files" },
  { re: /process\.env\.(\w*?(SECRET|TOKEN|KEY|PASS|CREDENTIAL)\w*)/i, what: "secret-named env var" },
];

/** Network sinks that could carry stolen data out. */
const EGRESS_SINK =
  /\b(fetch|axios|https?\.request|https?\.get|net\.connect|dgram|WebSocket|XMLHttpRequest|navigator\.sendBeacon)\b|require\(['"](https?|net|dgram|dns)['"]\)/;

/**
 * Correlates reading sensitive material with a network egress sink in the same
 * file. Read-without-send is `low`; read correlated with send is `critical`
 * (this is the event-stream / ua-parser-js exfil signature).
 */
export const secretExfilRule: Rule = {
  id: "secret-exfil",
  category: "secret-exfil",
  run(input: AuditInput): Finding[] {
    const findings: Finding[] = [];

    for (const file of codeFiles(input)) {
      const reads = SECRET_READS.flatMap((s) =>
        scanLines(file, s.re, 2).map((ev) => ({ what: s.what, ev })),
      );
      if (reads.length === 0) continue;

      const hasEgress = EGRESS_SINK.test(file.content);
      const what = [...new Set(reads.map((r) => r.what))].join(", ");

      if (hasEgress) {
        const sinkEv = scanLines(file, EGRESS_SINK, 1);
        findings.push(
          mkFinding({
            ruleId: this.id,
            category: this.category,
            severity: "critical",
            message: `Reads sensitive material (${what}) and contains a network egress sink in the same file — possible secret exfiltration.`,
            evidence: [...reads.map((r) => r.ev), ...sinkEv],
            files: input.files,
          }),
        );
      } else {
        findings.push(
          mkFinding({
            ruleId: this.id,
            category: this.category,
            severity: "low",
            message: `Accesses sensitive material (${what}). No egress sink detected in the same file.`,
            evidence: reads.map((r) => r.ev),
            files: input.files,
          }),
        );
      }
    }

    return findings;
  },
};
