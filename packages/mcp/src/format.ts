import type { AuditReport } from "@agentic-sentinel/core";

export function summarizeAudit(r: AuditReport, quarantined: boolean): string {
  const lines = [
    `${r.meta.name}@${r.meta.version} — verdict ${r.verdict.toUpperCase()} (score ${r.score}/100)`,
    `signature: ${r.meta.signature} · provenance: ${r.meta.provenance}${quarantined ? " · ⚠ QUARANTINED (runtime violation recorded)" : ""}`,
    `install scripts: ${r.meta.hasInstallScripts ? "yes" : "no"} · capabilities: ${r.capabilities.length}`,
  ];
  if (r.findings.length) {
    lines.push(`findings (${r.findings.length}):`);
    for (const f of r.findings.slice(0, 5)) lines.push(`  [${f.severity}] ${f.ruleId}: ${f.message}`);
  }
  return lines.join("\n");
}
