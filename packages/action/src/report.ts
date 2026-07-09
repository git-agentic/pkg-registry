import type { TreeAuditResult, TreePackageRow } from "@sentinel/core";
import { remediationHint } from "@sentinel/core";

export const REPORT_MARKER = "<!-- sentinel-report -->";

const RANK: Record<string, number> = { block: 0, warn: 1, allow: 2, error: 3 };

/** Render the PR/CI Markdown report for a tree audit. Pure; deterministic given `now`.
 *  Starts with a hidden marker so the Action can find-and-update its comment idempotently. */
export function renderPrComment(result: TreeAuditResult, opts: { now: string }): string {
  const a = result.aggregate;
  const badge = a.verdict.toUpperCase();
  const offenders = result.packages
    .filter((p) => p.status === "block" || p.status === "warn" || p.status === "error")
    .sort((x, y) => (RANK[x.status]! - RANK[y.status]!) || (x.name < y.name ? -1 : 1))
    .slice(0, 15);

  const L: string[] = [];
  L.push(REPORT_MARKER);
  L.push(`## Sentinel dependency audit — **${badge}**${a.gated ? " · ✗ gated" : " · ✓ ok"}`);
  L.push("");
  L.push(`${a.counts.allow} allow · ${a.counts.warn} warn · ${a.counts.block} block · ${a.counts.error} error`);
  const pv = a.provenance;
  L.push(`_provenance: ${pv.verified} verified · ${pv.invalid} invalid · ${pv.absent} absent · ${pv.unknown} unknown_`);
  L.push("");
  if (offenders.length) {
    L.push("| package | verdict | score | finding | how to fix |");
    L.push("| --- | --- | --- | --- | --- |");
    for (const p of offenders) {
      const finding = p.error ?? p.topFinding ?? "";
      const hint = p.topFindingRuleId ? remediationHint(p.topFindingRuleId) : "";
      L.push(
        `| ${escapePipe(`${p.name}@${p.version}`)} | ${p.status} | ${scoreCell(p)} | ${escapePipe(finding)} | ${escapePipe(hint)} |`,
      );
    }
    L.push("");
    L.push("▶ Run `sentinel explain <package> <version>` for a suggested safe version and a ready waiver.");
    L.push("");
  } else {
    L.push("_No flagged packages._");
    L.push("");
  }
  L.push(`<sub>Sentinel · ${result.packages.length} packages audited · ${opts.now} · SBOM uploaded as a build artifact</sub>`);
  return L.join("\n");
}

function scoreCell(p: TreePackageRow): string {
  return p.score === null ? "—" : `${p.score}/100`;
}
function escapePipe(s: string): string {
  // Escape backslashes FIRST, else an input `\|` would become `\\|` — a literal
  // backslash followed by an unescaped pipe that breaks out of the table cell.
  return s.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\n/g, " ");
}
