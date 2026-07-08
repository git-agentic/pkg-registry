import type { AuditReport, Capability, CapabilityKind, Remediation, Severity, Verdict, TreeAuditResult } from "@sentinel/core";

const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  blue: "\x1b[34m", gray: "\x1b[90m", white: "\x1b[97m",
};

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, s: string) => (useColor ? code + s + C.reset : s);

const verdictColor: Record<Verdict, string> = {
  allow: C.green,
  warn: C.yellow,
  block: C.red,
};
const sevColor: Record<Severity, string> = {
  info: C.gray, low: C.gray, medium: C.yellow, high: C.red, critical: C.red,
};

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

function bar(score: number): string {
  const filled = Math.round(score / 10);
  const col = score >= 80 ? C.green : score >= 50 ? C.yellow : C.red;
  return c(col, "█".repeat(filled)) + c(C.gray, "░".repeat(10 - filled));
}

/** Pre-install verdict panel. */
export function formatReport(r: AuditReport): string {
  const m = r.meta;
  const L: string[] = [];
  L.push("");
  L.push(c(C.bold, `  ${m.name}@${m.version}`));
  L.push(c(C.gray, `  ${"─".repeat(56)}`));
  L.push(`  size       ${bytes(m.unpackedSize)} ${c(C.gray, `(${m.fileCount} files)`)}`);
  L.push(`  author     ${m.author ?? c(C.gray, "unknown")}`);
  const sig = m.signature === "verified" ? c(C.green, "verified")
    : m.signature === "invalid" ? c(C.red, "invalid")
    : m.signature === "unsigned" ? c(C.yellow, "unsigned") : c(C.gray, "unknown");
  L.push(`  signature  ${sig}`);
  const prov = m.provenance === "verified" ? c(C.green, "verified")
    : m.provenance === "invalid" ? c(C.red, "invalid")
    : m.provenance === "unknown" ? c(C.yellow, "unknown") : c(C.gray, "absent");
  L.push(`  provenance ${prov}`);
  const pid = m.provenanceIdentity;
  if (m.provenance === "verified" && pid) {
    const commit = pid.commit ? ` (commit ${pid.commit.slice(0, 7)})` : "";
    L.push(`             ${c(C.gray, `built by ${pid.builder ?? "unknown builder"} from ${pid.sourceRepository ?? "?"}${pid.ref ? `@${pid.ref}` : ""}${commit}`)}`);
  }
  L.push(`  install    ${m.hasInstallScripts ? c(C.yellow, "⚠ runs lifecycle scripts") : "no install scripts"}`);
  L.push(`  audit      ${r.engine.mode}-mode · ${r.engine.rules.length} rules · engine ${r.engine.version}`);
  L.push("");
  L.push(`  score      ${bar(r.score)} ${c(C.bold, String(r.score))}${c(C.gray, "/100")}`);
  L.push(`  verdict    ${c(C.bold + verdictColor[r.verdict], r.verdict.toUpperCase())}`);

  if (r.findings.length) {
    L.push("");
    L.push(c(C.bold, `  findings (${r.findings.length})`));
    for (const f of r.findings) {
      L.push(`  ${c(sevColor[f.severity], f.severity.padEnd(8))} ${c(C.gray, `[${f.ruleId}]`)} ${f.message}`);
      const ev = f.evidence[0];
      if (ev) L.push(`           ${c(C.gray, `${ev.file}${ev.line ? `:${ev.line}` : ""}  ${ev.snippet}`)}`);
    }
  }
  if (r.llmSummary) {
    L.push("");
    L.push(c(C.bold, "  llm summary"));
    L.push(`  ${c(C.gray, r.llmSummary)}`);
  }
  L.push("");
  return L.join("\n");
}

export function verdictExitCode(v: Verdict): number {
  return v === "block" ? 2 : v === "warn" ? 1 : 0;
}

export interface Manifest {
  meta: { name: string; version: string; integrity: string };
  verdict: string;
  approvalState: string;
  capabilities: Capability[];
  approvalRequired: Capability[];
  inheritedFrom: string | null;
}

const stateColor: Record<string, string> = {
  approved: C.green, inherited: C.green, required: C.yellow, denied: C.red, "n-a": C.gray,
};

export function formatManifest(m: Manifest): string {
  const L: string[] = [];
  L.push("");
  L.push(c(C.bold, `  ${m.meta.name}@${m.meta.version}`));
  L.push(c(C.gray, `  ${"─".repeat(56)}`));
  L.push(`  verdict    ${c(C.bold + (verdictColor[m.verdict as Verdict] ?? C.gray), m.verdict.toUpperCase())}`);
  L.push(`  approval   ${c(C.bold + (stateColor[m.approvalState] ?? C.gray), m.approvalState.toUpperCase())}` +
    (m.inheritedFrom ? c(C.gray, ` (inherited from ${m.inheritedFrom})`) : ""));
  const byKind = new Map<CapabilityKind, string[]>();
  for (const cap of m.capabilities) {
    const list = byKind.get(cap.kind) ?? [];
    list.push(cap.target);
    byKind.set(cap.kind, list);
  }
  L.push("");
  L.push(c(C.bold, `  capabilities (${m.capabilities.length})`));
  if (m.capabilities.length === 0) L.push(c(C.gray, "  none"));
  for (const [kind, targets] of byKind) {
    L.push(`  ${kind.padEnd(11)}${c(C.gray, [...new Set(targets)].join(", "))}`);
  }
  if (m.approvalRequired.length) {
    L.push("");
    L.push(c(C.yellow, `  requires approval (${m.approvalRequired.length} new):`));
    for (const cap of m.approvalRequired) L.push(`  ${c(C.yellow, "›")} ${cap.kind}: ${cap.target}`);
  }
  L.push("");
  return L.join("\n");
}

const treeStatusColor: Record<string, string> = {
  allow: C.green, warn: C.yellow, block: C.red, error: C.gray,
};

/** Whole-tree audit summary: one line per package, then counts + aggregate verdict. */
export function formatTree(r: TreeAuditResult): string {
  const L: string[] = [];
  L.push("");
  L.push(c(C.bold, `  dependency tree audit (${r.packages.length} packages)`));
  L.push(c(C.gray, `  ${"─".repeat(56)}`));
  for (const p of r.packages) {
    const label = p.status.toUpperCase().padEnd(6);
    const score = p.score === null ? "" : c(C.gray, ` ${p.score}/100`);
    L.push(`  ${c(treeStatusColor[p.status] ?? C.gray, label)} ${p.name}@${p.version}${score}`);
    const note = p.error ?? p.topFinding;
    if (note) L.push(`         ${c(C.gray, note)}`);
  }
  const a = r.aggregate;
  L.push("");
  L.push(`  ${a.counts.allow} allow · ${a.counts.warn} warn · ${a.counts.block} block · ${a.counts.error} error`);
  const pv = a.provenance;
  L.push(c(C.gray, `  provenance: ${pv.verified} verified · ${pv.invalid} invalid · ${pv.absent} absent · ${pv.unknown} unknown`));
  L.push(
    `  verdict    ${c(C.bold + (verdictColor[a.verdict] ?? C.gray), a.verdict.toUpperCase())}` +
      (a.gated ? c(C.red, "  ✗ GATED") : c(C.green, "  ✓ ok")),
  );
  L.push("");
  return L.join("\n");
}

/** CI contract: non-zero when the tree is gated. */
export function treeExitCode(r: TreeAuditResult): number {
  return r.aggregate.gated ? 2 : 0;
}

export interface ViolationRow {
  name: string; version: string; kind: string; target: string | null;
  confidence: string; quarantined: boolean; evidence: { exitCode: number; stderrExcerpt: string };
}

/** Runtime violation list surfaced from the proxy's `/-/violations` feed. */
export function formatViolations(rows: ViolationRow[]): string {
  const L: string[] = ["", c(C.bold, `  runtime violations (${rows.length})`), c(C.gray, `  ${"─".repeat(56)}`)];
  if (rows.length === 0) L.push(c(C.gray, "  none recorded"));
  for (const v of rows) {
    const tag = v.quarantined ? c(C.red, "QUARANTINED") : c(C.yellow, v.confidence.toUpperCase());
    L.push(`  ${tag} ${v.name}@${v.version} ${c(C.gray, `${v.kind} → ${v.target ?? "?"}`)}`);
  }
  L.push("");
  return L.join("\n");
}

export interface StatsSummary {
  summary: { total: number; verdict: { allow: number; warn: number; block: number }; violations: number; quarantined: number };
  trends: { date: string; allow: number; warn: number; block: number }[];
  topFlagged: { name: string; warn: number; block: number }[];
}

/** Durable observability rollup surfaced from the proxy's `/-/metrics` feed. */
export function formatStats(m: StatsSummary): string {
  const L: string[] = [
    "",
    c(C.bold, `  audits: ${m.summary.total}`) +
      `  ·  ${c(verdictColor.allow, `${m.summary.verdict.allow} allow`)} · ${c(verdictColor.warn, `${m.summary.verdict.warn} warn`)} · ${c(verdictColor.block, `${m.summary.verdict.block} block`)}`,
    `  violations: ${m.summary.violations}  ·  quarantined: ${m.summary.quarantined}`,
    "",
  ];
  if (m.trends.length) {
    L.push(c(C.bold, "  trend (allow/warn/block per day):"));
    for (const t of m.trends) L.push(`    ${t.date}  ${t.allow}/${t.warn}/${t.block}`);
    L.push("");
  }
  if (m.topFlagged.length) {
    L.push(c(C.bold, "  most-flagged:"));
    for (const f of m.topFlagged) L.push(`    ${f.name}  (${f.warn} warn, ${f.block} block)`);
    L.push("");
  }
  return L.join("\n");
}

export interface HistoryRow {
  name: string; version: string; verdict: string; score: number; topFinding: string | null; auditedAt: string;
}

/** Recorded-audit list surfaced from the proxy's `/-/history` feed. */
export function formatHistory(rows: HistoryRow[]): string {
  if (!rows.length) return c(C.gray, "\n  (no audits recorded)\n");
  const L: string[] = ["", c(C.bold, `  ${rows.length} audit(s):`)];
  for (const r of rows) {
    const verdict = r.verdict as Verdict;
    const tag = c(verdictColor[verdict] ?? C.white, r.verdict.toUpperCase().padEnd(6));
    L.push(`  ${tag} ${r.name}@${r.version}  ${r.score}/100  ${c(C.gray, r.auditedAt)}`);
    if (r.topFinding) L.push(c(C.gray, `         ${r.topFinding}`));
  }
  L.push("");
  return L.join("\n");
}

export interface ExplainResult {
  report: AuditReport;
  remediation: Remediation;
  lastKnownGood: { version: string; score: number } | null;
}

/** Verdict explanation + per-finding remediation, suggested known-good version, and waiver command. */
export function formatExplain(r: ExplainResult): string {
  const L: string[] = ["", `  ${r.report.meta.name}@${r.report.meta.version}  —  ${c(verdictColor[r.report.verdict] ?? C.gray, r.report.verdict.toUpperCase())}  ${r.report.score}/100`, ""];
  L.push(c(C.bold, "  " + r.remediation.guidance));
  L.push("");
  for (const it of r.remediation.items) {
    L.push(`  • ${c(C.bold, it.ruleId)} (${it.severity}) — ${it.summary}`);
    L.push(`      ${c(C.gray, it.action)}`);
  }
  if (r.remediation.items.length) L.push("");
  if (r.lastKnownGood) {
    L.push(c(C.green, `  ✓ suggested: pin to ${r.report.meta.name}@${r.lastKnownGood.version} — the most recent clean release (${r.lastKnownGood.score}/100).`));
    L.push("");
  }
  if (r.remediation.waiver) {
    L.push("  To waive after review:");
    L.push(`      ${r.remediation.waiver.approveCommand}`);
    L.push("");
  }
  return L.join("\n");
}
