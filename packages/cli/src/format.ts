import type { AuditReport, Capability, CapabilityKind, Severity, Verdict, TreeAuditResult } from "@sentinel/core";

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
