import type { AuditReport, Severity, Verdict } from "@sentinel/core";

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
  const sig = m.signatureStatus === "signed" ? c(C.green, "signed")
    : m.signatureStatus === "unsigned" ? c(C.yellow, "unsigned") : c(C.gray, "unknown");
  L.push(`  signature  ${sig}`);
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
