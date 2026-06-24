import type { Finding, PackageFile, PackageMeta } from "../types.js";

export interface LlmEnrichInput {
  files: PackageFile[];
  findings: Finding[];
  meta: PackageMeta;
}

export interface LlmEnrichOutput {
  /** Plain-English summary shown on the dashboard / CLI. */
  summary: string;
  /** Supplementary findings. These NEVER set the score in Phase 1. */
  findings: Finding[];
}

/**
 * Pluggable LLM enrichment. Runs only in the proxy's async-enrich phase, never
 * on the inline gate. The score is produced entirely by the deterministic
 * heuristic engine; an adapter can only add human-readable context and
 * supplementary findings, so a missing key or model outage degrades gracefully.
 */
export interface LlmAuditAdapter {
  name: string;
  enrich(input: LlmEnrichInput): Promise<LlmEnrichOutput>;
}

/** Default: fully offline, deterministic. The engine works with no LLM at all. */
export class NoopLlmAdapter implements LlmAuditAdapter {
  readonly name = "noop";
  async enrich(): Promise<LlmEnrichOutput> {
    return { summary: "", findings: [] };
  }
}

/**
 * Wiring stub for a real model. Reads `ANTHROPIC_API_KEY`; when absent it falls
 * back to a deterministic local summary so behaviour stays predictable in tests
 * and offline. Left as a stub on purpose — the network call belongs in the
 * async-enrich path and is out of scope for the Phase 1 deterministic core.
 */
export class AnthropicLlmAdapter implements LlmAuditAdapter {
  readonly name = "anthropic";
  constructor(private readonly apiKey = process.env.ANTHROPIC_API_KEY) {}

  async enrich(input: LlmEnrichInput): Promise<LlmEnrichOutput> {
    if (!this.apiKey) {
      return { summary: localSummary(input), findings: [] };
    }
    // Real implementation would POST findings + redacted snippets to the
    // Messages API here and parse a structured response. Intentionally not
    // implemented in the offline Phase 1 core.
    return { summary: localSummary(input), findings: [] };
  }
}

function localSummary(input: LlmEnrichInput): string {
  if (input.findings.length === 0) {
    return `No risk patterns detected across ${input.files.length} files.`;
  }
  const top = [...input.findings].sort((a, b) => b.weight - a.weight)[0];
  const crit = input.findings.filter((f) => f.severity === "critical").length;
  return (
    `${input.findings.length} finding(s)${crit ? `, ${crit} critical` : ""}. ` +
    `Most significant: ${top?.message ?? "n/a"}`
  );
}
