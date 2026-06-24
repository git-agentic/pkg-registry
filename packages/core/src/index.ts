/** @sentinel/core — deterministic npm package audit engine. */

export * from "./types.js";
export { POLICY, scoreFindings, verdictFor, severityRank } from "./score.js";
export {
  ENGINE_VERSION,
  auditTarball,
  buildReport,
  runRules,
  type AuditTarballInput,
} from "./audit.js";
export {
  extractTarball,
  baselineFrom,
  integrityOf,
  type ExtractResult,
} from "./extract.js";
export { RULES } from "./rules/index.js";
export {
  NoopLlmAdapter,
  AnthropicLlmAdapter,
  type LlmAuditAdapter,
  type LlmEnrichInput,
  type LlmEnrichOutput,
} from "./llm/adapter.js";
