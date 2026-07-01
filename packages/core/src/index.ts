/** @sentinel/core — deterministic npm package audit engine. */

export * from "./types.js";
export { score, severityRank } from "./score.js";
export {
  DEFAULT_POLICY,
  policyHashOf,
  policyHashOfBytes,
  matchPackage,
  generateKeypair,
  signPolicy,
  verifyPolicyBytes,
  parsePolicy,
  loadPolicy,
  treeGateOf,
  type EnterprisePolicy,
} from "./policy.js";
export {
  ENGINE_VERSION,
  auditTarball,
  buildAudit,
  runAudit,
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
export { SENSITIVE_PATHS, sensitivePathsFor, type SensitivePath } from "./sensitive-paths.js";
export { extractCapabilities, diffCapabilities } from "./capabilities.js";
export { capabilityAtom, scanForCapabilities, normalizeTarget } from "./detect/patterns.js";
export {
  NoopLlmAdapter,
  AnthropicLlmAdapter,
  type LlmAuditAdapter,
  type LlmEnrichInput,
  type LlmEnrichOutput,
} from "./llm/adapter.js";
export {
  aggregateTree,
  type TreeStatus,
  type TreePackageRow,
  type TreeAggregate,
  type TreeAuditResult,
} from "./tree.js";
