/** @sentinel/core — deterministic npm package audit engine. */

export * from "./types.js";
export { score, severityRank } from "./score.js";
export { lintPolicy, type LintFinding } from "./policy-lint.js";
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
  integrityOfAlgo,
  type SriAlgorithm,
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
export {
  verifyRegistrySignature,
  NPM_SIGNING_KEYS,
  type SignatureVerdict,
  type RegistrySignature,
  type NpmSigningKey,
} from "./signature.js";
export {
  verifyProvenance,
  loadDefaultTrustMaterial,
  loadTrustMaterial,
  type ProvenanceTrustMaterial,
  type ProvenanceVerification,
  type NpmAttestationKey,
} from "./provenance.js";
export { parseLockfile, parseYarnLock, parsePnpmLock, parseAnyLockfile, type Coordinate } from "./lockfile.js";
export { signToken, verifyToken, type Role, type TokenPayload } from "./auth.js";
export { toCycloneDX, type CycloneDXBom, type CycloneDXComponent } from "./sbom.js";
export { remediate, remediationHint, type Remediation, type RemediationItem, type WaiverTemplate } from "./remediation.js";
export {
  buildAuditStatement, signAttestation, verifyAttestation, attestationKeyid, pae, SENTINEL_PREDICATE_TYPE,
  type InTotoStatementV1, type AuditPredicate, type DsseEnvelope, type VerifyResult, type VerifyReason,
} from "./attest.js";
