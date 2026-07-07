/**
 * Sentinel audit data model.
 *
 * The {@link AuditReport} schema maps 1:1 onto a future
 * `audits(package, version, integrity PK, report JSONB)` table — `integrity`
 * (the tarball's SRI hash) is the natural immutable primary key.
 */

export type Verdict = "allow" | "warn" | "block";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Result of verifying a package's npm registry signature. */
export type SignatureVerdict = "verified" | "invalid" | "unsigned" | "unknown";

/** Result of verifying a package's provenance attestation bundles (Phase 9). */
export type ProvenanceStatus = "verified" | "invalid" | "absent" | "unknown";

/** Identity extracted from a verified SLSA provenance attestation. */
export interface ProvenanceIdentity {
  /** Signing workflow identity (Fulcio cert SAN), e.g. "https://github.com/o/r/.github/workflows/release.yml@refs/heads/main". */
  workflow: string | null;
  /** OIDC issuer, e.g. "https://token.actions.githubusercontent.com". */
  issuer: string | null;
  /** Source repository URL from the signed SLSA predicate. */
  sourceRepository: string | null;
  /** Git ref the build ran from, e.g. "refs/heads/main". */
  ref: string | null;
  /** Builder id, e.g. "https://github.com/actions/runner/github-hosted". */
  builder: string | null;
  /** Resolved source commit SHA. */
  commit: string | null;
}

export type Category =
  | "obfuscation"
  | "network"
  | "secret-exfil"
  | "install-script"
  | "metadata"
  | "provenance";

export interface Evidence {
  /** File path inside the package (npm convention: `package/<path>`). */
  file: string;
  /** 1-based line number when the match is line-anchored. */
  line?: number;
  /** A short, redaction-safe snippet showing why the rule fired. */
  snippet: string;
}

export interface Finding {
  ruleId: string;
  category: Category;
  severity: Severity;
  message: string;
  /** True if any cited evidence is in a file added/changed vs the diff baseline. */
  onChangedFile: boolean;
  evidence: Evidence[];
}

/** A finding after a policy has been applied (weight computed, waivers resolved). */
export interface ScoredFinding extends Finding {
  /** Points deducted (0 when waived). */
  weight: number;
  waived: boolean;
  waivedBy?: string;
}

export type CapabilityKind = "network" | "filesystem" | "process" | "native" | "env";

/**
 * One concrete thing a package can do. The (kind, target) pair is the "atom"
 * diffed across versions. `target` is normalized; "*" means the target is
 * dynamic/uncomputable (so it can't churn the delta).
 */
export interface Capability {
  kind: CapabilityKind;
  target: string;
  evidence: Evidence[];
}

export interface CapabilityDelta {
  /** Atoms present in this version, absent in the prior published version. */
  added: Capability[];
  /** Atoms present in the prior published version, gone now (informational). */
  removed: Capability[];
}

export interface PackageMeta {
  name: string;
  version: string;
  author: string | null;
  maintainers: string[];
  license: string | null;
  hasInstallScripts: boolean;
  /** Verified npm registry-signature status. */
  signature: SignatureVerdict;
  /** Verified provenance-attestation status (ADR-0022). */
  provenance: ProvenanceStatus;
  /** Identity from the verified SLSA attestation; null unless provenance is "verified". */
  provenanceIdentity?: ProvenanceIdentity | null;
  /**
   * Subresource Integrity string recomputed from the actual served tarball
   * bytes, not the registry's claimed `dist.integrity` (ADR-0022) — the
   * registry's claimed value feeds the integrity-mismatch check instead.
   */
  integrity: string | null;
  unpackedSize: number;
  fileCount: number;
}

/** Policy-independent audit: what is cached by integrity. */
export interface Audit {
  schema: 3;
  meta: PackageMeta;
  findings: Finding[];
  capabilities: Capability[];
  capabilityDelta: CapabilityDelta | null;
  engine: { version: string; rules: string[]; mode: "full" | "diff" };
  auditedAt: string;
  durationMs: number;
}

export interface AuditReport {
  schema: 3;
  meta: PackageMeta;
  /** 0–100, where 100 is "no detected risk". */
  score: number;
  verdict: Verdict;
  findings: ScoredFinding[];
  capabilities: Capability[];
  capabilityDelta: CapabilityDelta | null;
  engine: { version: string; rules: string[]; llm: string | null; mode: "full" | "diff" };
  /** Human-readable summary from the LLM adapter, if one ran. */
  llmSummary: string | null;
  auditedAt: string;
  durationMs: number;
  /** The policy under which this report was scored. */
  policy: { version: string; hash: string };
}

/** A single file extracted from a package tarball. */
export interface PackageFile {
  /** Path inside the tarball, e.g. `package/index.js`. */
  path: string;
  /** Raw text content (binary files are skipped before rules run). */
  content: string;
  size: number;
  /**
   * True when this file is added or changed relative to the diff baseline
   * (the previous published version). Drives the diff weight multiplier.
   */
  changed: boolean;
}

/** Input to the rule pipeline. */
export interface AuditInput {
  meta: PackageMeta;
  files: PackageFile[];
  mode: "full" | "diff";
}

/** A pure, deterministic detection rule. */
export interface Rule {
  id: string;
  category: Category;
  run(input: AuditInput): Finding[];
}
