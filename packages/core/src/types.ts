/**
 * Sentinel audit data model.
 *
 * The {@link AuditReport} schema maps 1:1 onto a future
 * `audits(package, version, integrity PK, report JSONB)` table — `integrity`
 * (the tarball's SRI hash) is the natural immutable primary key.
 */

export type Verdict = "allow" | "warn" | "block";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Category =
  | "obfuscation"
  | "network"
  | "secret-exfil"
  | "install-script"
  | "metadata";

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
  /** Points deducted from the score (after the diff multiplier). */
  weight: number;
  evidence: Evidence[];
}

export interface PackageMeta {
  name: string;
  version: string;
  author: string | null;
  maintainers: string[];
  license: string | null;
  hasInstallScripts: boolean;
  /** npm registry signature / provenance status. */
  signatureStatus: "signed" | "unsigned" | "unknown";
  /** Subresource Integrity string from the registry `dist` block. */
  integrity: string | null;
  unpackedSize: number;
  fileCount: number;
}

export interface AuditReport {
  schema: 1;
  meta: PackageMeta;
  /** 0–100, where 100 is "no detected risk". */
  score: number;
  verdict: Verdict;
  findings: Finding[];
  engine: {
    version: string;
    rules: string[];
    llm: string | null;
    mode: "full" | "diff";
  };
  /** Human-readable summary from the LLM adapter, if one ran. */
  llmSummary: string | null;
  auditedAt: string;
  durationMs: number;
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
