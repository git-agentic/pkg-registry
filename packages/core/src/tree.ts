import type { ProvenanceStatus, Verdict } from "./types.js";

export type TreeStatus = Verdict | "error";

/** One package's line in a whole-tree audit. Compact by design — a gate summary
 *  needs the verdict, not the full report. */
export interface TreePackageRow {
  name: string;
  version: string;
  status: TreeStatus;
  score: number | null;
  topFinding: string | null;
  /** ruleId of the top finding, for remediation lookup (Phase 18); null on error/no-finding rows. */
  topFindingRuleId: string | null;
  error: string | null;
  /** Verified provenance-attestation status; null on error rows (no report was produced). */
  provenance: ProvenanceStatus | null;
  /** True when a caller-claimed integrity (e.g. from a lockfile) differs from the
   *  registry-served hash. Only set when both sides are present and disagree. */
  integrityMismatch: boolean;
  /** Count of `known-vulnerability` findings on this row (Phase 22). Optional — only the
   *  audit-tree route sets it; omitted on the ~24 other construction sites (counts as 0). */
  vulnerabilities?: number;
}

export interface TreeAggregate {
  verdict: Verdict;
  gated: boolean;
  counts: { allow: number; warn: number; block: number; error: number };
  provenance: { verified: number; invalid: number; absent: number; unknown: number };
  integrityMismatch: number;
  /** Sum of every row's `vulnerabilities` (Phase 22). */
  vulnerabilities: number;
}

export interface TreeAuditResult {
  aggregate: TreeAggregate;
  packages: TreePackageRow[];
  /** Hash of the policy the tree was scored under (Phase 19 attestation); set by the proxy route. */
  policyHash?: string;
  /** Verified claim-corpus identity used for source partitioning (Phase 31). */
  claimCorpus?: { version: string; hash: string };
}

const VERDICT_RANK: Record<Verdict, number> = { allow: 0, warn: 1, block: 2 };
const RANK_VERDICT: Verdict[] = ["allow", "warn", "block"];

/**
 * Roll per-package rows into one verdict. Worst-case-wins over non-error rows,
 * order-independent (invariant #1). `error` rows are counted but never set the
 * aggregate verdict or trip the gate (invariant #6) unless `opts.failOnError` is
 * set, in which case any error row also gates the tree (default off — fail-open,
 * ADR-0020). `gated` is true when the worst verdict is at or above the policy's
 * {@link Verdict} `treeGate`.
 */
export function aggregateTree(
  rows: TreePackageRow[],
  treeGate: Verdict,
  opts: { failOnError?: boolean } = {},
): TreeAggregate {
  const counts = { allow: 0, warn: 0, block: 0, error: 0 };
  const provenance = { verified: 0, invalid: 0, absent: 0, unknown: 0 };
  let worst = 0; // defaults to "allow" when there are no non-error rows
  let integrityMismatch = 0;
  let vulnerabilities = 0;
  for (const r of rows) {
    counts[r.status]++;
    if (r.status !== "error") worst = Math.max(worst, VERDICT_RANK[r.status]);
    if (r.provenance) provenance[r.provenance]++;
    if (r.integrityMismatch) integrityMismatch++;
    vulnerabilities += r.vulnerabilities ?? 0;
  }
  const verdict = RANK_VERDICT[worst]!;
  const gated = worst >= VERDICT_RANK[treeGate] || (Boolean(opts.failOnError) && counts.error > 0);
  return { verdict, gated, counts, provenance, integrityMismatch, vulnerabilities };
}
