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
  error: string | null;
  /** Verified provenance-attestation status; null on error rows (no report was produced). */
  provenance: ProvenanceStatus | null;
}

export interface TreeAggregate {
  verdict: Verdict;
  gated: boolean;
  counts: { allow: number; warn: number; block: number; error: number };
  provenance: { verified: number; invalid: number; absent: number; unknown: number };
}

export interface TreeAuditResult {
  aggregate: TreeAggregate;
  packages: TreePackageRow[];
}

const VERDICT_RANK: Record<Verdict, number> = { allow: 0, warn: 1, block: 2 };
const RANK_VERDICT: Verdict[] = ["allow", "warn", "block"];

/**
 * Roll per-package rows into one verdict. Worst-case-wins over non-error rows,
 * order-independent (invariant #1). `error` rows are counted but never set the
 * aggregate verdict or trip the gate (invariant #6). `gated` is true when the
 * worst verdict is at or above the policy's {@link Verdict} `treeGate`.
 */
export function aggregateTree(rows: TreePackageRow[], treeGate: Verdict): TreeAggregate {
  const counts = { allow: 0, warn: 0, block: 0, error: 0 };
  const provenance = { verified: 0, invalid: 0, absent: 0, unknown: 0 };
  let worst = 0; // defaults to "allow" when there are no non-error rows
  for (const r of rows) {
    counts[r.status]++;
    if (r.status !== "error") worst = Math.max(worst, VERDICT_RANK[r.status]);
    if (r.provenance) provenance[r.provenance]++;
  }
  const verdict = RANK_VERDICT[worst]!;
  const gated = worst >= VERDICT_RANK[treeGate];
  return { verdict, gated, counts, provenance };
}
