import { capabilityAtom, type Capability } from "@agentic-sentinel/core";
import type { Approval } from "./approvals.js";

export type ApprovalState = "approved" | "inherited" | "required" | "denied" | "n-a";

export interface Reconciliation {
  state: ApprovalState;
  /** Atoms not covered by an explicit or inherited approval — what must be approved. */
  approvalRequired: Capability[];
  /** Version whose approval covers this one (inherited state), else null. */
  inheritedFrom: string | null;
}

/**
 * Pure gate decision. `explicit` is the approval recorded for THIS integrity;
 * `priorApproved` is the latest approved record for a prior version (its atoms
 * are inherited). First sight of any capability requires approval; thereafter
 * only a NEW atom re-triggers.
 */
export function reconcileApproval(input: {
  capabilities: Capability[];
  explicit?: Approval;
  priorApproved?: Approval;
}): Reconciliation {
  const { capabilities, explicit, priorApproved } = input;
  if (capabilities.length === 0) return { state: "n-a", approvalRequired: [], inheritedFrom: null };
  if (explicit?.decision === "approved") return { state: "approved", approvalRequired: [], inheritedFrom: null };
  if (explicit?.decision === "denied") return { state: "denied", approvalRequired: [], inheritedFrom: null };

  const inherited = new Set((priorApproved?.approvedCapabilities ?? []).map(capabilityAtom));
  const approvalRequired = capabilities.filter((c) => !inherited.has(capabilityAtom(c)));
  if (approvalRequired.length === 0 && priorApproved) {
    return { state: "inherited", approvalRequired: [], inheritedFrom: priorApproved.version };
  }
  return { state: "required", approvalRequired, inheritedFrom: null };
}
