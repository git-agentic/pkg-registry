import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { Capability } from "@sentinel/core";
import { cmpSemver } from "./upstream.js";

export type ApprovalDecision = "approved" | "denied";

export interface Approval {
  name: string;
  version: string;
  integrity: string;
  decision: ApprovalDecision;
  /** Server-recorded snapshot of the audited capabilities at decision time. */
  approvedCapabilities: Capability[];
  actor: { type: "human" | "agent"; id: string };
  reason?: string;
  decidedAt: string; // ISO-8601
}

/**
 * Mutable approval state, keyed by the immutable integrity hash. Mirrors
 * AuditStore (in-memory + optional JSON-file). Never part of the audit report.
 */
export class ApprovalStore {
  private byIntegrity = new Map<string, Approval>();
  private order: string[] = [];

  constructor(private readonly file?: string) {
    if (file && existsSync(file)) {
      try {
        const rows = JSON.parse(readFileSync(file, "utf8")) as Approval[];
        for (const a of rows) this.index(a);
      } catch {
        /* start empty on a corrupt log */
      }
    }
  }

  get(integrity: string | null | undefined): Approval | undefined {
    return integrity ? this.byIntegrity.get(integrity) : undefined;
  }

  put(approval: Approval): Approval {
    this.index(approval);
    this.persist();
    return approval;
  }

  remove(integrity: string): boolean {
    const had = this.byIntegrity.delete(integrity);
    if (had) {
      this.order = this.order.filter((k) => k !== integrity);
      this.persist();
    }
    return had;
  }

  /** Highest-semver approval with decision 'approved' for a package name. */
  latestApprovedFor(name: string): Approval | undefined {
    let best: Approval | undefined;
    for (const a of this.byIntegrity.values()) {
      if (a.name !== name || a.decision !== "approved") continue;
      if (!best || cmpSemver(a.version, best.version) > 0) best = a;
    }
    return best;
  }

  recent(limit = 50): Approval[] {
    return this.order
      .slice(-limit)
      .reverse()
      .map((k) => this.byIntegrity.get(k))
      .filter((x): x is Approval => Boolean(x));
  }

  private index(a: Approval): void {
    if (!this.byIntegrity.has(a.integrity)) this.order.push(a.integrity);
    this.byIntegrity.set(a.integrity, a);
  }

  private persist(): void {
    if (!this.file) return;
    try {
      writeFileSync(this.file, JSON.stringify([...this.byIntegrity.values()], null, 2));
    } catch {
      /* best-effort */
    }
  }
}
