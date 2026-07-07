import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { Capability } from "@sentinel/core";

export interface ApprovalRequest {
  name: string;
  version: string;
  integrity: string;
  reason: string;
  requestedBy: { type: "human" | "agent"; id: string };
  capabilities: Capability[];
  requestedAt: string; // ISO-8601
}

/** Pending approval requests (an agent asks; a human grants). Integrity-keyed;
 *  mirrors ApprovalStore/ViolationStore (in-memory + optional JSON file). */
export class ApprovalRequestStore {
  private byIntegrity = new Map<string, ApprovalRequest>();
  private order: string[] = [];

  constructor(private readonly file?: string) {
    if (file && existsSync(file)) {
      try {
        for (const r of JSON.parse(readFileSync(file, "utf8")) as ApprovalRequest[]) this.index(r);
      } catch {
        /* start empty on a corrupt log */
      }
    }
  }

  record(r: Omit<ApprovalRequest, "requestedAt">, now = new Date().toISOString()): ApprovalRequest {
    const rec: ApprovalRequest = { ...r, requestedAt: now };
    this.index(rec);
    this.persist();
    return rec;
  }

  get(integrity: string | null | undefined): ApprovalRequest | undefined {
    return integrity ? this.byIntegrity.get(integrity) : undefined;
  }

  clear(integrity: string): boolean {
    const had = this.byIntegrity.delete(integrity);
    if (had) {
      this.order = this.order.filter((k) => k !== integrity);
      this.persist();
    }
    return had;
  }

  recent(limit = 50): ApprovalRequest[] {
    return this.order.slice(-limit).reverse()
      .map((k) => this.byIntegrity.get(k))
      .filter((x): x is ApprovalRequest => Boolean(x));
  }

  private index(r: ApprovalRequest): void {
    if (!this.byIntegrity.has(r.integrity)) this.order.push(r.integrity);
    this.byIntegrity.set(r.integrity, r);
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
