import { existsSync, readFileSync, writeFileSync } from "node:fs";

export interface ViolationInput {
  name: string;
  version: string;
  integrity: string;
  kind: "filesystem" | "network" | "process";
  target: string | null;
  confidence: "confirmed" | "suspected";
  deniedResource: string | null;
  evidence: { exitCode: number; stderrExcerpt: string };
}

export interface ViolationRecord extends ViolationInput {
  quarantined: boolean;
  reportedAt: string; // ISO-8601
}

/** Runtime-violation telemetry, integrity-keyed. Confirmed violations quarantine the build. */
export class ViolationStore {
  private byIntegrity = new Map<string, ViolationRecord>();
  private order: string[] = [];

  constructor(private readonly file?: string) {
    if (file && existsSync(file)) {
      try {
        for (const r of JSON.parse(readFileSync(file, "utf8")) as ViolationRecord[]) this.index(r);
      } catch {
        /* start empty on a corrupt log */
      }
    }
  }

  record(v: ViolationInput, now = new Date().toISOString()): ViolationRecord {
    const existing = this.byIntegrity.get(v.integrity);
    if (existing && existing.kind === v.kind && existing.target === v.target) return existing;
    const rec: ViolationRecord = { ...v, quarantined: v.confidence === "confirmed", reportedAt: now };
    this.index(rec);
    this.persist();
    return rec;
  }

  get(integrity: string | null | undefined): ViolationRecord | undefined {
    return integrity ? this.byIntegrity.get(integrity) : undefined;
  }

  isQuarantined(integrity: string | null | undefined): boolean {
    return Boolean(integrity && this.byIntegrity.get(integrity)?.quarantined);
  }

  clear(integrity: string): boolean {
    const had = this.byIntegrity.delete(integrity);
    if (had) {
      this.order = this.order.filter((k) => k !== integrity);
      this.persist();
    }
    return had;
  }

  recent(limit = 50): ViolationRecord[] {
    return this.order.slice(-limit).reverse()
      .map((k) => this.byIntegrity.get(k))
      .filter((x): x is ViolationRecord => Boolean(x));
  }

  private index(r: ViolationRecord): void {
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
