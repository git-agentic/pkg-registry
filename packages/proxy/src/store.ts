import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { AuditReport } from "@sentinel/core";

export interface StoredAudit {
  key: string; // `${name}@${version}`
  name: string;
  version: string;
  report: AuditReport;
}

/**
 * Verdict cache + audit log. Keyed by `(name, version, integrity)` — a published
 * tarball is immutable, so a cached audit is always valid. The in-memory map is
 * the verdict cache (sub-ms hits); the optional JSON file persists the log so the
 * dashboard survives a restart. Maps 1:1 onto a future Postgres `audits` table.
 */
export class AuditStore {
  private byIntegrity = new Map<string, StoredAudit>();
  private order: string[] = []; // integrity keys, most-recent last

  constructor(private readonly file?: string) {
    if (file && existsSync(file)) {
      try {
        const rows = JSON.parse(readFileSync(file, "utf8")) as StoredAudit[];
        for (const r of rows) {
          if (r.report?.schema !== 2) continue; // re-audit anything older
          this.index(r.report.meta.integrity ?? r.key, r);
        }
      } catch {
        /* start empty on a corrupt log */
      }
    }
  }

  /** Cache lookup by immutable integrity hash. */
  get(integrity: string | null | undefined): StoredAudit | undefined {
    return integrity ? this.byIntegrity.get(integrity) : undefined;
  }

  put(report: AuditReport): StoredAudit {
    const stored: StoredAudit = {
      key: `${report.meta.name}@${report.meta.version}`,
      name: report.meta.name,
      version: report.meta.version,
      report,
    };
    this.index(report.meta.integrity ?? stored.key, stored);
    this.persist();
    return stored;
  }

  /** Most-recent audits first. */
  recent(limit = 50): StoredAudit[] {
    return this.order
      .slice(-limit)
      .reverse()
      .map((k) => this.byIntegrity.get(k))
      .filter((x): x is StoredAudit => Boolean(x));
  }

  stats(): { total: number; allow: number; warn: number; block: number } {
    let allow = 0,
      warn = 0,
      block = 0;
    for (const s of this.byIntegrity.values()) {
      if (s.report.verdict === "allow") allow++;
      else if (s.report.verdict === "warn") warn++;
      else block++;
    }
    return { total: this.byIntegrity.size, allow, warn, block };
  }

  private index(key: string, stored: StoredAudit): void {
    if (!this.byIntegrity.has(key)) this.order.push(key);
    this.byIntegrity.set(key, stored);
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
