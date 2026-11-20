import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { ENGINE_VERSION, type AuditReport } from "@git-agentic/sentinel-core";
import type { HistoryDb } from "./history-db.js";

export interface StoredAudit {
  key: string; // `${name}@${version}`
  name: string;
  version: string;
  report: AuditReport;
}

/** Persist coalescing window: the file is a rebuildable cache, so a short delay is safe. */
const PERSIST_DEBOUNCE_MS = 500;

/** Fixed in-memory cap: the oldest entries are evicted so a long-lived proxy cannot grow without bound. */
export const MAX_AUDIT_ENTRIES = 20_000;

/**
 * Verdict cache + audit log. Keyed by `(name, version, integrity)` — a published
 * tarball is immutable, so a cached audit is always valid. The in-memory map is
 * the verdict cache (sub-ms hits); the optional JSON file persists the log so the
 * dashboard survives a restart. Maps 1:1 onto a future Postgres `audits` table.
 */
export class AuditStore {
  private byCoordinateIntegrity = new Map<string, StoredAudit>();
  private order: string[] = []; // coordinate + integrity keys, most-recent last

  constructor(
    private readonly file?: string,
    private readonly activePolicyHash?: string,
    private readonly history?: HistoryDb,
  ) {
    if (file && existsSync(file)) {
      try {
        const rows = JSON.parse(readFileSync(file, "utf8")) as StoredAudit[];
        for (const r of rows) {
          if (r.report?.schema !== 3) continue; // re-audit anything older
          if (r.report.engine?.version !== ENGINE_VERSION) continue; // scored by another engine: re-audit after an upgrade
          if (this.activePolicyHash && r.report.policy?.hash !== this.activePolicyHash) continue; // scored under a different policy
          const integrity = r.report.meta.integrity;
          if (!integrity) continue; // actual integrity is a mandatory cache-key dimension
          this.index(this.cacheKey(r.name, r.version, integrity), r);
        }
      } catch {
        /* start empty on a corrupt log */
      }
    }
  }

  /** Cache lookup by package coordinate plus immutable integrity hash. */
  get(name: string, version: string, integrity: string | null | undefined): StoredAudit | undefined {
    return integrity ? this.byCoordinateIntegrity.get(this.cacheKey(name, version, integrity)) : undefined;
  }

  /**
   * Backward-compatible control-plane lookup for integrity-only approval payloads.
   * Shared bytes are ambiguous and therefore fail closed instead of borrowing an
   * arbitrary coordinate's report.
   */
  getUniqueByIntegrity(integrity: string | null | undefined): StoredAudit | undefined {
    if (!integrity) return undefined;
    let found: StoredAudit | undefined;
    for (const stored of this.byCoordinateIntegrity.values()) {
      if (stored.report.meta.integrity !== integrity) continue;
      if (found) return undefined;
      found = stored;
    }
    return found;
  }

  put(report: AuditReport): StoredAudit {
    if (!report.meta.integrity) {
      throw new Error("cannot cache an audit report without actual integrity");
    }
    const stored: StoredAudit = {
      key: `${report.meta.name}@${report.meta.version}`,
      name: report.meta.name,
      version: report.meta.version,
      report,
    };
    this.index(this.cacheKey(stored.name, stored.version, report.meta.integrity), stored);
    this.persist();
    try {
      this.history?.recordAudit(report, new Date().toISOString());
    } catch {
      /* observability is best-effort — never break an audit (invariant #6) */
    }
    return stored;
  }

  /** Most-recent audits first. */
  recent(limit = 50): StoredAudit[] {
    return this.order
      .slice(-limit)
      .reverse()
      .map((k) => this.byCoordinateIntegrity.get(k))
      .filter((x): x is StoredAudit => Boolean(x));
  }

  stats(): { total: number; allow: number; warn: number; block: number } {
    let allow = 0,
      warn = 0,
      block = 0;
    for (const s of this.byCoordinateIntegrity.values()) {
      if (s.report.verdict === "allow") allow++;
      else if (s.report.verdict === "warn") warn++;
      else block++;
    }
    return { total: this.byCoordinateIntegrity.size, allow, warn, block };
  }

  private index(key: string, stored: StoredAudit): void {
    if (!this.byCoordinateIntegrity.has(key)) this.order.push(key);
    this.byCoordinateIntegrity.set(key, stored);
    while (this.order.length > MAX_AUDIT_ENTRIES) this.byCoordinateIntegrity.delete(this.order.shift()!);
  }

  private cacheKey(name: string, version: string, integrity: string): string {
    return `${name}\u0000${version}\u0000${integrity}`;
  }

  private persistTimer: ReturnType<typeof setTimeout> | undefined;

  /** Coalesce writes: one unref'd timer rewrites the file once for any burst of puts. */
  private persist(): void {
    if (!this.file || this.persistTimer) return;
    this.persistTimer = setTimeout(() => this.flush(), PERSIST_DEBOUNCE_MS);
    this.persistTimer.unref();
  }

  /** Write the file now (tests, shutdown). Cancels any pending debounced write. */
  flush(): void {
    if (this.persistTimer) { clearTimeout(this.persistTimer); this.persistTimer = undefined; }
    if (!this.file) return;
    try {
      writeFileSync(this.file, JSON.stringify([...this.byCoordinateIntegrity.values()], null, 2));
    } catch {
      /* best-effort */
    }
  }
}
