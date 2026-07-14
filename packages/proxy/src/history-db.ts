import { createRequire } from "node:module";
import { createHash, randomUUID } from "node:crypto";
import type { AuditReport } from "@git-agentic/sentinel-core";
import type { ViolationRecord } from "./violations.js";

export interface HistorySummary {
  total: number;
  verdict: { allow: number; warn: number; block: number };
  signature: { verified: number; invalid: number; unsigned: number; unknown: number };
  provenance: { verified: number; invalid: number; absent: number; unknown: number };
  violations: number;
  quarantined: number;
  retractionWindowHits: number;
}

export interface HistoryRow { name: string; version: string; verdict: string; score: number; topFinding: string | null; auditedAt: string; }
export interface TrendBucket { date: string; allow: number; warn: number; block: number; }
export interface TopFlagged { name: string; warn: number; block: number; }
export interface ViolationTimelineRow { name: string | null; version: string | null; status: string; quarantined: boolean; detail: string | null; recordedAt: string; }
export interface RetractionWindowHitRow {
  name: string;
  version: string;
  ageHours: number;
  downloads: number;
  maxAgeHours: number;
  maxDownloads: number;
  ageExceeded: boolean;
  downloadsExceeded: boolean;
  attemptedAt: string;
}

// Minimal shape of the node:sqlite surface we use (the module is loaded lazily).
interface Stmt { run(...p: unknown[]): unknown; all(...p: unknown[]): Record<string, unknown>[]; }
interface Db { exec(sql: string): void; prepare(sql: string): Stmt; close(): void; }

const SCHEMA = `
CREATE TABLE IF NOT EXISTS audit_events (
  integrity   TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  version     TEXT NOT NULL,
  verdict     TEXT NOT NULL,
  score       INTEGER NOT NULL,
  top_finding TEXT,
  signature   TEXT,
  provenance  TEXT,
  report_json TEXT NOT NULL,
  audited_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_events(audited_at);
CREATE INDEX IF NOT EXISTS idx_audit_verdict ON audit_events(verdict);
CREATE TABLE IF NOT EXISTS violation_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  integrity   TEXT NOT NULL,
  name        TEXT, version TEXT,
  status      TEXT NOT NULL,
  quarantined INTEGER NOT NULL,
  detail      TEXT,
  recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_viol_at ON violation_events(recorded_at);
CREATE TABLE IF NOT EXISTS download_events (
  dedupe_key TEXT PRIMARY KEY,
  integrity  TEXT NOT NULL,
  name       TEXT NOT NULL,
  version    TEXT NOT NULL,
  served_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_download_coordinate ON download_events(name, version);
CREATE TABLE IF NOT EXISTS retraction_window_hits (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  name               TEXT NOT NULL,
  version            TEXT NOT NULL,
  age_hours           REAL NOT NULL,
  downloads           INTEGER NOT NULL,
  max_age_hours       INTEGER NOT NULL,
  max_downloads       INTEGER NOT NULL,
  age_exceeded        INTEGER NOT NULL,
  downloads_exceeded  INTEGER NOT NULL,
  attempted_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_retraction_hit_at ON retraction_window_hits(attempted_at);
`;

/**
 * Durable, queryable observability store (audits + runtime violations) over the
 * built-in `node:sqlite`. Opt-in: only constructed when a DB path is configured.
 * `node:sqlite` is loaded lazily (createRequire, inside the constructor) so importing
 * this module never fires its experimental-warning — only constructing a HistoryDb does.
 */
export class HistoryDb {
  private readonly db: Db;

  constructor(path: string) {
    const require = createRequire(import.meta.url);
    const { DatabaseSync } = require("node:sqlite") as { DatabaseSync: new (p: string) => Db };
    this.db = new DatabaseSync(path);
    this.db.exec(SCHEMA);
  }

  recordAudit(report: AuditReport, now: string): void {
    const m = report.meta;
    this.db
      .prepare(
        `INSERT INTO audit_events(integrity,name,version,verdict,score,top_finding,signature,provenance,report_json,audited_at)
         VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(integrity) DO NOTHING`,
      )
      .run(
        m.integrity ?? `${m.name}@${m.version}`, m.name, m.version, report.verdict, report.score,
        report.findings[0]?.message ?? null, m.signature ?? null, m.provenance ?? null,
        JSON.stringify(report), now,
      );
  }

  recordViolation(rec: ViolationRecord): void {
    const detail = rec.kind + (rec.target ? `:${rec.target}` : rec.deniedResource ? `:${rec.deniedResource}` : "");
    this.db
      .prepare(
        `INSERT INTO violation_events(integrity,name,version,status,quarantined,detail,recorded_at)
         VALUES(?,?,?,?,?,?,?)`,
      )
      .run(rec.integrity, rec.name, rec.version, rec.confidence, rec.quarantined ? 1 : 0, detail, rec.reportedAt);
  }

  /** Count successful native tarball serves. npm-session retries dedupe per coordinate; requests without it count individually. */
  recordDownload(input: { name: string; version: string; integrity: string; npmSession?: string; servedAt: string }): { count: number; recorded: boolean } {
    const material = input.npmSession === undefined
      ? `serve:${randomUUID()}`
      : `npm-session:${input.name}\u0000${input.version}\u0000${input.integrity}\u0000${input.npmSession}`;
    const dedupeKey = createHash("sha256").update(material).digest("hex");
    const result = this.db.prepare(
      `INSERT INTO download_events(dedupe_key,integrity,name,version,served_at)
       VALUES(?,?,?,?,?) ON CONFLICT(dedupe_key) DO NOTHING`,
    ).run(dedupeKey, input.integrity, input.name, input.version, input.servedAt) as { changes: number | bigint };
    return { count: this.downloadCount(input.name, input.version), recorded: Number(result.changes) > 0 };
  }

  downloadCount(name: string, version: string): number {
    return Number((this.db.prepare("SELECT COUNT(*) c FROM download_events WHERE name=? AND version=?").all(name, version)[0] as { c: number }).c);
  }

  recordRetractionWindowHit(hit: RetractionWindowHitRow): void {
    this.db.prepare(
      `INSERT INTO retraction_window_hits(name,version,age_hours,downloads,max_age_hours,max_downloads,age_exceeded,downloads_exceeded,attempted_at)
       VALUES(?,?,?,?,?,?,?,?,?)`,
    ).run(
      hit.name, hit.version, hit.ageHours, hit.downloads, hit.maxAgeHours, hit.maxDownloads,
      hit.ageExceeded ? 1 : 0, hit.downloadsExceeded ? 1 : 0, hit.attemptedAt,
    );
  }

  retractionWindowHits(opts: { limit?: number } = {}): RetractionWindowHitRow[] {
    return this.db.prepare(
      `SELECT name,version,age_hours,downloads,max_age_hours,max_downloads,age_exceeded,downloads_exceeded,attempted_at
       FROM retraction_window_hits ORDER BY attempted_at DESC, id DESC LIMIT ?`,
    ).all(opts.limit ?? 100).map((row) => ({
      name: row.name as string,
      version: row.version as string,
      ageHours: Number(row.age_hours),
      downloads: Number(row.downloads),
      maxAgeHours: Number(row.max_age_hours),
      maxDownloads: Number(row.max_downloads),
      ageExceeded: Number(row.age_exceeded) === 1,
      downloadsExceeded: Number(row.downloads_exceeded) === 1,
      attemptedAt: row.attempted_at as string,
    }));
  }

  retractionWindowHitCounts(): { age: number; downloads: number; both: number } {
    const row = this.db.prepare(
      `SELECT
         SUM(CASE WHEN age_exceeded=1 AND downloads_exceeded=0 THEN 1 ELSE 0 END) age,
         SUM(CASE WHEN age_exceeded=0 AND downloads_exceeded=1 THEN 1 ELSE 0 END) downloads,
         SUM(CASE WHEN age_exceeded=1 AND downloads_exceeded=1 THEN 1 ELSE 0 END) both
       FROM retraction_window_hits`,
    ).all()[0] as { age: number | null; downloads: number | null; both: number | null };
    return { age: Number(row.age ?? 0), downloads: Number(row.downloads ?? 0), both: Number(row.both ?? 0) };
  }

  summary(): HistorySummary {
    const n = (col: "verdict" | "signature" | "provenance", val: string, table = "audit_events") =>
      Number((this.db.prepare(`SELECT COUNT(*) c FROM ${table} WHERE ${col}=?`).all(val)[0] as { c: number }).c);
    const total = Number((this.db.prepare("SELECT COUNT(*) c FROM audit_events").all()[0] as { c: number }).c);
    const violations = Number((this.db.prepare("SELECT COUNT(*) c FROM violation_events").all()[0] as { c: number }).c);
    const quarantined = Number((this.db.prepare("SELECT COUNT(*) c FROM violation_events WHERE quarantined=1").all()[0] as { c: number }).c);
    const retractionWindowHits = Number((this.db.prepare("SELECT COUNT(*) c FROM retraction_window_hits").all()[0] as { c: number }).c);
    return {
      total,
      verdict: { allow: n("verdict", "allow"), warn: n("verdict", "warn"), block: n("verdict", "block") },
      signature: { verified: n("signature", "verified"), invalid: n("signature", "invalid"), unsigned: n("signature", "unsigned"), unknown: n("signature", "unknown") },
      provenance: { verified: n("provenance", "verified"), invalid: n("provenance", "invalid"), absent: n("provenance", "absent"), unknown: n("provenance", "unknown") },
      violations, quarantined, retractionWindowHits,
    };
  }

  history(opts: { verdict?: string; name?: string; limit?: number; offset?: number }): HistoryRow[] {
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.verdict) { where.push("verdict=?"); params.push(opts.verdict); }
    if (opts.name) { where.push("name=?"); params.push(opts.name); }
    const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const rows = this.db
      .prepare(`SELECT name,version,verdict,score,top_finding,audited_at FROM audit_events ${clause} ORDER BY audited_at DESC LIMIT ? OFFSET ?`)
      .all(...params, opts.limit ?? 50, opts.offset ?? 0);
    return rows.map((r) => ({
      name: r.name as string, version: r.version as string, verdict: r.verdict as string,
      score: r.score as number, topFinding: (r.top_finding as string | null) ?? null, auditedAt: r.audited_at as string,
    }));
  }

  trends(opts: { limit?: number } = {}): TrendBucket[] {
    const rows = this.db
      .prepare(
        `SELECT date(audited_at) d,
                SUM(verdict='allow') a, SUM(verdict='warn') w, SUM(verdict='block') b
         FROM audit_events GROUP BY date(audited_at) ORDER BY d DESC LIMIT ?`,
      )
      .all(opts.limit ?? 30);
    return rows
      .map((r) => ({ date: r.d as string, allow: Number(r.a), warn: Number(r.w), block: Number(r.b) }))
      .reverse(); // chronological
  }

  topFlagged(opts: { limit?: number } = {}): TopFlagged[] {
    const rows = this.db
      .prepare(
        `SELECT name, SUM(verdict='warn') w, SUM(verdict='block') b
         FROM audit_events WHERE verdict IN ('warn','block')
         GROUP BY name ORDER BY (w+b) DESC, name ASC LIMIT ?`,
      )
      .all(opts.limit ?? 10);
    return rows.map((r) => ({ name: r.name as string, warn: Number(r.w), block: Number(r.b) }));
  }

  violationTimeline(opts: { limit?: number } = {}): ViolationTimelineRow[] {
    const rows = this.db
      .prepare(`SELECT name,version,status,quarantined,detail,recorded_at FROM violation_events ORDER BY recorded_at DESC, id DESC LIMIT ?`)
      .all(opts.limit ?? 50);
    return rows.map((r) => ({
      name: (r.name as string | null) ?? null, version: (r.version as string | null) ?? null,
      status: r.status as string, quarantined: Number(r.quarantined) === 1,
      detail: (r.detail as string | null) ?? null, recordedAt: r.recorded_at as string,
    }));
  }

  /** All stored audit reports, newest-first, bounded. For policy-impact replay (Phase 20). */
  allReports(limit = 1000): AuditReport[] {
    const rows = this.db.prepare(`SELECT report_json FROM audit_events ORDER BY audited_at DESC LIMIT ?`).all(limit);
    const out: AuditReport[] = [];
    for (const r of rows) {
      try { out.push(JSON.parse(r.report_json as string) as AuditReport); } catch { /* skip a corrupt row */ }
    }
    return out;
  }

  close(): void { this.db.close(); }
}
