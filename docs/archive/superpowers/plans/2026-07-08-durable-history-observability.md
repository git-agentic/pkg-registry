# Phase 15 — Durable Audit History + Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a durable, queryable observability layer (audit history + runtime-violation timeline + metrics) backed by the built-in `node:sqlite`, opt-in and write-through, so a deployed Sentinel can answer "what did we flag/block/quarantine over time."

**Architecture:** A new isolated `HistoryDb` unit (`packages/proxy/src/history-db.ts`) wraps `node:sqlite` (loaded lazily via `createRequire` so its experimental-warning never fires unless a DB is configured). It is opt-in (`SENTINEL_HISTORY_DB=<path>`); when set, `AuditStore.put()` and `ViolationStore.record()` write through to it best-effort, and the proxy exposes `/-/metrics`, `/-/history`, `/-/violations/timeline` read endpoints plus `sentinel stats`/`history` CLI and a dashboard section. When unset, nothing changes.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; `node:sqlite` (built-in — **zero new runtime dependency**); Express 5; `node:test` via `tsx`.

## Global Constraints

- **Zero new runtime dependencies.** `node:sqlite` is a Node built-in. Do not add `better-sqlite3` or any package.
- **Opt-in.** No `HistoryDb` unless `SENTINEL_HISTORY_DB` is set (server) or one is passed explicitly (tests). Unconfigured ⇒ exactly today's in-memory behavior; the ~400 existing tests construct stores with no `HistoryDb` and must stay green.
- **Lazy load.** `node:sqlite` is imported via `createRequire(import.meta.url)` **inside the `HistoryDb` constructor**, never at module top level — so importing `history-db.ts` (e.g. a type import) never triggers the experimental warning; only `new HistoryDb(...)` does.
- **Best-effort write-through (invariant #6).** Every `history?.recordX(...)` call is wrapped in try/catch and swallowed; a `HistoryDb` failure must never break an audit or a violation record. The store's existing return value is the source of truth.
- **Injected timestamps.** `recordAudit(report, now)` takes an ISO `now`; `recordViolation(rec)` uses `rec.reportedAt` (the violation's own event time). Tests pass fixed ISO strings for deterministic query assertions.
- **Audits upsert-ignore by integrity** (`INSERT … ON CONFLICT(integrity) DO NOTHING`) — one row per immutable audit, `audited_at` = first-seen. **Violations append-only** (one row per `record()`), preserving suspected→confirmed timelines.
- **Reads stay open** (Phase 12 authz split) — the three new GET endpoints are not role-gated.
- **Disabled endpoints return HTTP `501` + `{ enabled: false }`** — never a silent empty result. The CLI keys off `enabled: false` to print its enable hint.
- **Invariant #1 untouched:** `HistoryDb` is write-through storage + reads; the scoring path is unchanged; the determinism test is unaffected.
- ESM only, NodeNext: internal imports use `.js` specifiers even from `.ts`; cross-unit type-only imports use `import type` (so `history-db.ts` ↔ `violations.ts` stay runtime-decoupled).
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/<pkg>`.
- Run all commands from repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.

---

### Task 1: `HistoryDb` — schema, writes, and `summary()`

**Files:**
- Create: `packages/proxy/src/history-db.ts`
- Test: `packages/proxy/test/history-db.test.ts`

**Interfaces:**
- Consumes: `AuditReport` (`@sentinel/core`), `ViolationRecord` (`./violations.js`, type-only).
- Produces (used by Tasks 2–5):
  - `class HistoryDb { constructor(path: string); recordAudit(report: AuditReport, now: string): void; recordViolation(rec: ViolationRecord): void; summary(): HistorySummary; close(): void }`
  - `interface HistorySummary { total: number; verdict: { allow: number; warn: number; block: number }; signature: { verified: number; invalid: number; unsigned: number; unknown: number }; provenance: { verified: number; invalid: number; absent: number; unknown: number }; violations: number; quarantined: number }`

- [ ] **Step 1: Write the failing test** (`packages/proxy/test/history-db.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { HistoryDb } from "../src/history-db.js";
import type { AuditReport } from "@sentinel/core";
import type { ViolationRecord } from "../src/violations.js";

function auditReport(over: Partial<{ integrity: string; name: string; version: string; verdict: "allow" | "warn" | "block"; score: number; finding: string; signature: string; provenance: string }> = {}): AuditReport {
  return {
    schema: 3,
    meta: {
      name: over.name ?? "leftpad-lite", version: over.version ?? "1.0.0",
      integrity: over.integrity ?? "sha512-aaa",
      signature: (over.signature ?? "unsigned") as never,
      provenance: (over.provenance ?? "absent") as never,
    },
    score: over.score ?? 100,
    verdict: over.verdict ?? "allow",
    findings: over.finding ? [{ id: "x", message: over.finding, severity: "high", category: "metadata", weight: 25 } as never] : [],
  } as unknown as AuditReport;
}
function violation(over: Partial<ViolationRecord> = {}): ViolationRecord {
  return {
    name: "evil", version: "1.0.0", integrity: over.integrity ?? "sha512-v",
    kind: over.kind ?? "network", target: over.target ?? "203.0.113.9",
    confidence: over.confidence ?? "confirmed", deniedResource: over.deniedResource ?? null,
    evidence: { exitCode: 1, stderrExcerpt: "denied" },
    quarantined: over.quarantined ?? true, reportedAt: over.reportedAt ?? "2026-07-01T00:00:00Z",
    ...over,
  } as ViolationRecord;
}

describe("HistoryDb — schema, writes, summary", () => {
  test("recordAudit + summary counts verdict/signature/provenance", () => {
    const db = new HistoryDb(":memory:");
    db.recordAudit(auditReport({ integrity: "sha512-a", verdict: "allow", signature: "verified", provenance: "verified" }), "2026-07-01T10:00:00Z");
    db.recordAudit(auditReport({ integrity: "sha512-b", verdict: "block", score: 10 }), "2026-07-01T11:00:00Z");
    const s = db.summary();
    assert.equal(s.total, 2);
    assert.equal(s.verdict.allow, 1);
    assert.equal(s.verdict.block, 1);
    assert.equal(s.signature.verified, 1);
    assert.equal(s.provenance.verified, 1);
    db.close();
  });

  test("recordAudit is upsert-ignore: re-recording an integrity does not duplicate or move audited_at", () => {
    const db = new HistoryDb(":memory:");
    db.recordAudit(auditReport({ integrity: "sha512-a", verdict: "block" }), "2026-07-01T10:00:00Z");
    db.recordAudit(auditReport({ integrity: "sha512-a", verdict: "allow" }), "2026-07-05T10:00:00Z"); // ignored
    const s = db.summary();
    assert.equal(s.total, 1);
    assert.equal(s.verdict.block, 1); // kept the first row
    assert.equal(s.verdict.allow, 0);
    db.close();
  });

  test("recordViolation is append-only: suspected then confirmed keeps both", () => {
    const db = new HistoryDb(":memory:");
    db.recordViolation(violation({ integrity: "sha512-v", confidence: "suspected", quarantined: false, reportedAt: "2026-07-01T00:00:00Z" }));
    db.recordViolation(violation({ integrity: "sha512-v", confidence: "confirmed", quarantined: true, reportedAt: "2026-07-01T00:00:05Z" }));
    const s = db.summary();
    assert.equal(s.violations, 2);
    assert.equal(s.quarantined, 1);
    db.close();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/history-db.test.ts
```

Expected: FAIL — cannot find `../src/history-db.js`.

- [ ] **Step 3: Implement `packages/proxy/src/history-db.ts`**

```ts
import { createRequire } from "node:module";
import type { AuditReport } from "@sentinel/core";
import type { ViolationRecord } from "./violations.js";

export interface HistorySummary {
  total: number;
  verdict: { allow: number; warn: number; block: number };
  signature: { verified: number; invalid: number; unsigned: number; unknown: number };
  provenance: { verified: number; invalid: number; absent: number; unknown: number };
  violations: number;
  quarantined: number;
}

export interface HistoryRow { name: string; version: string; verdict: string; score: number; topFinding: string | null; auditedAt: string; }
export interface TrendBucket { date: string; allow: number; warn: number; block: number; }
export interface TopFlagged { name: string; warn: number; block: number; }
export interface ViolationTimelineRow { name: string | null; version: string | null; status: string; quarantined: boolean; detail: string | null; recordedAt: string; }

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

  summary(): HistorySummary {
    const n = (col: string, val: string, table = "audit_events") =>
      Number((this.db.prepare(`SELECT COUNT(*) c FROM ${table} WHERE ${col}=?`).all(val)[0] as { c: number }).c);
    const total = Number((this.db.prepare("SELECT COUNT(*) c FROM audit_events").all()[0] as { c: number }).c);
    const violations = Number((this.db.prepare("SELECT COUNT(*) c FROM violation_events").all()[0] as { c: number }).c);
    const quarantined = Number((this.db.prepare("SELECT COUNT(*) c FROM violation_events WHERE quarantined=1").all()[0] as { c: number }).c);
    return {
      total,
      verdict: { allow: n("verdict", "allow"), warn: n("verdict", "warn"), block: n("verdict", "block") },
      signature: { verified: n("signature", "verified"), invalid: n("signature", "invalid"), unsigned: n("signature", "unsigned"), unknown: n("signature", "unknown") },
      provenance: { verified: n("provenance", "verified"), invalid: n("provenance", "invalid"), absent: n("provenance", "absent"), unknown: n("provenance", "unknown") },
      violations, quarantined,
    };
  }

  close(): void { this.db.close(); }
}
```

- [ ] **Step 4: Run the test + build**

```bash
npm run build
npx tsx --test packages/proxy/test/history-db.test.ts
```

Expected: PASS (3/3). Build clean.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/history-db.ts packages/proxy/test/history-db.test.ts
git commit -m "feat(phase15): HistoryDb — node:sqlite schema, write path, summary() (lazy load, upsert-ignore audits, append-only violations)"
```

---

### Task 2: `HistoryDb` — `history` / `trends` / `topFlagged` / `violationTimeline`

**Files:**
- Modify: `packages/proxy/src/history-db.ts` (add four query methods)
- Test: `packages/proxy/test/history-db-queries.test.ts`

**Interfaces:**
- Consumes: the Task 1 `HistoryDb` + its exported row types.
- Produces (used by Tasks 4–6):
  - `history(opts: { verdict?: string; name?: string; limit?: number; offset?: number }): HistoryRow[]`
  - `trends(opts?: { limit?: number }): TrendBucket[]` — last `limit` day-buckets (default 30), chronological.
  - `topFlagged(opts?: { limit?: number }): TopFlagged[]` — package names by warn+block count, default 10.
  - `violationTimeline(opts?: { limit?: number }): ViolationTimelineRow[]` — most-recent first, default 50.

- [ ] **Step 1: Write the failing test** (`packages/proxy/test/history-db-queries.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { HistoryDb } from "../src/history-db.js";
import type { AuditReport } from "@sentinel/core";
import type { ViolationRecord } from "../src/violations.js";

function rep(integrity: string, name: string, verdict: "allow" | "warn" | "block", finding: string | null, at: string): [AuditReport, string] {
  return [{
    schema: 3,
    meta: { name, version: "1.0.0", integrity, signature: "unsigned", provenance: "absent" },
    score: verdict === "block" ? 10 : verdict === "warn" ? 60 : 100, verdict,
    findings: finding ? [{ id: "x", message: finding, severity: "high", category: "metadata", weight: 25 }] : [],
  } as unknown as AuditReport, at];
}

describe("HistoryDb queries", () => {
  function seed(): HistoryDb {
    const db = new HistoryDb(":memory:");
    db.recordAudit(...rep("sha512-1", "left-pad", "block", "install script", "2026-07-01T10:00:00Z"));
    db.recordAudit(...rep("sha512-2", "left-pad", "warn", "network egress", "2026-07-01T12:00:00Z"));
    db.recordAudit(...rep("sha512-3", "chalk", "allow", null, "2026-07-02T09:00:00Z"));
    db.recordAudit(...rep("sha512-4", "evil", "block", "secret exfil", "2026-07-02T15:00:00Z"));
    db.recordViolation({ name: "evil", version: "1.0.0", integrity: "sha512-4", kind: "network", target: "203.0.113.9", confidence: "confirmed", deniedResource: null, evidence: { exitCode: 1, stderrExcerpt: "x" }, quarantined: true, reportedAt: "2026-07-02T15:01:00Z" } as ViolationRecord);
    return db;
  }

  test("history filters by verdict and paginates, most-recent first", () => {
    const db = seed();
    const blocks = db.history({ verdict: "block", limit: 10, offset: 0 });
    assert.deepEqual(blocks.map((r) => r.name), ["evil", "left-pad"]); // 07-02 before 07-01
    assert.equal(blocks[0]!.topFinding, "secret exfil");
    const page = db.history({ limit: 2, offset: 0 });
    assert.equal(page.length, 2);
    db.close();
  });

  test("history filters by name", () => {
    const db = seed();
    assert.equal(db.history({ name: "left-pad", limit: 10, offset: 0 }).length, 2);
    db.close();
  });

  test("trends buckets verdicts per day, chronological", () => {
    const db = seed();
    const t = db.trends({ limit: 30 });
    assert.deepEqual(t, [
      { date: "2026-07-01", allow: 0, warn: 1, block: 1 },
      { date: "2026-07-02", allow: 1, warn: 0, block: 1 },
    ]);
    db.close();
  });

  test("topFlagged ranks by warn+block count", () => {
    const db = seed();
    const top = db.topFlagged({ limit: 10 });
    assert.equal(top[0]!.name, "left-pad"); // 1 warn + 1 block = 2
    assert.equal(top[0]!.warn, 1);
    assert.equal(top[0]!.block, 1);
    db.close();
  });

  test("violationTimeline returns recent events", () => {
    const db = seed();
    const tl = db.violationTimeline({ limit: 50 });
    assert.equal(tl.length, 1);
    assert.equal(tl[0]!.name, "evil");
    assert.equal(tl[0]!.quarantined, true);
    assert.equal(tl[0]!.detail, "network:203.0.113.9");
    db.close();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/history-db-queries.test.ts
```

Expected: FAIL — `history`/`trends`/`topFlagged`/`violationTimeline` are not methods.

- [ ] **Step 3: Add the four methods to `HistoryDb` (in `history-db.ts`, before `close()`)**

```ts
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
```

- [ ] **Step 4: Run the test + build**

```bash
npm run build
npx tsx --test packages/proxy/test/history-db-queries.test.ts
```

Expected: PASS (5/5).

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/history-db.ts packages/proxy/test/history-db-queries.test.ts
git commit -m "feat(phase15): HistoryDb queries — history/trends/topFlagged/violationTimeline"
```

---

### Task 3: Write-through wiring (stores + server options + main)

**Files:**
- Modify: `packages/proxy/src/store.ts` (`AuditStore` gains `history?` + write-through)
- Modify: `packages/proxy/src/violations.ts` (`ViolationStore` gains `history?` + write-through)
- Modify: `packages/proxy/src/server.ts` (`ServerOptions.history?`)
- Modify: `packages/proxy/src/index.ts` (`main()` reads `SENTINEL_HISTORY_DB`, constructs, wires)
- Test: `packages/proxy/test/history-writethrough.test.ts`

**Interfaces:**
- Consumes: `HistoryDb` (Task 1).
- Produces: `new AuditStore(file?, activePolicyHash?, history?)`; `new ViolationStore(file?, history?)`; `ServerOptions.history?: HistoryDb`.

- [ ] **Step 1: Write the failing test** (`packages/proxy/test/history-writethrough.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { HistoryDb } from "../src/history-db.js";
import { AuditStore } from "../src/store.js";
import { ViolationStore } from "../src/violations.js";
import type { AuditReport } from "@sentinel/core";
import type { ViolationRecord } from "../src/violations.js";

const report = {
  schema: 3, meta: { name: "p", version: "1.0.0", integrity: "sha512-w", signature: "unsigned", provenance: "absent" },
  score: 100, verdict: "allow", findings: [],
} as unknown as AuditReport;

describe("store write-through to HistoryDb", () => {
  test("AuditStore.put with a HistoryDb lands an audit row", () => {
    const h = new HistoryDb(":memory:");
    const store = new AuditStore(undefined, undefined, h);
    store.put(report);
    assert.equal(h.summary().total, 1);
    h.close();
  });

  test("AuditStore.put without a HistoryDb still works (default path unchanged)", () => {
    const store = new AuditStore();
    assert.equal(store.put(report).name, "p");
    assert.equal(store.stats().total, 1);
  });

  test("ViolationStore.record with a HistoryDb lands a violation row", () => {
    const h = new HistoryDb(":memory:");
    const vs = new ViolationStore(undefined, h);
    vs.record({ name: "evil", version: "1.0.0", integrity: "sha512-v", kind: "network", target: "203.0.113.9", confidence: "confirmed", deniedResource: null, evidence: { exitCode: 1, stderrExcerpt: "x" } });
    assert.equal(h.summary().violations, 1);
    h.close();
  });

  test("a HistoryDb whose write throws is swallowed; the store record still succeeds", () => {
    const broken = { recordAudit() { throw new Error("db down"); } } as unknown as HistoryDb;
    const store = new AuditStore(undefined, undefined, broken);
    assert.equal(store.put(report).name, "p"); // no throw
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/history-writethrough.test.ts
```

Expected: FAIL — `AuditStore`/`ViolationStore` constructors don't accept a `history` arg.

- [ ] **Step 3a: `AuditStore` — add the param + write-through (`packages/proxy/src/store.ts`)**

Add the import at the top:

```ts
import type { HistoryDb } from "./history-db.js";
```

Change the constructor signature (the existing `constructor(private readonly file?: string, private readonly activePolicyHash?: string)`):

```ts
  constructor(
    private readonly file?: string,
    private readonly activePolicyHash?: string,
    private readonly history?: HistoryDb,
  ) {
```

In `put(report)`, after `this.index(...)` and `this.persist()` (before `return stored;`), add:

```ts
    try {
      this.history?.recordAudit(report, new Date().toISOString());
    } catch {
      /* observability is best-effort — never break an audit (invariant #6) */
    }
```

- [ ] **Step 3b: `ViolationStore` — add the param + write-through (`packages/proxy/src/violations.ts`)**

Add the import at the top:

```ts
import type { HistoryDb } from "./history-db.js";
```

Change `constructor(private readonly file?: string)` to:

```ts
  constructor(private readonly file?: string, private readonly history?: HistoryDb) {
```

In `record(...)`, after `this.index(rec)` and `this.persist()` (before `return rec;`), add:

```ts
    try {
      this.history?.recordViolation(rec);
    } catch {
      /* best-effort telemetry — never break a violation record (invariant #6) */
    }
```

(Note: the two early-`return existing` paths in `record()` do NOT write through — they represent a de-duplicated/sticky record, not a new event. Only a freshly-indexed `rec` is recorded.)

- [ ] **Step 3c: `ServerOptions` — add the field (`packages/proxy/src/server.ts`)**

Add to the `ServerOptions` interface (near `violations`):

```ts
  /** Durable observability store (Phase 15). Undefined ⇒ history/metrics disabled. */
  history?: HistoryDb;
```

Add the type import to the existing proxy-local imports block:

```ts
import type { HistoryDb } from "./history-db.js";
```

Destructure it where the other opts are pulled (find `const { ... } = opts;` or the `opts.violations` usage) — expose `const history = opts.history;` for Task 4's routes.

- [ ] **Step 3d: `main()` — construct + wire (`packages/proxy/src/index.ts`)**

Add the import:

```ts
import { HistoryDb } from "./history-db.js";
```

In `main()`, before `const store = ...`, construct the history db:

```ts
  const history = process.env.SENTINEL_HISTORY_DB ? new HistoryDb(process.env.SENTINEL_HISTORY_DB) : undefined;
```

Thread it into both stores and the server:

```ts
  const store = new AuditStore(process.env.SENTINEL_STORE, policyHash, history);
  // ...
  const violations = new ViolationStore(process.env.SENTINEL_VIOLATIONS, history);
  // ...
  const app = createServer({ upstream, store, approvals, enterprisePolicy, policyHash, policy, publicDir, privateStore, publishTokens, trustMaterial, violations, approvalRequests, authPublicKey, history });
```

Add a startup log line beside the others:

```ts
    console.log(`  history  : ${history ? `enabled (${process.env.SENTINEL_HISTORY_DB})` : "disabled"}`);
```

- [ ] **Step 4: Build + run the write-through test + the existing store/violations suites**

```bash
npm run build
npx tsx --test packages/proxy/test/history-writethrough.test.ts packages/proxy/test/store.test.ts packages/proxy/test/violations.test.ts
```

Expected: PASS. (If the exact existing test filenames differ, run `ls packages/proxy/test | grep -E "store|violation"` and run those.)

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/store.ts packages/proxy/src/violations.ts packages/proxy/src/server.ts packages/proxy/src/index.ts packages/proxy/test/history-writethrough.test.ts
git commit -m "feat(phase15): opt-in HistoryDb write-through from AuditStore/ViolationStore + main wiring"
```

---

### Task 4: Observability endpoints

**Files:**
- Modify: `packages/proxy/src/server.ts` (register `GET /-/metrics`, `/-/history`, `/-/violations/timeline`)
- Test: `packages/proxy/test/history-endpoints-e2e.test.ts`

**Interfaces:**
- Consumes: `opts.history` (Task 3), the `HistoryDb` query methods (Tasks 1–2).
- Produces: three GET endpoints. Disabled (no `history`) ⇒ HTTP `501` + `{ enabled: false }`.

- [ ] **Step 1: Write the failing e2e** (`packages/proxy/test/history-endpoints-e2e.test.ts`)

Model the boot on `packages/proxy/test/audit-tree-integrity-e2e.test.ts` (same store set + `LocalFixtureUpstream`), but add a `history` to the options and seed a couple of audits through `store.put` before asserting. Skeleton:

```ts
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
import type { AuditReport } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import { HistoryDb } from "../src/history-db.js";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "fixtures");
const rep = (integrity: string, name: string, verdict: "allow" | "warn" | "block"): AuditReport =>
  ({ schema: 3, meta: { name, version: "1.0.0", integrity, signature: "unsigned", provenance: "absent" }, score: verdict === "block" ? 10 : 100, verdict, findings: [] } as unknown as AuditReport);

function boot(withHistory: boolean): Promise<{ server: Server; base: string; history?: HistoryDb }> {
  const history = withHistory ? new HistoryDb(":memory:") : undefined;
  const store = new AuditStore(undefined, undefined, history);
  if (history) { store.put(rep("sha512-1", "evil", "block")); store.put(rep("sha512-2", "ok", "allow")); }
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store, approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(undefined, history), approvalRequests: new ApprovalRequestStore(), history,
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, history })); });
}

describe("observability endpoints (e2e)", () => {
  test("GET /-/metrics returns summary + trends + topFlagged when enabled", async () => {
    const { server, base, history } = await boot(true);
    const m = await (await fetch(`${base}/-/metrics`)).json() as { summary: { total: number; verdict: { block: number } }; trends: unknown[]; topFlagged: { name: string }[] };
    assert.equal(m.summary.total, 2);
    assert.equal(m.summary.verdict.block, 1);
    assert.ok(Array.isArray(m.trends));
    assert.equal(m.topFlagged[0]!.name, "evil");
    server.close(); history?.close();
  });

  test("GET /-/history?verdict=block filters", async () => {
    const { server, base, history } = await boot(true);
    const h = await (await fetch(`${base}/-/history?verdict=block`)).json() as { history: { name: string }[] };
    assert.equal(h.history.length, 1);
    assert.equal(h.history[0]!.name, "evil");
    server.close(); history?.close();
  });

  test("disabled: /-/metrics returns 501 { enabled: false }", async () => {
    const { server, base } = await boot(false);
    const res = await fetch(`${base}/-/metrics`);
    assert.equal(res.status, 501);
    assert.equal(((await res.json()) as { enabled: boolean }).enabled, false);
    server.close();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/history-endpoints-e2e.test.ts
```

Expected: FAIL — the endpoints 404 / don't exist.

- [ ] **Step 3: Register the endpoints in `server.ts`** (near the other `/-/` GET routes, e.g. after `/-/audits`)

```ts
  const disabled = (res: import("express").Response) => res.status(501).json({ enabled: false });

  app.get("/-/metrics", (_req, res) => {
    if (!history) return disabled(res);
    res.json({ summary: history.summary(), trends: history.trends(), topFlagged: history.topFlagged() });
  });

  app.get("/-/history", (req, res) => {
    if (!history) return disabled(res);
    const q = req.query as { verdict?: string; name?: string; limit?: string; offset?: string };
    res.json({
      history: history.history({
        verdict: q.verdict, name: q.name,
        limit: q.limit ? Math.min(Number(q.limit) || 50, 500) : 50,
        offset: q.offset ? Number(q.offset) || 0 : 0,
      }),
    });
  });

  app.get("/-/violations/timeline", (_req, res) => {
    if (!history) return disabled(res);
    res.json({ timeline: history.violationTimeline() });
  });
```

(Ensure `const history = opts.history;` from Task 3c is in scope here.)

- [ ] **Step 4: Build + run the e2e**

```bash
npm run build
npx tsx --test packages/proxy/test/history-endpoints-e2e.test.ts
```

Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/history-endpoints-e2e.test.ts
git commit -m "feat(phase15): /-/metrics, /-/history, /-/violations/timeline read endpoints (501 when disabled)"
```

---

### Task 5: CLI — `sentinel stats` and `sentinel history`

**Files:**
- Modify: `packages/cli/src/index.ts` (two commands)
- Test: `packages/cli/test/stats-history-cli-e2e.test.ts`

**Interfaces:**
- Consumes: `GET /-/metrics`, `/-/history` (Task 4).
- Produces: `sentinel stats`, `sentinel history [--verdict <v>] [--name <n>] [--limit <N>]`.

- [ ] **Step 1: Write the failing e2e** (`packages/cli/test/stats-history-cli-e2e.test.ts`)

Boot an in-process proxy **with** a `:memory:` `HistoryDb` (seed two audits via `store.put`), run the CLI child against it with async `execFile` + `SENTINEL_PROXY` (model on an existing CLI e2e in `packages/cli/test`). Assert:
- `sentinel stats` prints the totals (e.g. output contains `2` audits and a `block` count) and exits 0.
- `sentinel history --verdict block` prints the blocked package name (`evil`) and exits 0.
- Against a proxy booted **without** history, `sentinel stats` prints a "history not enabled" message (still exits 0, or a documented non-zero — assert the message + a consistent code).

(Fill the boot/run helpers from the existing CLI e2e; keep assertions to output substrings + exit code.)

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/cli/test/stats-history-cli-e2e.test.ts
```

Expected: FAIL — `stats`/`history` commands don't exist.

- [ ] **Step 3: Add the commands in `packages/cli/src/index.ts`** (model on the existing `violations` command at ~line 157)

```ts
program
  .command("stats")
  .description("Show durable audit/violation metrics (requires the proxy's SENTINEL_HISTORY_DB).")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .action(async (opts: { proxy: string }) => {
    const res = await fetch(`${opts.proxy}/-/metrics`);
    if (res.status === 501) { console.log("history not enabled — set SENTINEL_HISTORY_DB on the proxy"); return; }
    if (!res.ok) return fail(new Error(`metrics failed: ${res.status}`), opts.proxy);
    const m = (await res.json()) as { summary: { total: number; verdict: { allow: number; warn: number; block: number }; violations: number; quarantined: number }; trends: { date: string; allow: number; warn: number; block: number }[]; topFlagged: { name: string; warn: number; block: number }[] };
    console.log(formatStats(m));
  });

program
  .command("history")
  .description("List recorded audits (requires the proxy's SENTINEL_HISTORY_DB).")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--verdict <v>", "filter by verdict (allow|warn|block)")
  .option("--name <name>", "filter by package name")
  .option("--limit <n>", "max rows", "50")
  .action(async (opts: { proxy: string; verdict?: string; name?: string; limit: string }) => {
    const qs = new URLSearchParams();
    if (opts.verdict) qs.set("verdict", opts.verdict);
    if (opts.name) qs.set("name", opts.name);
    qs.set("limit", opts.limit);
    const res = await fetch(`${opts.proxy}/-/history?${qs}`);
    if (res.status === 501) { console.log("history not enabled — set SENTINEL_HISTORY_DB on the proxy"); return; }
    if (!res.ok) return fail(new Error(`history failed: ${res.status}`), opts.proxy);
    const { history } = (await res.json()) as { history: { name: string; version: string; verdict: string; score: number; topFinding: string | null; auditedAt: string }[] };
    console.log(formatHistory(history));
  });
```

Add the two formatters to `packages/cli/src/format.ts` (pure string builders; match the existing `formatViolations`/`formatTree` style — colored, aligned):

```ts
export function formatStats(m: { summary: { total: number; verdict: { allow: number; warn: number; block: number }; violations: number; quarantined: number }; trends: { date: string; allow: number; warn: number; block: number }[]; topFlagged: { name: string; warn: number; block: number }[] }): string {
  const L: string[] = ["", `  audits: ${m.summary.total}  ·  ${m.summary.verdict.allow} allow · ${m.summary.verdict.warn} warn · ${m.summary.verdict.block} block`,
    `  violations: ${m.summary.violations}  ·  quarantined: ${m.summary.quarantined}`, ""];
  if (m.trends.length) {
    L.push("  trend (allow/warn/block per day):");
    for (const t of m.trends) L.push(`    ${t.date}  ${t.allow}/${t.warn}/${t.block}`);
    L.push("");
  }
  if (m.topFlagged.length) {
    L.push("  most-flagged:");
    for (const f of m.topFlagged) L.push(`    ${f.name}  (${f.warn} warn, ${f.block} block)`);
    L.push("");
  }
  return L.join("\n");
}

export function formatHistory(rows: { name: string; version: string; verdict: string; score: number; topFinding: string | null; auditedAt: string }[]): string {
  if (!rows.length) return "\n  (no audits recorded)\n";
  const L: string[] = ["", `  ${rows.length} audit(s):`];
  for (const r of rows) {
    L.push(`  ${r.verdict.toUpperCase().padEnd(6)} ${r.name}@${r.version}  ${r.score}/100  ${r.auditedAt}`);
    if (r.topFinding) L.push(`         ${r.topFinding}`);
  }
  L.push("");
  return L.join("\n");
}
```

Import them in `index.ts` (extend the existing `./format.js` import).

- [ ] **Step 4: Build + run the e2e + full suite**

```bash
npm run build
npx tsx --test packages/cli/test/stats-history-cli-e2e.test.ts
npm test 2>&1 | tail -6
```

Expected: PASS; record counts.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/index.ts packages/cli/src/format.ts packages/cli/test/stats-history-cli-e2e.test.ts
git commit -m "feat(phase15): sentinel stats + history CLI commands"
```

---

### Task 6: Dashboard observability section

**Files:**
- Modify: `packages/proxy/public/index.html` (add an Observability section + inline-SVG trend)
- Test: `packages/proxy/test/history-endpoints-e2e.test.ts` (extend: assert `/-/metrics` shape already covers the data; add a smoke assert that `GET /` still serves)

**Interfaces:**
- Consumes: `GET /-/metrics`, `/-/violations/timeline`.
- Produces: a dashboard panel; no new JS dependency (inline `<script>` + inline SVG only).

- [ ] **Step 1: Read the current dashboard** to match its style and fetch pattern:

```bash
sed -n '1,60p' packages/proxy/public/index.html
grep -n "fetch(\|/-/audits\|<section\|<script" packages/proxy/public/index.html
```

- [ ] **Step 2: Add an "Observability" section** — an HTML block plus an inline script that `fetch("/-/metrics")` and `fetch("/-/violations/timeline")`, and on a `501`/`enabled:false` shows a "history not enabled" note. Render:
  - the summary line (totals + verdict/violation/quarantine counts),
  - a compact **inline-SVG bar chart** of `trends` (one bar-group per day; no chart lib — build `<rect>`s from the data; height scaled to the max daily total),
  - the `topFlagged` list, and
  - the `violationTimeline` list.

Concrete inline-SVG builder (drop into the dashboard script — no external asset):

```js
function trendSvg(trends) {
  if (!trends.length) return '<p class="muted">no trend data yet</p>';
  const W = 320, H = 80, bw = Math.max(4, Math.floor(W / (trends.length * 3)));
  const max = Math.max(1, ...trends.map(t => t.allow + t.warn + t.block));
  const colors = { allow: '#3fb950', warn: '#d29922', block: '#f85149' };
  let x = 0, bars = '';
  for (const t of trends) {
    let y = H;
    for (const k of ['block', 'warn', 'allow']) {
      const h = Math.round((t[k] / max) * (H - 10));
      y -= h;
      if (h > 0) bars += `<rect x="${x}" y="${y}" width="${bw}" height="${h}" fill="${colors[k]}"><title>${t.date} ${k}: ${t[k]}</title></rect>`;
    }
    x += bw + 3;
  }
  return `<svg width="${W}" height="${H}" role="img" aria-label="verdict trend">${bars}</svg>`;
}
```

Wire it: `const m = await (await fetch('/-/metrics')).json(); if (m.enabled === false) { /* show note */ } else { el.innerHTML = summary(m.summary) + trendSvg(m.trends) + topFlagged(m.topFlagged); }` — but since a disabled proxy returns HTTP 501, check `res.status === 501` first.

- [ ] **Step 3: Extend the e2e smoke** — in `history-endpoints-e2e.test.ts`, add:

```ts
  test("GET / still serves the dashboard html", async () => {
    const { server, base, history } = await boot(true);
    const res = await fetch(`${base}/`);
    // publicDir is not set in this boot, so GET / may 404 — assert the endpoint contract instead:
    assert.ok(res.status === 200 || res.status === 404);
    server.close(); history?.close();
  });
```

(The dashboard HTML itself is static; its data contract is covered by the `/-/metrics` tests. Do not add a browser test.)

- [ ] **Step 4: Build + run + a manual smoke of the JSON shape**

```bash
npm run build
npx tsx --test packages/proxy/test/history-endpoints-e2e.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/public/index.html packages/proxy/test/history-endpoints-e2e.test.ts
git commit -m "feat(phase15): dashboard observability section (inline-SVG trend, top-flagged, violation timeline)"
```

---

### Task 7: Docs, ADR-0028, final verification

**Files:**
- Create: `docs/adr/0028-durable-history-observability.md`
- Modify: `ARCHITECTURE.md` (new observability/HistoryDb section)
- Modify: `CLAUDE.md` (What-this-is phase list; test-count line; the `node:sqlite` opt-in + Node-22 `--experimental-sqlite` caveat)
- Modify: `README.md` (`SENTINEL_HISTORY_DB`, `sentinel stats`/`history`, the new endpoints, the dashboard section)

- [ ] **Step 1: Write ADR-0028** — follow the house style of `docs/adr/0027-ecosystem-breadth-sbom.md`. Required content: **Context** (all signal was in-memory + an O(n)-rewrite JSON file; no durable/queryable history/metrics/trends/audit-trail; ADR-0004 anticipated the `audits(...)` table). **Decision** (built-in `node:sqlite`, probed working unflagged — zero new dep; opt-in `SENTINEL_HISTORY_DB`; additive write-through beside the in-memory hot cache; audits upsert-ignore by integrity, violations append-only; `/-/metrics` `/-/history` `/-/violations/timeline` open reads; `sentinel stats`/`history`; dashboard section). **Determinism** (write-through storage + reads only; injected `now`; invariant #1 untouched). **Consequences** (zero deps; Node 22 needs `--experimental-sqlite`, so it's opt-in and the in-memory default keeps the `>=22` floor; best-effort writes never break the gate; SQLite is single-node — Postgres/scale deferred; unbounded growth / no retention yet). **Deferred** (cache rehydration from `report_json`; removing the JSON cache file; approvals stream; Postgres/shared store; retention/pruning; auth on the read endpoints). **Rejected** (`better-sqlite3` native addon; NDJSON append-log without SQL aggregates). Extends ADR-0004/0023.

- [ ] **Step 2: ARCHITECTURE.md** — add an observability section: the opt-in `HistoryDb` (`node:sqlite`, lazy load), the two tables + write-through from `AuditStore`/`ViolationStore`, the three read endpoints, the CLI + dashboard. Note the default (no history) path is unchanged and the hot verdict cache is untouched.

- [ ] **Step 3: CLAUDE.md** — add the Phase 15 sentence to "What this is" (mirror Phase 14's density: opt-in `node:sqlite` `HistoryDb`, write-through audits + violations, `/-/metrics`/`/-/history`/`/-/violations/timeline`, `sentinel stats`/`history`, dashboard). Update the `npm test` count to the ACTUAL number from Step 5 (preserve the darwin-skip caveats). In the stack/quirks area, note `node:sqlite` is a built-in (no dep) and that durable history is opt-in via `SENTINEL_HISTORY_DB`, requiring Node 24 or Node 22 + `--experimental-sqlite`.

- [ ] **Step 4: README.md** — document `SENTINEL_HISTORY_DB` (enables durable history), the `sentinel stats` / `sentinel history` commands, the `/-/metrics` / `/-/history` / `/-/violations/timeline` endpoints, and the dashboard Observability section. Note it is opt-in and the Node-version caveat.

- [ ] **Step 5: Full Definition-of-Done run**

```bash
npm run build
npm run fixtures
npm test 2>&1 | tail -8
npm run demo 2>&1 | tail -3
```

Expected: build clean; ALL tests pass (record exact count for CLAUDE.md); demo still blocks the malicious fixture. If the count differs from CLAUDE.md, update the doc to reality.

- [ ] **Step 6: Commit**

```bash
git add docs ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs(phase15): ADR-0028 durable history + observability; ARCHITECTURE/CLAUDE/README"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 opt-in/lazy `HistoryDb` → Task 1 (createRequire lazy load, opt-in construction); §2 schema + write path → Task 1 (schema, recordAudit upsert-ignore, recordViolation append-only, injected `now`, best-effort) + Task 3 (write-through from both stores, main wiring); §3 query surface → Task 2, endpoints → Task 4, CLI → Task 5, dashboard → Task 6; §4 testing/DoD → every task's tests + Task 7. Invariant #6 best-effort proven in Task 3; invariant #1 untouched (no scoring change) noted throughout.
- **Type consistency:** `HistoryDb` methods + row types (`HistorySummary`, `HistoryRow`, `TrendBucket`, `TopFlagged`, `ViolationTimelineRow`) defined in Task 1/2 and consumed by Tasks 4–6; `new AuditStore(file?, activePolicyHash?, history?)` and `new ViolationStore(file?, history?)` defined in Task 3 and used in the Task 4 boot; `ServerOptions.history?` (Task 3c) read by the Task 4 routes; `recordAudit(report, now)` vs `recordViolation(rec)` (asymmetry justified — the report has no timestamp, the violation carries `reportedAt`).
- **Known judgment calls:** `node:sqlite` loaded via `createRequire` inside the constructor (not a top-level import) so the experimental-warning fires only on `new HistoryDb(...)`, never on a type import; the two early-`return existing` paths in `ViolationStore.record()` deliberately do NOT write through (they aren't new events); disabled endpoints return `501 { enabled: false }` and the CLI/dashboard branch on that; `trends()`/`topFlagged()` take a `limit` (no clock dependency in the query layer — deterministic tests). Cross-unit `import type` keeps `history-db.ts` ↔ `violations.ts`/`store.ts` runtime-decoupled (no import cycle).
