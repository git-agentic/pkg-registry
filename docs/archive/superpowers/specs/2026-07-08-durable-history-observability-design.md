# Phase 15 — Durable Audit History + Observability

**Date:** 2026-07-08
**Status:** Approved design, pre-implementation
**Extends:** ADR-0004 (integrity-hash cache key — the `audit_events` table keys on
integrity, the "future persistence layer" ADR-0004 explicitly anticipates), ADR-0023
(runtime-violation sensor — violations become a durable event stream), ADR-0012-era
authz split (the new read endpoints stay open). Supersedes nothing.

## Problem

Every signal Sentinel produces — verdicts, scores, findings, signature/provenance
status, runtime violations, quarantines — lives only in memory (a `Map`) plus, for
audits, a single flat JSON file rewritten in full on every `put()`. There is no
durable, queryable history, no metrics/trends, no time-series, and no compliance
audit trail. `stats()` is a trivial four-count; `recent(50)` is the only "history"
and it is capped and in-memory. A deployed security product must answer "what did we
flag/block over time, which packages keep tripping, what got quarantined" — and today
it cannot. ADR-0004 already anticipates a durable `audits(...)` table; this phase
delivers the observability layer on top of the two richest event streams (audits and
runtime violations/quarantines).

## Decisions (brainstorm outcomes)

1. **Storage engine: the built-in `node:sqlite`** (`DatabaseSync`) — probed working on
   this host **without a flag**. Zero new runtime dependency, synchronous (matches the
   existing sync store), no native addon. Rejected: `better-sqlite3` (a native addon +
   build step) and an append-only NDJSON log (no cheap `GROUP BY` for trends).
2. **Opt-in via config**, not always-on. `SENTINEL_HISTORY_DB=<path>` (or a constructor
   arg) enables it. Unconfigured ⇒ no `HistoryDb`, `node:sqlite` never imported, exactly
   today's behavior. This keeps the `engines.node >=22` floor safe (Node 22 needs
   `--experimental-sqlite`, which we never force) and leaves all ~400 existing tests
   untouched.
3. **Additive, write-through** — the in-memory `Map` stays the hot verdict cache
   (invariant #4 untouched); `HistoryDb` is a durable analytics store *beside* it.
   `AuditStore.put()` / `ViolationStore.record()` write through best-effort. The existing
   JSON cache-persistence path is left as-is (rehydrating the cache from `HistoryDb` is
   deferred — the schema stores `report_json` to enable it later).
4. **Scope: audits + violations/quarantines** — the two event streams, in one SQLite
   file, for a unified operational timeline. Approvals deferred.

## Section 1 — Architecture: an opt-in, write-through `HistoryDb`

New isolated unit `packages/proxy/src/history-db.ts`, backed by `node:sqlite`
(`DatabaseSync`), imported **lazily inside the unit** so its experimental-warning never
fires unless configured.

- **Not configured (default + every existing test):** no `HistoryDb` constructed;
  `Map` + optional JSON cache behave exactly as today; Node-22-safe.
- **Configured (Node 24, or Node 22 + `--experimental-sqlite`):** a durable SQLite file
  is opened + migrated; `AuditStore.put()` and `ViolationStore.record()` write through.

`HistoryDb` responsibilities: constructor opens/migrates the schema; `recordAudit(report,
now)` / `recordViolation(rec, now)` write; query methods read. `AuditStore` and
`ViolationStore` each gain an optional `history?: HistoryDb` dependency — absent ⇒
unchanged behavior. `createServer(...)` wires a `HistoryDb` into both stores when the env
var is set; `main()` reads `SENTINEL_HISTORY_DB`.

## Section 2 — Schema & the write path

One SQLite file, two tables — indexed projection columns for fast aggregates **plus** the
full JSON for detail/future-rehydration:

```sql
CREATE TABLE IF NOT EXISTS audit_events (
  integrity   TEXT PRIMARY KEY,          -- immutable audit identity (invariant #4)
  name        TEXT NOT NULL,
  version     TEXT NOT NULL,
  verdict     TEXT NOT NULL,             -- allow | warn | block
  score       INTEGER NOT NULL,
  top_finding TEXT,
  signature   TEXT,                      -- verified | invalid | unsigned | unknown
  provenance  TEXT,                      -- verified | invalid | absent | unknown
  report_json TEXT NOT NULL,             -- full AuditReport (detail + future rehydration)
  audited_at  TEXT NOT NULL              -- ISO, first-seen
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_events(audited_at);
CREATE INDEX IF NOT EXISTS idx_audit_verdict ON audit_events(verdict);

CREATE TABLE IF NOT EXISTS violation_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  integrity   TEXT NOT NULL,
  name        TEXT, version TEXT,
  status      TEXT NOT NULL,             -- confirmed | suspected (the violation confidence)
  quarantined INTEGER NOT NULL,          -- 0/1 (rec.quarantined)
  detail      TEXT,                      -- the classified violation reason
  recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_viol_at ON violation_events(recorded_at);
```

- **Audits** are written **upsert-ignore** (`INSERT … ON CONFLICT(integrity) DO NOTHING`)
  — one row per immutable audit, `audited_at` = first-seen. A given integrity's verdict is
  deterministic, so recording it once is the meaningful history (no duplicate bloat); trends
  read as "new packages entering the system per day." Columns are projected from the report:
  `meta.integrity`, `meta.name`, `meta.version`, `verdict`, `score`,
  `findings[0]?.message ?? null`, `meta.signature`, `meta.provenance`, `JSON.stringify(report)`.
- **Violations** are **append-only** (one row per `record()` call) so a suspected→confirmed
  progression keeps both rows — the timeline must preserve it. Columns from the
  `ViolationRecord`: `integrity`, `name`, `version`, `confidence` (→ `status`),
  `quarantined`, the violation reason (→ `detail`), `reportedAt` (→ `recorded_at`).
- **Timestamps injected** — `recordAudit(report, now)` / `recordViolation(rec, now)` take an
  ISO `now`; the server passes real time, tests pass fixed values (deterministic query tests).
- **Best-effort writes** — every write-through call is wrapped so a `HistoryDb` failure is
  swallowed and never breaks the audit/violation record (invariant #6 — observability must
  never take down the gate). The store's existing behavior is the source of truth; the
  `HistoryDb` row is a side effect.

## Section 3 — Query surface, endpoints, CLI, dashboard

`HistoryDb` query methods (each a small parameterized statement):
- `summary()` → totals + verdict/signature/provenance breakdown + violation & quarantine
  counts (the durable superset of today's `stats()`).
- `history({ verdict?, name?, limit, offset })` → paginated recent audit rows.
- `trends({ sinceDays })` → `GROUP BY date(audited_at), verdict` → daily verdict counts.
- `topFlagged({ limit })` → package names most often `warn`/`block`.
- `violationTimeline({ limit })` → recent violation events.

**Endpoints** (all reads — stay open per the Phase 12 authz split): `GET /-/metrics` →
`summary()` + `trends()` + `topFlagged()`; `GET /-/history?verdict=&name=&limit=&offset=`
→ `history()`; `GET /-/violations/timeline` → `violationTimeline()`. When `HistoryDb` is not
configured, these return an explicit `{ enabled: false }` body with HTTP `501` (Not
Implemented — the feature is off, not a transient error) — never a silent empty result that
reads as "no history." The CLI keys off this `enabled: false` to print its enable hint.

**CLI:** `sentinel stats` (renders `summary()` + a compact trend sparkline + top-flagged)
and `sentinel history [--verdict block] [--name <pkg>] [--limit N]` (a table). Both hit the
new endpoints; the disabled-path prints a clear "history not enabled (set SENTINEL_HISTORY_DB)"
message. Async `execFile` in e2e (the in-process-proxy deadlock rule).

**Dashboard:** the served dashboard gains an "Observability" section — a small **inline-SVG**
bar chart of the daily verdict trend (no chart library / external asset — CSP &
proxy-transparency safe), the top-flagged list, and the violation timeline. Degrades to a
"history not enabled" note when `HistoryDb` is off.

## Section 4 — Testing & Definition of Done

*Testing (hermetic, deterministic):*
- **`HistoryDb` unit tests** — `new HistoryDb(":memory:")`; record synthetic `AuditReport`s
  and violations with **fixed injected `now` across several days**; assert `summary()`
  counts, `history()` filter/pagination, `trends()` daily buckets, `topFlagged()` ordering,
  `violationTimeline()`. Prove upsert-ignore (re-recording an integrity neither duplicates
  nor moves `audited_at`) and append-only violations (suspected→confirmed keeps both rows).
- **Write-through tests** — an `AuditStore` / `ViolationStore` given a `:memory:` `HistoryDb`:
  a `put()` / `record()` lands a row; **without** a `HistoryDb` the stores behave exactly as
  today (regression guard for the default path); a `HistoryDb` whose write throws is swallowed
  and the store record still succeeds (invariant #6).
- **Endpoint e2e** — in-process proxy booted **with** a temp-file/`:memory:` `HistoryDb`:
  `GET /-/metrics`, `/-/history?verdict=block`, `/-/violations/timeline` return the expected
  shapes; booted **without** → the explicit disabled response.
- **CLI e2e** — `sentinel stats` / `sentinel history --verdict block` against the in-process
  proxy (async `execFile`); the disabled-path message when off.
- **Default suite untouched** — every existing test constructs stores with no `HistoryDb`, so
  `node:sqlite` is never imported and the ~400 existing tests are unchanged; the determinism
  test (invariant #1) is unaffected (storage/read tooling, not scoring).

*Definition of done:* `npm run build` clean; `npm test` green (new suites; record the count);
**zero new runtime dependencies** (`node:sqlite` is built-in); the malicious fixture still
blocked; ADR-0028 recorded; ARCHITECTURE (a new observability/`HistoryDb` section), CLAUDE
(phase summary + count + the `node:sqlite` opt-in and Node-22 `--experimental-sqlite` caveat),
and README (`SENTINEL_HISTORY_DB`, `sentinel stats`/`history`, the new endpoints, the dashboard
section) updated.

## Out of scope (deferred beyond Phase 15)

- Rehydrating the in-memory verdict cache from `HistoryDb` (the schema stores `report_json` to
  enable it; the existing JSON-file cache path is untouched this phase).
- Subsuming / removing the JSON cache-persistence file (its O(n)-rewrite is a known limitation,
  not fixed here).
- Approvals as a third event stream (audits + violations only this phase).
- A Postgres/shared-store backend for horizontal scaling (ADR-0004's longer-term note; SQLite
  is the single-node durable store now).
- Retention/rotation/pruning of history rows (unbounded growth is acceptable at this stage;
  note it).
- Auth on the read endpoints (they stay open, consistent with the Phase 12 split).

## Invariants preserved

1. **Deterministic score** — untouched; `HistoryDb` is write-through storage + reads. The
   determinism test is unaffected.
2. **LLM never scores** — untouched.
3. **Sync gate cheap** — `node:sqlite` is synchronous and the write-through is a single local
   `INSERT` off the already-computed report; no network/LLM on the request path. (Queries are
   on the separate metrics/history read endpoints, not the tarball gate.)
4. **Cache key = integrity** — `audit_events` is keyed on `integrity`; the in-memory cache is
   unchanged.
5. **Proxy transparency** — packument/tarball paths untouched; only new read endpoints added.
6. **Rules fail open / audit never crashes** — write-through is best-effort and swallowed; a
   `HistoryDb` failure never breaks an audit or a violation record.
7. **Private namespaces authoritative** — unchanged; history records whatever was audited
   through the existing routing.
