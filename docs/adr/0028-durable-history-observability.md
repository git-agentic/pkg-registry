# ADR-0028: Durable audit history + observability (opt-in `node:sqlite`)

**Status:** Accepted (Phase 15)
**Date:** 2026-07-08

## Context

Every audit and every runtime violation Sentinel produces has, through
Phase 14, lived in two places: the in-memory `AuditStore`/`ViolationStore`
hot caches the request path reads from, and (for audits) an O(n)-rewrite
JSON file on disk for restart survival. Neither is queryable. There is no
way to ask "how many packages did we block this week", "which packages
trip the most warnings", or "show me the violation timeline" without
grepping a JSON blob by hand — no trend, no aggregate, no durable
audit-trail an operator could hand to a security review. ADR-0004 keyed
the verdict cache on `dist.integrity` and explicitly anticipated this gap:
its own text names a future `audits(...)` table keyed the same way as the
natural next step. Phase 15 is that table, plus a matching durable stream
for Phase 10's runtime violations and three read endpoints, a CLI surface,
and a dashboard section on top.

## Decision

- **`HistoryDb`** (`packages/proxy/src/history-db.ts`) wraps the **built-in
  `node:sqlite`** — probed working unflagged on Node 24, zero new
  dependency. It is loaded via `createRequire` **inside the constructor**,
  not a top-level import, so importing `history-db.ts` (e.g. for its
  exported types) never fires `node:sqlite`'s experimental warning; only
  `new HistoryDb(path)` does.
- **Opt-in via `SENTINEL_HISTORY_DB=<path>`.** `index.ts`'s `main()`
  constructs a `HistoryDb` only when the env var is set and threads it into
  `AuditStore`, `ViolationStore`, and `createServer`'s `ServerOptions`.
  Unset (the default) ⇒ no `HistoryDb` is ever constructed, `node:sqlite`
  is never imported, and every existing code path — request handling,
  scoring, the JSON-file cache, all ~400 pre-Phase-15 tests — is byte-for-
  byte what it was before this phase.
- **Additive write-through beside the existing hot cache**, not a
  replacement. `AuditStore.put(report, history?)` and
  `ViolationStore.record(rec, history?)` each gained an optional trailing
  `history` parameter; when present, the same in-memory write that already
  happens also calls `history.recordAudit(report, now)` or
  `history.recordViolation(rec)`. The in-memory hot cache the request path
  reads from is untouched — `HistoryDb` is purely a second, durable
  destination for the same events.
- **Two tables, two write disciplines.** `audit_events` is keyed on
  `integrity` (`PRIMARY KEY`) with an `INSERT ... ON CONFLICT(integrity) DO
  NOTHING` — a tarball is immutable (ADR-0004), so the *first* time an
  integrity hash is audited is recorded and re-audits of the same tarball
  are silently deduplicated, never overwritten. `violation_events` is
  `AUTOINCREMENT`-keyed and strictly append-only — every reported violation
  is its own row, because a package can be flagged more than once and each
  occurrence is a distinct event worth keeping. `audit_events` stores the
  full `report_json` alongside denormalized columns (`verdict`, `score`,
  `top_finding`, `signature`, `provenance`, `audited_at`) so the query
  surface below never has to re-parse JSON to aggregate.
- **Query surface** on `HistoryDb`: `summary()` (verdict/signature/
  provenance/violation/quarantine counts), `history({verdict, name, limit,
  offset})` (paginated, filterable audit rows), `trends({limit})`
  (chronological per-day allow/warn/block buckets, last N days),
  `topFlagged({limit})` (packages ranked by warn+block count), and
  `violationTimeline({limit})` (most-recent-first violation stream with
  quarantine status).
- **Three open, un-role-gated read routes** on the proxy:
  `GET /-/metrics` (`{summary, trends, topFlagged}`), `GET /-/history`
  (`?verdict=&name=&limit=&offset=` → `{history}`), and
  `GET /-/violations/timeline` (`{timeline}`). They join the rest of the
  read surface Phase 12's `makeAuthz` leaves open (only the six mutating
  routes are role-gated) — read access to your own audit history isn't a
  privileged operation. When no `HistoryDb` is configured, all three
  return `501 { enabled: false }` rather than an empty body, so a caller
  can tell "disabled" apart from "no data yet".
- **CLI**: `sentinel stats` (renders `summary()` + `trends()` +
  `topFlagged()`) and `sentinel history [--verdict --name --limit]` (renders
  `history()`). Both print a plain "history not enabled — set
  SENTINEL_HISTORY_DB on the proxy" line on a `501`.
- **Dashboard**: a new "Observability" section on `packages/proxy/public/
  index.html` — an inline-SVG verdict trend bar chart, a top-flagged list,
  and a violation timeline — polled the same way the rest of the dashboard
  polls, all fetched fields passed through the existing `esc()` helper, and
  degrading to a plain note when the endpoints 501. No new JS dependency,
  no external asset.

## Determinism (invariant #1 untouched)

`HistoryDb` only ever *stores* and *reads back* events the deterministic
scoring path already produced — it never participates in producing a
verdict. `recordAudit(report, now)` takes `now` as a caller-supplied string
rather than reading the clock itself, the same injected-clock discipline
ADR-0022 established for `trust-root-stale` and ADR-0027 continued for
`toCycloneDX`; the one call site (`AuditStore.put`) passes
`new Date().toISOString()`. `trends()`/`topFlagged()` take only a `limit` —
no clock dependency in the query layer, so their tests are deterministic
given a fixed set of inserted rows. `runAudit`, `score()`, and the rule set
are untouched by this phase; the pinned `scoring is deterministic across
runs` test exercises none of `history-db.ts`.

## Consequences

- **Zero new dependencies.** `node:sqlite` is built into Node; no
  `package.json` change.
- **Node 22 needs `--experimental-sqlite`**; Node 24 does not. Because
  `HistoryDb` is opt-in and lazily loaded, this doesn't move the `>=22`
  floor — an operator on Node 22 who never sets `SENTINEL_HISTORY_DB` is
  completely unaffected, and one who does gets an actionable Node error to
  add the flag rather than a broken default install.
- **Write-through is best-effort (invariant #6).** Both call sites wrap the
  `history?.recordAudit(...)`/`recordViolation(...)` call in the same
  try/catch discipline the rest of the store already uses — a `HistoryDb`
  failure (disk full, corrupt file, locked DB) never breaks the audit
  gate or the in-memory record; it only means that one event is missing
  from durable history.
- **SQLite is single-node.** `HistoryDb` opens a local file; there is no
  multi-proxy-instance sharing, replication, or concurrent-writer story.
  Fine for the current single-proxy deployment model; not a fit for a
  horizontally-scaled proxy fleet without further work.
- **Unbounded growth, no retention.** Both tables only ever grow — there is
  no pruning, TTL, or size cap yet. A long-lived proxy with
  `SENTINEL_HISTORY_DB` set will accumulate rows indefinitely.

## Deferred

- **Cache rehydration from `report_json`.** `audit_events.report_json`
  holds the full report, but nothing reads it back to warm the in-memory
  hot cache on restart — the JSON-file cache remains the sole rehydration
  path.
- **Removing the JSON-file cache.** `HistoryDb` is additive; the existing
  O(n)-rewrite JSON file is untouched and still does its original job.
- **An approvals stream.** Audits and violations are durable; approval
  grants/revocations are not (yet) mirrored into `HistoryDb`.
- **Postgres / a shared store** for a multi-instance proxy deployment.
- **Retention / pruning** — no TTL, row cap, or archival policy.
- **Auth on the read endpoints.** `/-/metrics`, `/-/history`, and
  `/-/violations/timeline` are open like the rest of the read surface;
  scoping them to a role (the way the six mutating routes are scoped) is
  left for a later phase if audit history turns out to need
  confidentiality beyond what the rest of the read surface has.

## Rejected

- **`better-sqlite3` (native addon)** — rejected: it's a compiled
  dependency with prebuilt-binary/Node-ABI concerns across the platforms
  this repo already supports (macOS Seatbelt, Linux bwrap, CI). The
  built-in `node:sqlite` gives the same synchronous, transactional query
  surface with zero install-time compilation and zero new
  `package.json` entry.
- **NDJSON append-log without SQL aggregates** — rejected: `trends()`,
  `topFlagged()`, and filtered `history()` are aggregate/group-by queries.
  An append-only NDJSON file would need every one of those computed by
  scanning and re-parsing the whole file on each request; SQLite's indexes
  (`idx_audit_at`, `idx_audit_verdict`, `idx_viol_at`) and `GROUP BY` do
  that in the database instead, at no added dependency cost over
  `node:sqlite` already being on the table.

Extends ADR-0004 (integrity-hash cache key — `audit_events` is
integrity-keyed with upsert-ignore semantics, the `audits(...)` table
ADR-0004 anticipated) and ADR-0023 (runtime-violation telemetry —
`violation_events` gives the sandbox-as-sensor stream a durable,
queryable home instead of only the in-memory `ViolationStore`).
Supersedes nothing.
