# Phase 24 — Resource robustness (ADR-0037) — design

**Date:** 2026-07-09
**Status:** Approved for planning
**Supersedes/extends:** the Phase 24 section of
`docs/superpowers/specs/2026-07-09-security-hardening-phases-design.md`
(refined against post-Phase-23 code; packument cap added).

## Context

The external security audit's medium findings all sit at the same seam: an
open endpoint or an upstream fetch can be made to do unbounded expensive work.
Phase 23 closed the trust boundary (who the proxy talks to); Phase 24 bounds
*how much work* any request can force. The design target remains a
network-deployed enterprise proxy.

Findings, verified against current `main`:

| # | Finding | Location |
|---|---------|----------|
| 5a | `/-/audit-tree` accepts unbounded coordinates, no dedupe | `packages/proxy/src/server.ts` `/-/audit-tree` route (`mapPool(coords, 8, …)`) |
| 5b | Tarball fetched with `res.arrayBuffer()`, no size cap; packument/attestations `res.json()` unbounded too | `packages/proxy/src/upstream.ts` (`fetchPinned` → `getTarball`/`getPackument`/`getAttestations`) |
| 6 | Cache stampede — integrity cache checked only after fetch+hash | `packages/proxy/src/server.ts` `auditVersion` (`store.get(actualIntegrity)` after `getTarball`) |
| — | No in-process rate limiting on expensive open endpoints | `packages/proxy/src/server.ts` express chain |

All four ship in one phase under **ADR-0037** — they share one theme (bound
expensive work) and splitting adds more cycle overhead than the size warrants.
Each is an independently reviewable task.

**Invariants preserved throughout:** scoring is untouched (#1–#2); the
integrity hash stays the durable cache key (#4); packument passthrough still
rewrites only `dist.tarball` (#5); rules still fail open (#6). New env vars all
follow the Phase 21–23 fail-closed startup posture (malformed ⇒ FATAL, same as
`SENTINEL_AUTH_PUBKEY`).

---

## 1. Audit-tree caps + dedupe

**File:** `packages/proxy/src/server.ts` (`/-/audit-tree` route).

- **Dedupe first.** Collapse `coords` to distinct `name@version` before any
  work. Fan the *distinct* set through the existing `mapPool(…, 8)`, then
  re-expand the audited rows back to the caller's original order and
  multiplicity, so the response still carries one row per requested package.
  Dedupe is behavior-neutral because `auditVersion` is deterministic.
- **Cap after dedupe.** If the distinct count exceeds
  `SENTINEL_MAX_TREE_PACKAGES` (default **5000** — above real-world monorepos
  at ~3–4k distinct packages), return **413** with a message stating the
  distinct count and the limit. No silent truncation (repo's no-silent-caps
  principle): the operator raises the env var if they legitimately exceed it.
- `mapPool` concurrency (8) unchanged. Env var parsed fail-closed at startup;
  unset ⇒ 5000.

Rationale for hard-413-after-dedupe over truncate: the Phase 17 CI action
(`sentinel-ci`) posts the caller's whole lockfile, and a silent under-audit
would read as "clean" when it wasn't. Dedupe first means a monorepo's real
distinct-package count (far below its lockfile line count) rarely approaches
the cap.

### Tests (hermetic)

- N duplicate coordinates ⇒ one `auditVersion` per distinct `name@version`
  (instrumented fixture upstream counting calls), N rows in the response in
  request order.
- Over-cap distinct set ⇒ 413 naming count + limit; at-cap ⇒ 200.
- `SENTINEL_MAX_TREE_PACKAGES` malformed ⇒ FATAL at startup.

---

## 2. Streamed byte caps (tarball + packument)

**File:** `packages/proxy/src/upstream.ts` (`NpmUpstream` only —
`LocalFixtureUpstream` is disk-backed and untouched).

A shared streamed **byte-counting reader** replaces the unbounded
`res.arrayBuffer()` / `res.json()` reads: it consumes the response body as a
stream, sums chunk lengths, and throws the moment the running total exceeds a
supplied cap. Two enforcement layers wherever it's used:

1. **Early reject:** if the response `content-length` header already exceeds
   the cap, throw before reading the body.
2. **Streamed count:** content-length can lie or be absent, so the reader also
   aborts mid-stream past the cap.

Two independent caps (JSON metadata and tarballs have very different sizes):

- **`SENTINEL_MAX_TARBALL_BYTES`** (default **256 MB** — generous headroom over
  the largest real npm tarballs, ~100 MB). Governs `getTarball`. Over-limit ⇒
  `HttpError(502)`: an `error` row in a tree audit (ADR-0020 fail-open
  aggregation unchanged), a 502 on the gate path — never an OOM. The full
  tarball still lands in one `Buffer` for hashing + extraction (inherent to the
  integrity cache and static analysis), but now bounded by the cap.
- **`SENTINEL_MAX_PACKUMENT_BYTES`** (default **128 MB** — a pure DoS backstop,
  deliberately generous because high-version-count packuments like
  `@types/node` / `aws-sdk` are genuinely large, and under-capping would break
  resolution, invariant #5). Governs `getPackument` and `getAttestations`.
  `getPackument` over-cap throws (breaks that install like any upstream
  failure); `getAttestations` over-cap is caught by its existing try/catch and
  becomes `null` (fail-open to "unknown", contract unchanged).

Both env vars parsed fail-closed at startup; unset ⇒ defaults.

### Tests (hermetic)

- Local registry serves a tarball whose streamed size exceeds a low
  test-configured cap ⇒ 502 / error row, no crash; body abort verified (server
  stops reading — assert via a body larger than the cap that would OOM if fully
  buffered at a tiny cap).
- `content-length` over cap ⇒ early reject without reading body.
- Packument over cap ⇒ `getPackument` throws; attestations over cap ⇒ `null`.
- Both env vars malformed ⇒ FATAL.

---

## 3. Request coalescing (stampede fix)

**File:** `packages/proxy/src/server.ts` (inside `createServer`, around
`auditVersion`).

An in-flight `Map<string, Promise<{ report: AuditReport; tarball: Buffer }>>`
keyed by `name@version`, wrapping the **public uncached path** of
`auditVersion`:

- The `isClaimed` private branch short-circuits with no network — nothing to
  coalesce.
- A `providedTarball` caller already holds the bytes — skips the map.
- A request that finds an in-flight promise for its `name@version` awaits it
  instead of launching its own fetch/extract/score.
- The entry is deleted on settle (resolve **and** reject), so a failure is
  never cached — the next request retries cleanly.

The integrity-keyed `store` remains the durable cache (invariant #4); this map
is transient concurrency dedupe, living and dying within the overlapping-request
window.

### Tests (hermetic)

- k parallel requests for one uncached `name@version` ⇒ exactly one
  `getTarball` call (instrumented fixture upstream), all k get the same report.
- A rejected in-flight audit ⇒ the entry is cleared; a subsequent request
  retries (and succeeds if the transient cause is gone).

---

## 4. Opt-in rate limiting

**File:** new `packages/proxy/src/rate-limit.ts` (pure token-bucket) +
wiring in `server.ts`.

- **In-house token bucket**, zero new dependencies (matches the repo's
  dependency-minimal, pure-helper posture — like `net-config.ts`).
- **Keyed by socket remote address** (`req.socket.remoteAddress`) — not the
  spoofable `X-Forwarded-For`. An XFF-trusting mode behind a configured trusted
  proxy can come later.
- **Injectable clock** — deterministic tests, no wall-clock near scoring.
- **`SENTINEL_RATE_LIMIT_RPM=<n>`** opts in; unset ⇒ off (zero behavior
  change); malformed ⇒ FATAL at startup. Over-limit ⇒ **429** with
  `Retry-After`.
- **Applied to expensive open endpoints only:** `POST /-/audit-tree`,
  `GET /-/explain/*`, `POST /-/policy/preview`.
- **Install-gate paths (packument/tarball) are never rate-limited** —
  coalescing + the integrity cache already make them cheap, and throttling
  installs would break the transparent-proxy promise.
- **Bounded memory:** buckets held in a `Map` keyed by address; an idle-eviction
  step drops buckets untouched longer than their refill window, so many
  distinct source IPs can't grow the map unbounded.

### Tests (hermetic)

- n+1th request within the window ⇒ 429 with `Retry-After` (injected clock);
  after the refill interval ⇒ admitted again.
- Unset `SENTINEL_RATE_LIMIT_RPM` ⇒ unlimited (no 429 ever).
- Two distinct remote addresses have independent buckets.
- Gate paths (tarball/packument) never 429 even over the limit.
- `SENTINEL_RATE_LIMIT_RPM` malformed ⇒ FATAL.

---

## ADR / documentation impact

- **ADR-0037** — resource robustness: tree caps + dedupe, streamed byte caps
  (tarball + packument), request coalescing, opt-in rate limiting. Rejected
  alternatives: **auth on reads** (contradicts ADR-0025's reads-stay-open);
  **truncate-and-warn tree** (contradicts no-silent-caps); **express-rate-limit
  dependency** (non-injectable clock, unneeded store abstractions). Notes that
  shared deployments should still front the proxy with infra rate limiting.
- `ARCHITECTURE.md` — Phase 24 section (§3.24) in the established per-phase
  style.
- `CLAUDE.md` — Phase 24 paragraph after Phase 23's; the four new env vars in
  the Stack section (`SENTINEL_MAX_TREE_PACKAGES`, `SENTINEL_MAX_TARBALL_BYTES`,
  `SENTINEL_MAX_PACKUMENT_BYTES`, `SENTINEL_RATE_LIMIT_RPM`); test-count comment
  updated with the real number from the full run.
- `README.md` — env-var table rows for all new vars.
- `docs/adr/README.md` — ADR-0037 index entry.

## Explicitly out of scope

- Auth or rate limits on cheap read endpoints (`/-/metrics`, `/-/history`, …).
- XFF-aware rate-limit keying (needs a trusted-proxy config; later if asked).
- Disk-spooled tarball processing (the byte cap bounds memory; streaming
  extraction is a separate perf project).
- The sandbox default-deny rework (Phase 25 / ADR-0038).
