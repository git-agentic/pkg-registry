# ADR-0037: Resource robustness — caps, coalescing, and opt-in rate limiting

Date: 2026-07-09
Status: Accepted

## Context

An external security audit flagged that several open endpoints and upstream
fetches can be driven to do unbounded expensive work: `/-/audit-tree` accepts
arbitrarily many coordinates and fans out audits, each of which fully buffers a
tarball (and packument/attestations) in memory; concurrent uncached requests
for the same package each run the whole fetch/extract/score pipeline (cache
stampede); and no in-process throttle protects the expensive read endpoints.

## Decision

Four bounded-work changes, all under this ADR:

1. **Audit-tree caps + dedupe.** `/-/audit-tree` dedupes coordinates by
   `name@version` before fan-out (deterministic audit ⇒ behavior-neutral),
   audits each distinct coordinate once, and re-expands rows to one per
   requested coordinate in request order. If the distinct count exceeds
   `SENTINEL_MAX_TREE_PACKAGES` (default 5000), it returns 413 — no silent
   truncation. Dedupe keys on `name@version` only, not integrity: if a single
   request carries two entries with the same `name@version` but different
   claimed integrity, only the first entry's integrity is checked and the
   second silently inherits its row — a well-formed lockfile never emits two
   different integrities for one `name@version`, so this is accepted as a
   non-issue rather than fixed.
2. **Streamed byte caps.** A shared byte-counting reader replaces unbounded
   `arrayBuffer()`/`json()` reads in `NpmUpstream`: it rejects up front if
   content-length exceeds the cap and aborts mid-stream if the running total
   does. `SENTINEL_MAX_TARBALL_BYTES` (default 256 MB) bounds tarballs;
   `SENTINEL_MAX_PACKUMENT_BYTES` (default 128 MB, a deliberately generous DoS
   backstop) bounds packument/attestations. Over-cap is a 502 (or a null
   attestation, preserving fail-open).
3. **Request coalescing.** An in-flight `name@version` map lets concurrent
   uncached public audits share one pipeline; the entry clears on settle so a
   failure isn't cached. The integrity hash stays the durable cache key
   (invariant #4); the map is transient concurrency dedupe only.
4. **Opt-in rate limiting.** A pure in-house token bucket (injectable clock,
   keyed by socket remote address) throttles `POST /-/audit-tree`,
   `GET /-/explain/*`, and `POST /-/policy/preview` when
   `SENTINEL_RATE_LIMIT_RPM` is set; over-limit ⇒ 429 + Retry-After. The
   install-gate paths are never limited — coalescing and the integrity cache
   already make them cheap, and throttling installs would break the
   transparent-proxy promise.

All four env vars parse fail-closed at startup (malformed ⇒ FATAL).

## Alternatives considered

- **Auth on the expensive reads**: rejected — contradicts ADR-0025's
  reads-stay-open boundary. Rate limiting throttles without gating.
- **Truncate-and-warn oversized trees**: rejected — a silent under-audit reads
  as "clean"; the repo's no-silent-caps principle prefers a hard 413.
- **`express-rate-limit` dependency**: rejected — non-injectable clock (breaks
  deterministic tests) and store abstractions we don't need for a single-process
  in-memory limiter. A ~40-line token bucket keeps the zero-new-dep posture.
- **`X-Forwarded-For` keying**: rejected for now — spoofable without a
  trusted-proxy config; socket address is the safe default. An XFF-aware mode
  can come later.

## Consequences

- Memory per fetch is bounded by the byte caps; a hostile or accidental giant
  tarball is a 502, not an OOM.
- A monorepo whose distinct-package count exceeds the tree cap gets an
  actionable 413; the operator raises the env var.
- Shared network deployments should still front the proxy with infra rate
  limiting — the in-process limiter is a backstop, not a replacement.
- Scoring, caching semantics, and packument transparency are unchanged
  (invariants #1–#6).
