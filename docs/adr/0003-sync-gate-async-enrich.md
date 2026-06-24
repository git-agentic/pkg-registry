# ADR-0003: Split the audit into a synchronous gate and an asynchronous enrich phase

**Status:** Accepted
**Date:** 2026-06-24
**Deciders:** Founder/Eng
**Phase:** 1

## Context

The proxy is on the install hot path (ADR-0001). A blocking decision must be made
before tarball bytes are served, or there is nothing to gate. But some valuable
signals are inherently slow or non-deterministic: LLM enrichment (ADR-0002),
provenance/registry-signature lookups, cross-version trend analysis, reputation
data. Putting any of those on the request path would add latency and a failure mode
that could stall — or worse, silently fail-open — every install.

## Decision

Two phases with a hard boundary:

- **Synchronous gate** — the deterministic heuristic rules run on the tarball
  request, over bytes already in memory, with no network and no LLM. This produces
  the score + verdict the client sees inline. Results are cached by integrity hash
  (ADR-0004), so steady state is a cache hit.
- **Asynchronous enrich** — LLM summary, provenance, and trend analysis run after
  the response is served, updating the stored report and the dashboard. Never on
  the request path.

**Invariant:** no network call and no LLM call may run on the request path.

## Options Considered

### Option A: Sync gate + async enrich (chosen)
| Dimension | Assessment |
|-----------|------------|
| Inline latency | Low (static analysis on in-memory bytes; cached by hash) |
| Availability | High — gate has no external dependency |
| Signal richness | High — slow signals still captured, just not inline |

**Pros:** Fast, predictable, available gate; richer context arrives shortly after
without blocking; clean failure isolation.
**Cons:** The verdict a client sees may be enriched moments later (eventual
consistency on findings, though never on the score).

### Option B: Everything synchronous (LLM + provenance inline)
**Pros:** The inline verdict is "complete."
**Cons:** Adds hundreds of ms to seconds per cold fetch; a model/provenance outage
stalls installs or forces an unsafe fail-open; cost per request balloons. Rejected.

### Option C: Everything asynchronous (serve first, audit after)
**Pros:** Zero added inline latency.
**Cons:** Can't gate — the bytes are already delivered and may have executed.
Defeats the product. Rejected.

## Trade-off Analysis

The split lets each signal run where its cost is acceptable. The gate is what makes
enforcement possible, so it must be cheap and dependency-free; enrichment is what
makes the verdict *rich*, so it can be slow and best-effort. The only thing we give
up — inline completeness of *findings* — is immaterial because the score (the
enforceable part) is final at gate time and the dangerous patterns
(install-script/exfil/obfuscation) are all statically detectable without the slow
signals.

## Consequences

- **Easier:** predictable p99 on the proxy; an LLM or provenance outage cannot
  block or unsafely unblock an install.
- **Harder:** two code paths and an enrich queue to operate; findings are
  eventually-consistent in the dashboard.
- **Revisit:** if a future signal is both fast and deterministic, it may join the
  sync gate; anything slow or networked stays async by rule.

## Action Items
1. [x] Gate runs rules over in-memory tarball bytes; cache by integrity.
2. [ ] Stand up the async enrich worker + queue (post-Phase-1 inline scope).
3. [ ] Add a metric/alert on any network call observed on the request path (guards the invariant).
