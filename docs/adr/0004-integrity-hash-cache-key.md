# ADR-0004: Key the verdict cache on the tarball integrity hash

**Status:** Accepted
**Date:** 2026-06-24
**Deciders:** Founder/Eng
**Phase:** 1

## Context

The synchronous gate (ADR-0003) must be cheap in steady state, which means caching
verdicts. Choosing the cache key is a correctness decision, not just performance:
if the key can collide with changed content, we can serve a stale "allow" for bytes
that have actually changed — a security hole. npm package *versions* are nominally
immutable, but operational reality includes re-publishes, registry mirrors that
differ, and the general principle that a security cache must key on *what was
actually scanned*, not on a label.

## Decision

The cache key is the tarball's **Subresource Integrity hash**
(`sha512-…`), taken from the packument `dist.integrity` (or computed from the bytes
when absent). The logical identity is `(name, version, integrity)`. A published
tarball cannot change its bytes without changing this hash, so a cached audit keyed
on integrity is always valid for exactly the bytes it scored. This maps directly
onto the future persistence layer: `audits(name, version, integrity PK, report)`.

## Options Considered

### Option A: Key on integrity hash (chosen)
**Pros:** Content-addressed — impossible to serve a stale verdict for changed bytes;
survives re-publishes (new bytes ⇒ new hash ⇒ fresh audit); trivially correct
across mirrors; doubles as the DB primary key.
**Cons:** Slightly more bookkeeping (must obtain/compute the hash); cache misses on
any byte change (which is the correct, safe behavior).

### Option B: Key on `(name, version)`
**Pros:** Simplest; one entry per release.
**Cons:** Treats the version label as immutable truth. A re-publish or a tampered
mirror with the same version string would hit a stale "allow." Unsafe for a security
cache. Rejected.

### Option C: Key on `(name, version)` with a short TTL
**Pros:** Bounds staleness.
**Cons:** Still serves wrong verdicts within the TTL; picks an arbitrary
safety/perf knob to paper over a wrong key. Rejected.

## Trade-off Analysis

This is a case where the "obvious" key (name+version) is subtly unsafe and the
content-addressed key is both safer *and* more useful (it's the natural DB PK and is
mirror-agnostic). The only cost — recomputing on byte changes — is precisely the
behavior we want from a security cache.

## Consequences

- **Easier:** correctness by construction; the in-memory cache and the eventual
  Postgres table share one immutable key; horizontal scaling is just a shared store.
- **Harder:** we must always have the integrity value (fetch from packument or hash
  the bytes); cannot "warm" a cache by version alone.
- **Revisit:** if we add per-enterprise policy (ADR-0012), the cached *verdict* may
  need to include a policy fingerprint in the key, since the same bytes can yield
  different verdicts under different policies. The *findings* remain integrity-keyed.

## Action Items
1. [x] `AuditStore` keyed by integrity; falls back to `name@version` only when no hash exists.
2. [ ] When policy becomes per-enterprise, extend the verdict key to `(integrity, policyHash)`.
