# ADR-0005: Transparent packument pass-through — rewrite only `dist.tarball`

**Status:** Accepted
**Date:** 2026-06-24
**Deciders:** Founder/Eng
**Phase:** 1

## Context

To audit every tarball we must guarantee that every tarball fetch flows through the
proxy. The packument (`GET /:pkg`) is the document npm uses to resolve versions,
dependencies, peer dependencies, engines, dist-tags, and more. It is large,
evolving, and full of fields whose semantics we don't want to own. If we synthesize
or strip fields, we risk breaking resolution in subtle, version-specific ways.

We need interception without becoming a (partial, buggy) reimplementation of npm's
resolution semantics.

## Decision

Pass the upstream packument through **verbatim**, mutating exactly one field per
version: rewrite `dist.tarball` to point back at the proxy
(`{base}/{pkg}/-/{name}-{version}.tgz`). Everything else — dependencies, peerDeps,
engines, dist-tags, deprecations, `dist.integrity`, signatures — is forwarded
unchanged. Because resolution stays npm's job and only the fetch URL is redirected,
any client (npm, yarn, pnpm, bun, npx) works unmodified, and **every** tarball in
the resolved tree, including transitive deps, is fetched through us.

## Options Considered

### Option A: Pass through, rewrite only `dist.tarball` (chosen)
**Pros:** Resolution correctness is npm's, not ours; forward-compatible with new
packument fields; minimal surface; transitive coverage for free.
**Cons:** We forward fields we don't understand (acceptable — they're for the
client); the rewrite must handle scoped names and odd tarball filenames.

### Option B: Synthesize a minimal packument from normalized metadata
**Pros:** Smaller, fully-understood documents; uniform across upstreams.
**Cons:** Any omitted field (a dependency, a peerDep range, an `os`/`cpu`
constraint) silently breaks resolution for some packages; we'd be chasing npm's
schema forever. We use a synthesized doc *only* for local fixtures, never on the npm
path. Rejected for production.

### Option C: Rewrite the tarball host at the HTTP layer (URL substitution proxy)
**Pros:** No JSON parsing.
**Cons:** Fragile (CDN hostnames, redirects, query params) and can't attach
verdict metadata or apply policy. Rejected.

## Trade-off Analysis

The guiding principle is **own the choke point, not the semantics**. Redirecting
just the tarball URL gives us 100% interception while delegating the genuinely hard
and fast-moving part (resolution) to the system that defines it. The cost is purely
cosmetic (forwarding opaque fields); the benefit is robustness against npm's
evolving schema and free transitive coverage.

## Consequences

- **Easier:** correctness across all clients and package shapes; new registry
  features don't break us; transitive deps are covered automatically.
- **Harder:** we must faithfully reconstruct tarball filenames (scoped packages,
  prerelease tags) to round-trip the rewrite; we trust upstream field correctness.
- **Revisit:** Phase 2 private-namespace override (ADR-0010) deliberately *breaks*
  transparency for chosen names — that is an intentional, scoped exception layered
  on top of this default.

## Action Items
1. [x] Rewrite `dist.tarball` per version; forward the rest of the document.
2. [x] Handle scoped names + version extraction from tarball filenames.
3. [ ] Add a contract test against a few real packuments (scoped, peerDeps, deprecated) to guard transparency.
