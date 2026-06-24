# ADR-0001: Enter as a transparent auditing proxy, not an npm replacement

**Status:** Accepted
**Date:** 2026-06-24
**Deciders:** Founder/Eng, Security lead
**Phase:** 1

## Context

AI agents and humans install and execute untrusted npm packages with no risk
signaling at the moment that matters — before install-time code runs. The
ecosystem has structural gaps: npm cannot reliably retract a bad release, there
are no install-time permissions, and name-squatting / dependency-confusion are
unaddressed by the registry itself.

We need a product shape that (a) delivers value on day one, (b) requires near-zero
behavior change from the people we protect, and (c) does not put us on the hook for
the availability and correctness of the entire npm registry. The constraint that
shapes everything: developers will not migrate off npm, and any friction in
`npm install` is fatal to adoption.

## Decision

Ship Phase 1 as a **transparent auditing proxy** that sits in front of
`registry.npmjs.org`. It resolves and serves real packages unchanged, but
intercepts every tarball, scores its contents, and attaches a verdict
(`allow` / `warn` / `block`) plus human-readable findings. We attach *signal*; we
do not become the source of truth for packages. This is the "Socket/Chainguard
wedge": insert a thin, transparent layer into an existing flow and monetize the
signal, then expand into policy and enforcement (Phase 2+).

## Options Considered

### Option A: Transparent auditing proxy (chosen)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low–Med — a handful of registry routes |
| Time to value | Days — works with unmodified npm clients |
| Operational risk | Med — on the resolution path, but upstream stays authoritative |
| Adoption friction | Very low — point `registry` at us |

**Pros:** No client changes; every tarball in the dependency tree flows through us;
incremental trust (start in observe mode); clean upgrade path to enforcement.
**Cons:** We sit on the install hot path (latency + availability matter); we must
faithfully mirror enough of the registry API to stay transparent.

### Option B: Full registry replacement / mirror
| Dimension | Assessment |
|-----------|------------|
| Complexity | High — full registry semantics, storage, replication |
| Time to value | Months |
| Operational risk | High — we own uptime for all installs |
| Adoption friction | High — migration, trust, completeness |

**Pros:** Total control over namespace and content; natural home for private packages.
**Cons:** Enormous surface area; we inherit npm's whole problem; adoption requires
wholesale migration. Wrong first step.

### Option C: Client-side CLI / lockfile scanner (à la `npm audit`)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low |
| Coverage | Partial — runs after resolution, easy to skip |
| Adoption friction | Low |

**Pros:** Trivial to adopt; no hot-path involvement.
**Cons:** Advisory only and bypassable; doesn't see the actual fetched bytes at
fetch time; cannot *gate* an install. Good as a complement, weak as the core wedge.

## Trade-off Analysis

The decisive factor is **enforcement leverage with minimal friction**. Only the
proxy sits at the exact choke point (the tarball fetch) where we can both observe
the real bytes and refuse to serve them, while leaving resolution to npm. A
replacement maximizes control but is the wrong-sized first bet; a client scanner
minimizes risk but can't gate. The proxy is the only option that is adoptable
today *and* upgradeable into hard enforcement later.

## Consequences

- **Easier:** zero-change adoption; transitive coverage (every tarball, not just
  top-level); a natural place to later inject private-namespace override (Phase 2).
- **Harder:** we accept hot-path responsibilities — latency, availability, and
  faithful registry transparency become hard requirements (see ADR-0003, ADR-0005).
- **Revisit:** when we add private packages and enforcement, the proxy's role grows
  from "attach signal" toward "authoritative for some names" — re-evaluate the
  transparency boundary then.

## Action Items
1. [x] Implement `GET /:pkg` (packument) and `GET /:pkg/-/:tarball` (interception).
2. [x] Default to `observe` policy; make `block` opt-in.
3. [ ] Document a managed-hosting availability target (SLA) before first paid pilot.
