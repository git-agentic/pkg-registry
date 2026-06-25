# ADR-0010: Private-namespace override to structurally block dependency confusion

**Status:** Accepted
**Date:** 2026-06-24
**Deciders:** Founder/Eng, Security lead, Design partner (enterprise)
**Phase:** 2

## Context

Dependency confusion (Alex Birsan, 2021) exploits resolution ambiguity: if an
internal package name (`@acme/payments`, or an unscoped `acme-config`) also exists
on public npm, a misconfigured client — or a deliberately higher public version —
can pull the **attacker's** public package instead of the company's private one,
executing attacker code inside the org. Mitigations today (scoped registries,
`.npmrc` precedence, version pinning) are configuration the user must get exactly
right, everywhere, forever. We want to remove the ambiguity *structurally* at the
proxy, which already sits on the resolution path (ADR-0001/0005/0007).

## Decision

Introduce an enterprise-configured **private namespace registry**. For any name
claimed as private (by exact name or scope/prefix pattern), the proxy serves the
private package **authoritatively and never consults public npm for that name** —
the private package always wins a public collision, regardless of public version
numbers. Public resolution continues transparently for all other names. This is a
deliberate, scoped exception to the transparency default in ADR-0005: for *claimed*
names we are the source of truth; for everything else we still pass through.

## Options Considered

### Option A: Proxy-enforced private-namespace override (chosen)
| Dimension | Assessment |
|-----------|------------|
| Attack elimination | Structural — collision is impossible for claimed names |
| User config burden | Low — declare claims once, centrally |
| Fits existing arch | Yes — extends the resolution choke point |

**Pros:** Removes the ambiguity at the one place all resolution flows through;
central policy instead of per-repo `.npmrc` discipline; works for all clients;
covers transitive resolution.
**Cons:** We become authoritative for claimed names (availability + correctness
matter); requires private package hosting/upload or federation with an existing
internal registry; namespace-claim management and verification become a feature.

### Option B: Rely on scoped registries + `.npmrc` precedence (status quo)
**Pros:** No new infrastructure.
**Cons:** Per-repo config that is easy to get wrong and silently regress; unscoped
internal names remain exposed; no central visibility or enforcement. This is the
failure mode the attack exploits. Rejected.

### Option C: Detect-and-warn on public/private name collisions
**Pros:** Low risk; no authoritative role.
**Cons:** Advisory only; the race/precedence bug can still resolve to the attacker
before a human reads the warning. Necessary as a signal, insufficient as a control.
Use as a complement, not the mechanism.

## Trade-off Analysis

The choice is between **eliminating** the attack class and **mitigating** it.
Configuration-based mitigations have failed repeatedly in practice precisely because
they depend on flawless, durable per-project setup. Making the proxy authoritative
for claimed names converts a configuration problem into a structural guarantee. The
cost — we now own availability/correctness for private names and must build claim
management — is the natural Phase 2 expansion of the wedge and is acceptable for the
enterprise buyer who is asking for exactly this.

## Consequences

- **Easier:** dependency confusion becomes impossible for claimed names; central,
  auditable namespace policy; a foothold for hosting private packages.
- **Harder:** we take on registry-authoritative duties (uptime, storage,
  publish/upload or federation); we must verify and manage namespace claims to
  prevent abuse; cache keying may need a private-vs-public dimension.
- **Revisit:** the transparency boundary (ADR-0005) — document precisely which names
  are authoritative vs. passed through; define behavior when a claimed private
  package is missing (fail closed, never silently fall through to public).

## Action Items
1. [ ] Namespace-claim model (exact names + scope/prefix patterns) with verification.
2. [ ] Authoritative serving path for claimed names; **never** fall through to public on miss.
3. [ ] Private package hosting or federation with an existing internal registry.
4. [ ] Collision telemetry: log every public name that shadows a claimed private name.
