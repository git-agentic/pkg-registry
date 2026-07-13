# ADR-0045: Registry write path and deterministic resolution merge

**Status:** Accepted (Phase 30 — implemented 2026-07-13)
**Date:** 2026-07-11

First of the four registry-evolution ADRs (0045–0048). Decision record for
[wayfinder ticket #37](https://github.com/git-agentic/pkg-registry/issues/37)
(map [#33](https://github.com/git-agentic/pkg-registry/issues/33)); the roadmap
stage is Phase 30 in [docs/product/registry-roadmap.md](../product/registry-roadmap.md).
Client-facing API constraints come from
[docs/research/npm-registry-api-surface.md](../research/npm-registry-api-surface.md).

## Context

Sentinel is evolving from a transparent auditing proxy into a first-class
registry, because two capabilities are structurally unavailable to a proxy:
verified canonical namespace ownership and time-locked retraction (ADR-0046,
ADR-0047). Accepting writes forces a question the proxy never had to answer in
general form: when an installer asks for a name, which of several possible
sources answers — and can an attacker-writable source (public npm) ever shadow
or steer a trusted one?

A narrow precedent already exists: ADR-0010/0015 made claimed
`privateNamespaces` authoritative and fail-closed (served only from the
`PrivatePackageStore`, 404 if unpublished, never consulting upstream), and
ADR-0015 shipped an npm-compatible `PUT /:pkg` publish path for exactly those
names, audited and policy-gated. This ADR generalizes that precedent to a
registry with verified claims (ADR-0046), and pins the rules that keep the
write path inside the existing invariants: deterministic scoring (invariant 1),
the sync-gate/async-enrich split (ADR-0003), integrity-keyed caching
(ADR-0004), and packument transparency for everything still proxied (ADR-0005).

## Decision

Six rules, each with its testable statement.

1. **Name-level partition — no version merge.** Every package name maps to
   exactly one source class; a served packument never contains versions from
   two sources. There is no per-version union of native and upstream content,
   so there is no version-union surface for a downgrade or steering attack to
   exploit. *Test: `source(name)` is a pure function of (signed policy, claim
   registry); no native/claimed packument references an upstream version.*
2. **Publish requires a claim.** The publishable name space is exactly the
   signed policy's `privateNamespaces` ∪ verified claims (ADR-0046). A `PUT`
   on an unclaimed name is rejected 403 ("claim first") before any store
   write. "Native-published" is not a separate source class — it is the
   content of the claimed classes, so there is no unclaimed-but-publishable
   state for a squatter to race. *Test: unclaimed publish is rejected with no
   store side effects.*
3. **Total order: policy-private → verified-claim → public-mirror, first
   match wins.** The local operator's signed policy is sovereign over global
   claims — both on principle (their instance, their trust root) and as the
   operational escape hatch when a claim is compromised. The claim registry is
   non-overlapping **by construction**: a new claim that overlaps an existing
   one is rejected at claim time, so resolution never needs a within-class
   tie-break. Claimed names keep ADR-0015 fail-closed semantics (served only
   from their native store; 404 if unpublished; upstream never consulted).
   *Test: for any (policy, claim-set, name) triple, resolution is
   deterministic and matches the order.*
4. **Claim grammar: scope globs + exact unscoped names; no unscoped
   wildcards.** Scope matching reuses `matchPackage` semantics. Exact unscoped
   claims make brand names (`tanstack`) protectable — the class of name the
   2026 npm squatting incidents exploited — while banning unscoped globs keeps
   the non-overlap check statically decidable. *Test: overlap rejection
   enforced at claim time; an exact unscoped claim is expressible and
   resolves.*
5. **`publishGate` is policy data, default `block`.** A publish stores the
   version iff its `score(policy).verdict` is below the gate; rejection is a
   403 carrying the full `AuditReport` so the publisher sees exactly which
   findings blocked them. This mirrors the `audit-tree` gate-level precedent
   (ADR-0020) and keeps thresholds in `DEFAULT_POLICY`, not code. The
   determinism invariant extends verbatim to publishing: same bytes + same
   policy ⇒ same publish outcome. *Test: fixture publishes pin the behavior
   for all three verdicts.*
6. **Synchronous gate, fail-closed, no timeout-fallback-to-allow.** The
   publish gate runs the existing audit engine inline (`runAudit` +
   `score(policy)`, as ADR-0015 already does) and blocks until the verdict
   exists. Latency budget: **p50 ≤ 1 s, p99 ≤ 15 s** from `PUT` received to
   verdict returned, within the existing byte caps (256 MB fetch, 1 GiB /
   100k-file extraction — ADR-0037/0039), pinned by a CI benchmark. The budget
   is a regression tripwire, not an SLA: an overrun is fixed by optimizing or
   moving the slow part to async enrich (ADR-0003) — never by weakening or
   fail-opening the gate. *Test: benchmark pins the fixture-corpus median and
   a cap-adjacent synthetic package against the two targets.*

## Consequences

- The resolution-merge downgrade attack — steering an installer's semver range
  to an attacker-supplied higher version on the public side — is removed
  structurally rather than detected heuristically. The threat-model draft
  analyzes the residual surface (claim forgery moves to ADR-0046's issuance
  policy; the escape hatch's revert manifest in ADR-0048 names the
  resurrection risk on mode revert).
- Adopting an existing public name under a claim is an **explicit, audit-gated
  history import** (data model in ADR-0048), never live blending. Sharper
  migration work in exchange for an attack surface that does not exist.
- A claimed-but-unpublished name 404s (unchanged from ADR-0015). For a
  squatted name this is the protection working; for a legitimate migration the
  import flow is the answer.
- `publishGate` and the latency budget live in policy/config data, so the
  scoring-determinism test extends to the write path without new invariants.
- Publishing takes on availability duties for claimed names (already accepted
  in ADR-0015's consequences); durability/GC remain deferred to
  implementation phases, with exit criteria in the roadmap.

## Implementation

- `packages/proxy/src/resolution.ts` defines the data-only `ClaimCorpus` input
  and the pure `source()` partition. Phase 30 accepts already-verified claim
  entries programmatically; Phase 31 still owns corpus signature verification,
  loading, issuance, renewal, freeze, and transfer semantics.
- `EnterprisePolicy.publishGate` is validated with the other signed policy
  fields and defaults to `block`. Publish rejects a report at or above the gate
  and returns that complete `AuditReport`.
- `PrivatePackageStore.publish()` stages tarball and metadata in a temporary
  version directory, atomically renames the complete directory, then exposes it
  in memory. Duplicate publication is store-authoritative, so concurrent PUTs
  cannot replace a version or lose sibling versions.
- `npm run benchmark:publish` measures the complete HTTP PUT-through-response
  path over all fixture-corpus tarballs plus an 8 MiB synthetic package against an
  injected 9 MiB extraction cap; CI runs it on Node 22 and 24.

## Alternatives considered

- **Per-version merge (native + upstream versions under one name).** Friendlier
  migration for existing public names — no import step — but it creates a
  version-union surface where the attacker-writable side can always win a
  semver race; every mitigations variant (pin native ceilings, prefer-native
  tie-breaks) re-introduces nondeterminism keyed on mutable upstream state.
  Rejected: the partition rule is the only shape where the downgrade attack is
  inexpressible.
- **Open native publish (first-come-first-served names on Sentinel).** Lower
  friction than claim-first, but it recreates the squatting economy inside the
  trust boundary and makes `source(name)` depend on mutable store state
  ("has anyone published this natively yet?"), breaking the pure-function
  determinism that the partition rule provides. Rejected.
- **Live claim lookups at resolution time.** Always-fresh claims, but it puts
  a network dependency on the request path — a direct violation of the
  sync-gate invariant (ADR-0003) and the offline thesis; an outage of the
  claim service would become an install outage. Rejected in favor of the
  offline signed claim corpus (ADR-0046).
- **Timeout-fallback-to-allow on the publish gate.** Bounded worst-case
  latency, but it converts an audit slowdown into a security bypass: a
  pathological-but-under-caps tarball that blows the budget would publish
  unaudited. Publish latency is not on any install's critical path, so the
  trade is all downside. Rejected — the gate blocks until the verdict exists.
- **Hardcoded `warn`-blocks-publish (or hardcoded `block`-only).** Simpler than
  a policy field, but gate thresholds are exactly the kind of per-enterprise
  posture ADR-0012 made signed policy data; hardcoding either level would be
  the first threshold to live in code. Rejected for `publishGate` in
  `DEFAULT_POLICY`.
