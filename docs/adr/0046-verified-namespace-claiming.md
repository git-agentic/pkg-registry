# ADR-0046: Verified namespace claiming

**Status:** Accepted (Phase 31 implemented 2026-07-13)
**Date:** 2026-07-11

Second of the four registry-evolution ADRs (0045–0048). Decision record for
[wayfinder ticket #38](https://github.com/git-agentic/pkg-registry/issues/38)
(map [#33](https://github.com/git-agentic/pkg-registry/issues/33)); prior art in
[docs/research/namespace-ownership-prior-art.md](../research/namespace-ownership-prior-art.md).
Depends on ADR-0045: claims are the sole gateway to publishability, must be
non-overlapping by construction, and use the scope-glob + exact-unscoped-name
grammar.

## Context

ADR-0045 makes verified claims a resolution input: `source(name)` is a pure
function of the signed policy and the claim registry. This ADR decides what a
claim *is* — how ownership is proven, renewed, transferred, disputed, and how
the existing public npm corpus maps in.

The prior-art survey constrains the design from several directions. Maven
Central is the only registry that verifies organizational identity (one-shot
DNS TXT on the exact apex domain) but publishes no policy for domain expiry,
transfer, or disputes. Go binds namespaces to *continuous* domain control at
fetch time — incompatible with Sentinel's offline thesis — but its proxy+sumdb
layer contributes the key containment idea: a domain's new owner inherits only
*future* versions, never observed history. Sigstore/OIDC identity proves build
origin, not namespace legitimacy: nothing in a Fulcio certificate or npm
publish attestation links a CI identity to a scope, and a compromised CI run
yields *valid* provenance (the May-2026 TanStack postmortem). PEP 541-style
adjudication drowns in backlog, while crates.io categorically refuses
mediation, noting it is itself a social-engineering vector. And npm's scope
overlay left brand-equivalent unscoped names claimable by strangers — the
April-2026 `tanstack` incident shipped env-exfil malware from exactly that gap
while `@tanstack` was safely owned.

Sentinel's own invariants apply: resolution must stay deterministic and
offline (ADR-0003, invariant 1); trust material is static and loaded at boot
(ADR-0012/0014/0021/0022); the advisory corpus (ADR-0034) is the proven
pattern for distributing steward-maintained security data offline.

## Decision

1. **Claims live in a global signed claim corpus, distributed offline.**
   Claims are verified and accumulated by the Sentinel steward, then shipped
   as a versioned, signed, bundled dataset on the ADR-0034 pattern: never
   fetched at resolution time, signature-verified against pinned keys at boot,
   fail-closed on tamper. The corpus version is recorded in audit provenance
   alongside `policyHash`. The local operator's signed policy stays sovereign
   above the corpus (ADR-0045 precedence). *Test: resolution reproducible
   given (policy, corpus version, name); tampered corpus ⇒ boot FATAL.*
2. **DNS TXT is constitutive of a claim; Sigstore OIDC is publish-auth under
   it — never the claim itself.** A claim binds a namespace set (ADR-0045
   grammar) to an organizational domain: the steward issues a challenge key,
   the org publishes it as a TXT record on the exact apex domain, an automated
   check passes, and the claim enters the corpus at the next release. A claim
   may additionally enumerate trusted-publisher identities (OIDC issuer +
   repo/workflow patterns); where present, publishes to the namespace must
   carry a matching attestation, verified by the existing offline provenance
   machinery (ADR-0022, pinned Sigstore roots). *Tests: no corpus entry
   without a passed challenge; trusted-publisher namespaces reject unattested
   publishes.*
3. **Lifecycle: 12-month renewal; failure ⇒ freeze, never fallthrough, never
   auto-transfer.** A claim that fails renewal (or whose domain visibly
   changes hands) is frozen: no new publishes; already-published versions keep
   serving; the name stays partitioned to the claim. It never reverts to
   public-mirror (that would hand resolution to whoever squats the name
   upstream) and never passes to the domain's buyer (they inherit nothing
   without the dispute flow). Unfreeze requires re-verification by the same
   org or a transfer/dispute ruling. *Tests: frozen claim rejects publishes
   with a distinct error; renewal failure alone never changes `source(name)`;
   frozen-claim serving is byte-identical for published versions.*
4. **Transfers and disputes are timelocked and narrow.** Voluntary transfer =
   old claimant's signature + new claimant's fresh TXT challenge + a 30-day
   pending entry in the corpus (corpus diffs are the fleet's announcement
   channel; operators can pin the old state locally during the window).
   Disputes adjudicate exactly one question — does the challenger control the
   organizational identity the namespace names? — evidenced by domain control
   plus, for brand names, PEP-541-grade proof that the claimant demonstrably
   *is* the project. Brand/trademark arbitration is categorically refused.
   Contested claims freeze during the dispute; rulings take effect via the
   same 30-day timelock. Published history never re-attributes. *Tests: no
   transfer/ruling effective under 30 days; disputed namespace rejects
   publishes; local override beats a pending transfer.*
5. **Grandfathering: a three-tier issuance rule for names that exist on
   public npm.**
   - **Tier 1 — corroborated, auto-grant:** the upstream packument's own
     metadata (repository/homepage URL or provenance repo org) already points
     at the claimant's domain. TXT challenge alone suffices; the linkage check
     is a pure function of (upstream packument, claim domain).
   - **Tier 2 — contested, evidence-gated:** an active upstream publisher
     with no linkage to the claimant's domain. Refused by default; granting
     requires the rule-4 evidence standard plus the 30-day timelocked entry.
     This is the tanstack tier: the squatter has no domain linkage, the real
     org does — and once granted, ADR-0045's partition eclipses the squatter
     fleet-wide.
   - **Tier 3 — free names:** nothing (or a long-dead placeholder) upstream;
     challenge-only reservation.
   Unclaimed names remain byte-identical public-mirror passthrough. Claiming a
   name with legitimate history means an explicit audit-gated import
   (ADR-0045/0048), never live blending. *Tests: Tier-1 linkage pinned by
   fixtures; a Tier-2 grant cannot land without a timelock entry; unclaimed
   resolution unchanged.*

## Consequences

- Sentinel gains an operational dependency that is new in kind: a **steward
  role + claim service** (challenge issuance, verification, renewal tracking,
  corpus release). The roadmap names it as a Phase 31 entry criterion; the
  engine and proxy remain fully offline consumers of its output.
- The tanstack-class attack becomes structurally inexpressible against
  claimed names on Sentinel instances: there is no unclaimed-but-publishable
  state (ADR-0045), and brand-equivalent unscoped names are claimable by the
  verified org even while squatted upstream.
- The freeze rule means a lapsed claim degrades to read-only rather than
  changing hands — availability of published versions is never hostage to DNS
  renewal. The cost: a genuinely abandoned namespace requires the dispute flow
  to revive, by design.
- Claim forgery pressure concentrates on the Tier-2 evidence bar and on
  lookalike-domain challenges at claim time; the threat-model draft analyzes
  both (the steward, not the fleet, is the trust chokepoint — compromise of
  the corpus signing key is in the same class as policy-key compromise,
  ADR-0012).
- Corpus-cadence latency applies to claim changes fleet-wide; urgent local
  needs are covered by the operator's policy override, not by weakening the
  offline model.

## Alternatives considered

- **Registry user accounts as identity (npm's model).** Simplest to build,
  but it binds names to credentials, not organizations — precisely the model
  under which account takeover and the unscoped-`tanstack` gap flourished; the
  ticket's charter excluded it.
- **OIDC identity as the claim mechanism.** Attractive because npm/PyPI/crates
  all adopted OIDC in 2025 — but for *publish-auth*, not namespace ownership.
  The survey's negative result is decisive: no field binds a CI identity to a
  scope, and CI compromise yields valid credentials. Rejected as constitutive;
  adopted as optional trusted publishing under a claim.
- **Live claim service queried at resolution time.** Always-fresh, but puts a
  network dependency and an availability coupling on the install path —
  rejected in ADR-0045 already; restated here because it is the *claims*
  variant most tempting to reach for.
- **Continuous Go-style domain checks.** The strongest freshness guarantee on
  the survey, but requires per-fetch network access and makes resolution
  nondeterministic across time; incompatible with the offline corpus and the
  reproducible-verdict thesis. Its containment idea (frozen history) is kept;
  its transport is not.
- **One-shot, never-renewed verification (Maven's model).** Operationally
  cheapest and proven at Central's scale — but Maven's own documented silence
  on expiry/transfer is the gap this ADR exists to close; without renewal, a
  sold or hijacked domain silently keeps a live claim forever.
- **Claim-expiry fallthrough to public-mirror.** Keeps names "working" after a
  lapse, but hands resolution of a formerly-trusted name to whoever occupies
  it upstream — a time-delayed dependency-confusion grant. Freeze instead.
- **Full brand-dispute adjudication (PEP 541's scope).** Maximal fairness on
  paper; in practice a documented backlog machine and a social-engineering
  surface (crates.io RFC 3646's argument). The narrow domain-control question
  keeps most disputes machine-checkable.
