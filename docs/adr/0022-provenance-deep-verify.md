# ADR-0022: Provenance deep-verify (Sigstore bundle verification)

**Status:** Accepted (Phase 9)
**Date:** 2026-07-07

## Context

ADR-0021 gated on `provenance: present|absent` — whether the packument *claimed* an
attestation existed, never whether the attestation actually verified. That left the
gap its own Deferred section named: "full Sigstore/Rekor attestation-bundle
verification"; "verifying provenance contents (repo/builder identity)". A package
could claim provenance and pass `requireProvenance` with a bundle that was never
checked — trust-the-claim, not trust-but-verify.

## Decision

- **Gate-time verification, not enrich-time.** `verifyProvenance` (`packages/core/src/provenance.ts`)
  runs inline in `runAudit`, pure and total (never throws — same inputs ⇒ same
  result), against pinned trust material in `packages/core/trust/`
  (`trusted-root.json` + `npm-attestation-keys.json`), a static input like
  `NPM_SIGNING_KEYS`, never fetched at audit time (invariant #3).
- **Acquisition-path fetch.** `Upstream.getAttestations(name, version)` is called
  only when the packument claims attestations (`vmeta.hasProvenance`); a fetch
  failure returns `null`, which maps to `unknown`, not a crash.
- **Real verifier, not hand-rolled crypto.** One `@sigstore/verify` `Verifier`
  (`{ ctlogThreshold: 1, tlogThreshold: 1, tsaThreshold: 0 }`) with a `keyFinder`
  resolving npm's publish-attestation key from the pinned key set verifies both
  the Fulcio-cert SLSA bundle and the public-key npm publish bundle.
- **Status model:** `verified | invalid | absent | unknown` (`ProvenanceStatus`).
  `absent` = packument claimed no attestations. `unknown` = claimed, but an input
  is missing. `invalid` = bundles present but any fail crypto, chain, tlog,
  parsing, or subject binding. `verified` = every present attestation verifies
  and every subject digest binds.
- **Subject-digest binding on every subject of every bundle.** The in-toto
  subject's `sha512` digest must match `integrity` — the SRI of the tarball's
  **actual served bytes**, not the claimed `dist.integrity`. A cryptographically
  valid attestation for different bytes is `invalid`. Deliberately no purl/name
  matching — the digest is the strong bind; purl encodings vary across
  registries and add a weaker, redundant check.
- **Identity extracted only from authenticated data**: workflow SAN, issuer
  (Fulcio cert extensions from the verifier's `result.identity`), and
  `sourceRepository`/`ref`/`builder`/`commit` (from the *signed* DSSE in-toto
  statement) — never from unauthenticated packument fields.
- **Served-bytes integrity recompute.** `runAudit` recomputes integrity from the
  bytes it actually has (`actualIntegrity = integrityOf(tarball)`); `meta.integrity`
  is the actual hash. `claimed !== actual` ⇒ a critical `integrity-mismatch`
  finding (hard-blocks). The registry *signature* (ADR-0021) still verifies over
  the **claimed** integrity — that's npm's own statement about its dist entry —
  while *provenance* binds to the **actual** bytes: each check verifies the layer
  that produced it. The proxy caches and reports by the actual-bytes hash
  (`store.get`/`store.put` agree), which structurally closes the
  cache-poisoning-by-claim vector ADR-0021 flagged as open (a forged claimed
  integrity can no longer paper over tampered bytes on the cache path).
- **`provenanceIdentities` score-time gate** (`score.ts`, beside `deny` and the
  ADR-0021 `requireSignature`/`requireProvenance` gates): a policy lists
  `{ pattern, repository?, workflowRef?, builder?, issuer? }` entries; every
  matching entry must be satisfied — **fail-closed AND** across entries. `repository`,
  `workflowRef`, and `builder` compare via `matchPackage` (glob); `issuer` compares
  exact. `workflowRef` matches against the cert SAN (`identity.workflow`). A
  violation pushes a weight-0 critical `provenance-identity` finding (computed
  after, and independent of, the ordinary `hardBlockSeverity` check) and forces
  `verdict = "block"`.
- **`requireProvenance` now demands `"verified"`**, not merely `"present"` (the
  ADR-0021 gate compared against `"present"`; that comparison is now vacuous since
  `provenance` no longer has a `"present"` member — this ADR's status model
  replaces it). `unknown` is **exempt from the identity gate** (an attestation
  outage must not block ordinary installs — fail-open by default) **but not from
  `requireProvenance`** (the opt-in fail-closed lever for operators who need it).

### The fail-closed refinement

> A thrown error while verifying **present** bundles maps to `invalid`, not
> `unknown`. If it mapped to `unknown`, a crafted crash-bundle — malformed DSSE,
> a bundle shaped to throw partway through chain-building — would degrade to the
> same fail-open status as a missing input, sliding straight past the identity
> gate (which exempts `unknown`). `unknown` is reserved for missing inputs only:
> the bundle endpoint is unfetchable, the bundle list is empty, or no trust
> material is configured. Everything that reaches the verifier with a present
> bundle and fails is `invalid`.

This is also recorded as a spec amendment in
`docs/archive/superpowers/specs/2026-07-07-provenance-deep-verify-design.md` §2.

## Consequences

- Three new core deps: `@sigstore/verify`, `@sigstore/bundle`,
  `@sigstore/protobuf-specs`. All three are Sigstore-project-maintained and
  themselves provenance-published — an acceptable trust delegation for a
  verifier whose whole job is verifying provenance.
- The trust root (`packages/core/trust/trusted-root.json`) is operator-updated
  static data, same posture as `NPM_SIGNING_KEYS`. Staleness is **not enforced** —
  it is surfaced as a zero-weight info finding (`trust-root-stale`) via an
  injectable `verifyAt`/`now`, preserving invariant #1 (no clock-dependent score).
  Staleness is defined conservatively: **stale only when every CA in the pinned
  root has `validFor.end` in the past.** The real, current Fulcio CA has no
  `validFor.end` (open-ended), so staleness is undeterminable from the snapshot
  and the root **never** reports stale in practice today. This is a deliberate
  fail-open choice — a root that can't prove it's stale shouldn't manufacture a
  false-positive finding.
- Old bundles stay `verified`: Sigstore verification is tlog-timestamp-anchored
  (the signed entry timestamp / inclusion proof establishes when the signature
  was made), not wall-clock-anchored, so a package published years ago verifies
  the same way today as the day it was published.
- `SENTINEL_TRUSTED_ROOT` / `SENTINEL_NPM_ATTESTATION_KEYS` env overrides let an
  operator pin their own trust material; a bad path is a fatal startup error
  (fail loud at boot, not silently at audit time).
- `Upstream.getAttestations` adds one more conditional network call to the
  acquisition path (only when the packument claims provenance) — still no
  network call on the cached-integrity request path once cached (invariant #3
  intact: the *fetch* is acquisition, the *audit* stays sync-over-bytes-in-memory).
- An `allow` waiver that matches the `provenance` **category** also waives the
  `integrity-mismatch` critical finding, since it shares that category. An
  enterprise that wants to silence attestation noise (e.g. `trust-root-stale`)
  without also blinding itself to a claimed/actual integrity mismatch should
  waive by `ruleId`, not by category. A distinct category for the integrity
  check is deferred.
- `requireProvenance` demands verified provenance **and** a non-null build
  identity (ADR-0022's identity-required refinement); `provenanceIdentities`
  entries are checked independently and are exempt when provenance is
  `unknown` by design. Operators should pair `provenanceIdentities` with
  `requireProvenance` on the same package patterns — `requireProvenance` is
  the fail-closed lever that also covers the outage case the identity gate
  deliberately exempts.
- `trust-root-stale` is zero-weight only **under the default policy**, where
  `severityWeight.info = 0`; it's still an `info`-severity finding, `verifyAt`
  is an explicit audit input, and determinism-given-a-policy (invariant #1)
  holds regardless — a custom policy that weights `info > 0` will make the
  score depend on `verifyAt`, which is expected, not a bug.
- `matchPackage` globs match across `/`, so a repository pattern like
  `"https://github.com/acme*"` also matches `"https://github.com/acme-evil"`.
  Operators writing `provenanceIdentities` `repository` patterns should prefer
  an explicit separator, e.g. `"https://github.com/acme/*"`.

## Deferred

- TUF auto-refresh of the pinned trust root (still static, operator-updated).
- Enforcing staleness (currently informational only).
- purl/name-binding check on the attestation subject — digest binding is judged
  the strong bind; adding a weaker, format-varying check is not worth the
  false-mismatch risk across registries.
- Source-commit liveness checks (verifying the commit still exists / hasn't been
  force-pushed away in the named repository).

## Rejected

- **Async-enrich-only verification** (mirroring the LLM adapter's placement) —
  advisory-only verification can produce a `llmSummary` note but can never block
  a forged attestation before install-time code runs; that defeats the point of
  gate-time provenance checking.
- **Hand-rolled verifier** (parse the DSSE, chase the cert chain, check SCTs and
  Merkle inclusion proofs by hand) — this is exactly the class of code where
  security bugs are born; `@sigstore/verify` is the maintained, audited
  reference implementation and ADR-0021 already rejected hand-rolling for the
  registry-signature case on the same grounds.
- **Verifier-level identity policy** (teach `verifyProvenance` about
  organization-specific allowed repos/workflows) — the verifier and rules stay
  policy-blind per ADR-0014; identity requirements are enterprise policy data
  and live in `score.ts`'s `provenanceIdentities` gate, not in the pure
  verification function.

Extends ADR-0021 (signature/provenance status model, `requireSignature`/`requireProvenance`
split), ADR-0020 (whole-tree gate — `TreePackageRow.provenance` carries this
status through `audit-tree`), ADR-0014 (policy stays data, rules/verifiers stay
policy-blind), ADR-0002 (deterministic scoring — the identity gate is data-driven,
not a hardcoded verdict). Supersedes nothing.
