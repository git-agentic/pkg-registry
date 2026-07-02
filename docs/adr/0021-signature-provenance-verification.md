# ADR-0021: Signature & provenance verification

**Status:** Accepted (Phase 8)
**Date:** 2026-07-02

## Context

`normalizeVersion` flattened `signed || provenance → "signed"` and discarded the detail; no
rule or policy acted on it, despite the threat model promising to "surface signature/provenance
status."

## Decision

- **Un-flatten** `PackageMeta.signatureStatus` into `signature: verified|invalid|unsigned|unknown`
  + `provenance: present|absent`.
- **Verify the npm registry signature offline** — ECDSA P-256, SHA-256, **DER** encoding (Node's
  default; the common IEEE-P1363 assumption is wrong — confirmed live against `/-/npm/v1/keys`,
  where `left-pad@1.3.0` verified under DER and failed under ieee-p1363). Payload
  `${name}@${version}:${integrity}`. Keys are matched by `keyid` against a configured set
  (`NPM_SIGNING_KEYS`, both current npm keys bundled), a **static input never fetched at audit
  time** (invariant #3). `invalid` ⇒ critical ⇒ hard-block.
- **Rule vs gate split:** a pure `provenance` rule surfaces status as findings (it cannot see
  policy); the conditional gate lives in `score.ts` beside `deny`, driven by optional
  `requireSignature`/`requireProvenance` pattern lists.
- **Provenance gated on presence** this phase.

## Consequences

- Verifies the `name@version → integrity` binding against npm's registry key, so a forged
  packument entry (wrong claimed `integrity`) is caught; policy can require provenance for a
  namespace. This is **not** full MITM/compromised-mirror defense: `verifyRegistrySignature`
  checks the signature over the *claimed* `dist.integrity`, but the proxy fetch path does not
  recompute `integrityOf(tarball)` against that claim, so byte-level tampering between the
  claimed integrity and the delivered tarball is caught downstream by npm-client SRI
  enforcement, not by this gate (Sentinel's content rules still scan the real bytes regardless).
- Key rotation/expiry: keys are matched by `keyid`; expiry is surfaced, not enforced (a package
  signed under a since-rotated key stays `verified`).
- Deferred: full Sigstore/Rekor attestation-bundle verification (async-enrich follow-up);
  expiry-as-invalid; automatic key refresh; verifying provenance contents (repo/builder identity).

## Rejected

- IEEE-P1363 signature encoding (empirically wrong for npm).
- Verifying inline with a network fetch (violates invariant #3).
- Making verification a rule (rules are pure and can't see policy or configured keys).

Extends ADR-0001 (proxy wedge), ADR-0002 (deterministic scoring — the signature gate is data,
not a hardcoded verdict); supersedes nothing.
