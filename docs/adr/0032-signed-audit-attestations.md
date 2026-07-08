# ADR-0032: Signed audit attestations (VSA) — a portable, offline deploy gate

**Status:** Accepted (Phase 19)
**Date:** 2026-07-08

## Context

Every phase through 18 makes Sentinel's audit trustworthy *as it happens*:
deterministic scoring (ADR-0002), signed policy (ADR-0012/0014), registry
signature and provenance verification (ADR-0021/0022), a whole-tree gate with
an SBOM export (ADR-0020/0027). But the audit result itself is not a
portable, verifiable artifact — it's a JSON response an install-time client
consumed once. A CI run can gate `sentinel audit-tree` on `treeGate`, but
nothing survives that CI job that a *later*, independent step — a deploy
pipeline, a release-approval gate, an auditor reviewing what shipped — can
check offline against a pinned key. Sentinel verifies trust flowing *in*
(registry signatures, build provenance) but produces none flowing *out*: an
operator who wants "prove this exact dependency tree passed Sentinel's gate,
without re-running the audit and without trusting whoever hands me the JSON"
has no artifact to check.

## Decision

- **`buildAuditStatement(tree, opts)`** (`packages/core/src/attest.ts`, pure)
  projects a `TreeAuditResult` into an in-toto `Statement` v1
  (`_type: "https://in-toto.io/Statement/v1"`). `subject` is a single entry
  whose `digest.sha256` is the hex SHA-256 of the tree's CycloneDX SBOM bytes
  (ADR-0027) — not the lockfile, not the raw tree JSON — so the attestation
  binds to the same artifact a consumer's existing SBOM tooling already
  handles. `predicateType` is a Sentinel-owned URI,
  `https://sentinel.dev/attestation/audit-summary/v1`; the predicate is a
  VSA-style summary (`verifier`, `policyHash`, `verdict`, `gated`, `counts`,
  `packageCount`, `timestamp`) — enough to gate on without re-fetching the
  full per-package report.
- **`signAttestation(statement, privPem, keyid)`** wraps the Statement in a
  DSSE envelope and signs the PAE (`pae(payloadType, payload)` —
  `DSSEv1 <len> <type> <len> ` + payload, per the DSSE spec) with Ed25519,
  reusing `signPolicy` from `packages/core/src/policy.ts` (ADR-0014's
  raw-bytes Ed25519 primitive) rather than adding a new crypto dependency or
  signing scheme. `attestationKeyid(pubPem)` derives a stable
  `SHA256:base64(sha256(SPKI DER))` keyid, matching the keyid convention
  ADR-0021 established for registry signing keys.
- **`verifyAttestation(envelope, pubPem, opts?)`** is pure, offline, total,
  and fail-closed: it never fetches anything and never throws (a `try/catch`
  around the whole body maps any parse/verify exception to
  `{ valid: false, reason: "malformed" }`). It checks the Ed25519 signature
  over the recomputed PAE first; only a verified envelope's payload is then
  parsed and checked against `predicateType`, and optionally against
  `opts.expectedSbomDigest` (`subject-mismatch`), `opts.expectedPolicyHash`
  (`policy-mismatch`), and `opts.requireVerdict` (`allow` or
  `allow-or-warn`, rejecting with `verdict-block`/`verdict-warn`). Every
  failure path returns a typed `reason`, never a partial or ambiguous
  "maybe valid."
- **Signing is operator-side, in the CLI, never on the proxy.** The proxy
  gains no new mutating route and holds no signing key; `sentinel
  attest-keygen`/`attest` run wherever the operator's CI or release pipeline
  runs, keeping the private key off the always-on, network-facing process.
  Three CLI commands: `sentinel attest-keygen --out <prefix>` generates an
  Ed25519 keypair (private key written `0600`); `sentinel attest <lockfile>
  --key <priv> --out <att> [--sbom <file>]` audits the tree, writes the
  CycloneDX SBOM, and writes the signed DSSE envelope over it; `sentinel
  verify-attestation <att> --key <pub> [--sbom --policy-hash --require]`
  checks an attestation offline and exits non-zero on any rejection — the
  deploy gate. (Commander 15 enforces a parent command's `requiredOption`s
  even when routing to a subcommand, which broke a `attest keygen` +
  `attest <lockfile>` parent/subcommand split; `attest-keygen` and `attest`
  ship as two sibling top-level commands instead.)
- **The proxy's only change is exposing `policyHash` on `TreeAuditResult`.**
  `POST /-/audit-tree`'s response already computed the scoring-time policy
  hash (`opts.policyHash ?? policyHashOf(enterprisePolicy)`, ADR-0012); Phase
  19 threads it onto the response so `buildAuditStatement` can embed the
  policy that produced the verdict, and `verify-attestation --policy-hash`
  can pin against it. No new computation, no new route.

## Determinism (invariant #1 untouched)

`buildAuditStatement` and `pae` are pure functions of their inputs; `now` is
injected by the caller (the CLI passes `new Date().toISOString()`), never
read from the clock inside `attest.ts`, matching the injected-clock pattern
ADR-0022 established for `trust-root-stale`. Given the same `TreeAuditResult`,
SBOM digest, and `now`, `signAttestation` with the same Ed25519 key produces
a byte-identical DSSE envelope every time. This phase attests *over* an
already-computed, already-deterministic tree audit result — it adds no new
input to scoring and no new code on the scoring path (`runAudit`, `score()`,
the rule set, and `aggregateTree` are untouched). `verifyAttestation` makes
no network call, reads no filesystem beyond what the CLI hands it, and
consults no clock — it is a pure function of the envelope, the public key,
and the caller's expectations.

## Consequences

- Enforcement now extends past install-time and past CI-time to
  **deploy-time**: a release pipeline can gate on a portable, offline-
  verifiable artifact instead of re-running `audit-tree` or trusting an
  unauthenticated JSON blob handed across a pipeline boundary.
- No new cryptographic primitive or dependency — DSSE/in-toto envelope
  shapes plus the existing Ed25519 signing/verification pair
  (`signPolicy`/`verifyPolicyBytes`) and the existing SBOM export are
  reused wholesale.
- The predicate type is Sentinel-owned
  (`https://sentinel.dev/attestation/audit-summary/v1`), not one of the
  standard SLSA predicate types (e.g. `slsa.dev/verification_summary/v1`).
  The envelope and Statement shapes are spec-compliant DSSE/in-toto, so a
  generic DSSE/in-toto tool can parse and verify the signature, but a
  SLSA-aware verifier expecting a standard predicate type won't recognize
  Sentinel's predicate without adaptation — this bounds interop today to
  Sentinel's own `verify-attestation` and any consumer willing to read the
  custom predicate shape.

## Deferred

- **Automatic production in CI** (e.g. a GitHub Action step that runs
  `sentinel attest` automatically) — Phase 19 ships the CLI primitive; wiring
  it into ADR-0030's Action is not part of this phase.
- **Rekor / transparency-log submission** — envelopes are signed and
  verified locally against a pinned key; nothing is published to or looked
  up from a public transparency log.
- **Multi-signer / threshold signatures** — one `keyid`/signature per
  envelope; no N-of-M signing or key rotation ceremony.
- **Per-package attestations** — the Statement's subject is the whole tree's
  SBOM; there is no attestation scoped to a single package/version.
- **Key auto-discovery** — `verify-attestation --key` takes an explicit,
  pinned public key file; there is no keyring, no fetch-by-keyid, no
  registry of trusted keys.

## Rejected

- **A bespoke Sentinel-native signed JSON format** (e.g. `{ tree, sig }`
  over the raw tree result) — rejected: it would have been simpler to build
  but non-standard. DSSE/in-toto are established shapes with existing
  tooling and a well-defined PAE, and reusing them keeps the attestation
  legible to non-Sentinel consumers in a way a one-off format wouldn't be.
- **Signing on the proxy** (the proxy holds the key and signs on request) —
  rejected: the proxy is the always-on, network-facing process that already
  handles registry traffic; giving it a standing private signing key raises
  the value of compromising it and blurs the operator-side/service-side key
  boundary ADR-0014's policy-signing model already keeps separate (the
  policy is signed offline and the proxy only ever verifies it). Keeping
  attestation signing in the CLI, run wherever the operator's pipeline
  already runs, keeps the key off the proxy entirely.

Extends ADR-0002 (deterministic scoring — attestation is a pure projection of
an already-deterministic tree result; the score path is untouched), ADR-0014
(reuses the raw-bytes Ed25519 signing/verification primitive introduced for
policy signing), ADR-0020 (whole-tree audit — the artifact attested over),
and ADR-0027 (SBOM export — the attestation's subject digest is the SBOM's
hash). Supersedes nothing.
