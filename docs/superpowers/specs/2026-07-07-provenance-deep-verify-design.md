# Phase 9 — Provenance Deep-Verify (Sigstore attestation verification + identity gate)

**Date:** 2026-07-07
**Status:** Approved design, pre-implementation
**Extends:** ADR-0021 (which deferred "full Sigstore/Rekor attestation-bundle verification"
and "verifying provenance contents (repo/builder identity)"), ADR-0020 (audit-tree),
ADR-0014 (score-time policy), ADR-0002 (deterministic scoring).

## Problem

Phase 8 left an honest gap, documented in ADR-0021: `PackageMeta.provenance` is
`present | absent` — Sentinel trusts the registry's *claim* that a provenance
attestation exists without verifying it, and never checks who built the package or
from which repository. Separately, ADR-0021 documented that the proxy fetch path
does not recompute `integrityOf(tarball)` against the claimed `dist.integrity`, so
byte-level tampering between claim and delivery is left to npm-client SRI.

Phase 9 closes both: full offline Sigstore verification of npm attestation bundles
against pinned trust material, a per-namespace **identity gate** ("@acme packages
must be built by GitHub Actions from github.com/acme/*"), and served-bytes
integrity recomputation.

## Probe evidence (2026-07-07, this repo's probe-before-spec discipline)

Probed live against `registry.npmjs.org/-/npm/v1/attestations/sigstore@3.0.0`:

- The endpoint returns two attestations: an npm **publish** attestation
  (`…/specs/publish/v0.1`, signed with npm's registry key) and a **SLSA provenance**
  attestation (`https://slsa.dev/provenance/v1`, Fulcio cert chain), both as Sigstore
  bundles (`application/vnd.dev.sigstore.bundle+json;version=0.2`).
- The SLSA predicate carries exactly the identity fields the policy needs: builder id,
  workflow `repository`/`ref`/`path`, and resolved source commit.
- `@sigstore/verify` verified the real bundle **fully offline** against a pinned
  `trusted_root.json` (parsed via `TrustedRoot.fromJSON` from
  `@sigstore/protobuf-specs` — a plain `JSON.stringify` round-trip mangles the
  protobuf byte fields). Thresholds used: ctlog 1, tlog 1, tsa 0.
- Negative controls behave: a one-string tamper in the DSSE payload →
  `TLOG_BODY_ERROR`; a wrong-identity policy on a valid bundle →
  `UNTRUSTED_SIGNER_ERROR`.
- The npm publish attestation fails with `PUBLIC_KEY_ERROR` unless npm's registry key
  is supplied as additional trust material. That key is canonically distributed via
  Sigstore TUF as target `registry.npmjs.org/keys.json` (same source as Phase 8's
  `NPM_SIGNING_KEYS`).

## Decisions (brainstorm outcomes)

1. **Placement: gate-time verify.** Attestation bundles are fetched during
   *acquisition* (where the tarball fetch already lives — invariant #3 forbids
   network on the audit path, not the acquisition path). Verification is pure
   crypto over bytes against pinned trust material, so the audit stays offline,
   deterministic, and cacheable by integrity. Rejected: async-enrich-only (a forged
   provenance could never block — advisory verification undercuts the point);
   audit-tree-only (two provenance semantics, install path keeps trusting claims).
2. **Verifier: official sigstore-js.** Core gains `@sigstore/verify`,
   `@sigstore/bundle`, `@sigstore/protobuf-specs` (Sigstore-project-maintained,
   themselves provenance-published). Rejected: hand-rolling (X.509 chain building,
   SCTs, Merkle proofs, DSSE PAE — where security bugs are born); a swappable
   verifier interface (YAGNI).
3. **Policy: verify + identity constraints** (full trusted-publishing gate), not
   verify-only and not identity-as-findings-only.
4. **Scope extras — all in:** served-bytes integrity recompute; npm publish
   attestation verification; dashboard + audit-tree surfacing; trust-root staleness
   surfacing.

## Section 1 — Architecture & data flow

- **New core module `packages/core/src/provenance.ts`** (sibling of `signature.ts`):
  pure, offline `verifyProvenance()` over: attestation bundles (JSON), claimed
  `dist.integrity`, package name/version, and pinned **trust material**
  (`trusted_root.json` + npm publish keys), shipped as static config exactly like
  `NPM_SIGNING_KEYS` — overridable, never fetched at audit time. Returns a status
  plus extracted identity (source repo, workflow ref/path, commit, builder, issuer).
- **`Upstream` gains `getAttestations(pkg, version)`**: `NpmUpstream` fetches
  `/-/npm/v1/attestations/<pkg>@<ver>` during acquisition; `LocalFixtureUpstream`
  serves bundles from `fixtures/registry.json`. Fetch failure → `null` → provenance
  `unknown` (fail-open: a Sigstore/npm outage never breaks installs).
- **Acquisition hardening in `server.ts`**: replace
  `integrity = vmeta.integrity ?? integrityOf(tarball)` with an unconditional
  recompute from served bytes. If a claimed integrity exists and differs →
  byte-level tampering → critical hard-block finding; the audit cache keys on the
  *actual* bytes hash. Completes the chain: attestation subject digest → claimed
  integrity → actual served bytes.
- **`runAudit` computes `provenance`** the way it computes `signature` today:
  `PackageMeta.provenance` widens to `verified | invalid | absent | unknown`, plus
  optional `provenanceIdentity` on meta for findings, dashboard, audit-tree.

## Section 2 — Verification semantics & status mapping

`verified` requires **all** of:

1. **SLSA provenance bundle**: DSSE signature valid under the Fulcio leaf; chain to
   pinned trusted root; SCT threshold 1; Rekor tlog threshold 1 (inclusion proof +
   signed entry timestamp).
2. **npm publish attestation** (when present in the bundle set): verifies under
   npm's registry key from pinned trust material. Any present attestation failing
   crypto → `invalid`.
3. **Subject binding**: the in-toto subject digest (sha512) must match the claimed
   `dist.integrity`. A valid attestation for a *different* tarball is `invalid`.
4. **Identity extraction** (informational, not pass/fail here): repo, workflow,
   commit, builder, issuer from cert SAN + Fulcio extensions + SLSA predicate.

| Status | Meaning |
|---|---|
| `verified` | All present attestations verify + subject binds to integrity |
| `invalid` | Any crypto/chain/tlog/binding failure → critical finding, hard-block |
| `absent` | Packument claims no attestations |
| `unknown` | Claimed but bundle unfetchable, or no trust root configured → low finding; no unconditional block (but see §3: it does not satisfy `requireProvenance`) |

> **Implementation refinement (ADR-0022):** a thrown error while verifying
> *present* bundles maps to `invalid`, not `unknown` — a crafted crash-bundle
> must not fail open past an identity gate. `unknown` is reserved for missing
> inputs (bundle unfetchable, empty bundle list, no trust material).

- **Trust-root staleness**: computed against an injectable timestamp, surfaced as a
  **zero-weight info finding** when the pinned root's `validFor` can no longer chain
  newly issued certs. Zero weight preserves invariant #1 (no clock-dependent score).
- **Expiry stance (from Phase 8)**: old bundles verified against tlog integrated
  time stay `verified` — Sigstore verification is timestamp-anchored by design.

## Section 3 — Policy & scoring

New optional `EnterprisePolicy` block beside `requireSignature`/`requireProvenance`:

```ts
provenanceIdentities?: Array<{
  pattern: string;        // package glob, e.g. "@acme/*" (same matchPackage as existing gates)
  repository?: string;    // glob, e.g. "https://github.com/acme/*"
  issuer?: string;        // exact, e.g. "https://token.actions.githubusercontent.com"
  workflowRef?: string;   // glob over workflow ref/path
  builder?: string;       // glob over builder id
}>;
```

- **Evaluation lives in `score.ts`** (ADR-0014 score-time policy; rules stay pure
  and policy-blind). The verifier reports crypto truth; the gate asserts business
  truth.
- A package matching a `provenanceIdentities` entry must be `verified` **and**
  match every constraint in the entry; when multiple entries match a package, **all**
  matching entries must be satisfied (fail-closed AND). Failure → `block` + critical
  `provenance` finding naming the mismatch. `meta.provenance` stays `verified` — honest
  reporting: valid crypto, disallowed identity.
- **`requireProvenance` upgrades**: `!== "present"` becomes `!== "verified"`.
  An unverifiable claim no longer satisfies the requirement. `requireSignature`
  untouched.
- `invalid` hard-blocks unconditionally (critical finding), like a bad registry
  signature.
- `unknown` **does** trip `requireProvenance` (proof demanded, none verifiable) but
  does **not** trip `provenanceIdentities` on its own (low finding only): fail-open
  on outages for ordinary packages, fail-closed where provenance was explicitly
  demanded.
- **Signed-policy compatibility**: all new fields optional; raw-bytes signing
  (ADR-0014) is field-agnostic; default `POLICY` ships no identity constraints.

## Section 4 — Fixtures, testing, surfacing

Hermetic-testing constraint: Fulcio certs / Rekor proofs cannot be minted offline,
so a synthetic fixture can never reach `verified`. Strategy:

- **Captured real-bundle fixtures** (data, not executed code): vendor the real
  `sigstore@3.0.0` attestation response + pinned `trusted_root.json` + npm keys
  snapshot under `fixtures/attestations/`. Unit tests drive `verifyProvenance()`
  through the full real crypto path offline: verified happy path, plus deterministic
  tampered variants (flipped DSSE payload, wrong subject digest, truncated chain,
  foreign tlog key) → each maps to `invalid` with the right reason.
- **E2E via `LocalFixtureUpstream`**: `absent` (existing fixtures, unchanged),
  `unknown` (attestations claimed, `getAttestations` → null), `invalid` → 403
  (real bundle claimed over our fixture tarball fails subject binding — which
  e2e-tests the binding check). Identity-gate e2e: `provenanceIdentities` matching a
  fixture name → blocked with mismatch finding.
- **Full verified e2e** requires vendoring the real `sigstore-3.0.0.tgz` so served
  bytes match the attestation subject. **Plan-stage probe**: check tarball size; if
  comfortably vendorable, add end-to-end `verified` through the proxy; otherwise
  unit-level verified coverage stands and this doc says so honestly.
- **Invariant tests**: determinism test extended (same bundles + policy + pinned
  roots ⇒ same score); verifier wrapped so a thrown error inside `@sigstore/verify`
  degrades to `unknown` + finding, never crashes the audit (invariant #6);
  tamper-recompute test (served bytes ≠ claimed integrity → 403).

Surfacing:

- **Header**: `x-sentinel-provenance: verified|invalid|absent|unknown`.
- **Dashboard**: package view shows verified identity (repo, workflow, commit,
  builder), colored by status.
- **`sentinel audit-tree`**: per-row provenance status + `counts.provenance`
  rollup; identity-gate blocks trip `treeGate` like any other block.
- **CLI `sentinel audit`**: prints the identity block when present ("built by
  GitHub Actions from github.com/sigstore/sigstore-js@refs/heads/main, commit
  3a57a74").

## Out of scope (deferred beyond Phase 9)

- Automatic TUF trust-root refresh (stays a static, operator-updated input).
- Enforcing trust-root staleness (surfaced only).
- Verifying resolved source-commit reachability or repo liveness (network; belongs
  to async enrich if ever).
- yarn/pnpm lockfiles, SBOM output, `--fail-on-error` (still ADR-0020 deferred).

## Definition of done

`npm run build` clean; `npm test` green with the new suites; malicious fixtures
still blocked; determinism test green; new ADR-0022 recorded; ARCHITECTURE.md §3
extended; CLAUDE.md phase summary + test count updated.
