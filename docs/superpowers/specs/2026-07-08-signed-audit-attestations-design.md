# Phase 19 — Signed Audit Attestations (Verification Summary Attestation)

**Date:** 2026-07-08
**Status:** Approved design, pre-implementation
**Extends:** ADR-0002 (deterministic scoring — the attestation is *over* the audit result and
never changes scoring), the Phase 8/9 provenance-verification machinery (reuses the in-toto
`Statement`/DSSE shapes it already parses; now Sentinel *emits* one), and Phase 12/policy
Ed25519 signing (reuses `generateKeypair`/`edSign`/`edVerify`). Reuses Phase 14's CycloneDX SBOM
(the attestation subject). Supersedes nothing. (ADR-0032 will verify and cite the exact
provenance/signing ADR numbers before recording.)

## Problem

After eighteen phases Sentinel is a deep *consumer* of supply-chain trust — it verifies registry
signatures and SLSA provenance coming in, scores every release, and gates CI. But it **produces no
verifiable proof that it audited anything.** An organization cannot require "this dependency tree
was audited by Sentinel under our policy and passed" as a gate — the audit result lives only in a
PR comment or an exit code, not in a portable, signed, offline-verifiable artifact. Phase 19 closes
the loop: Sentinel emits a signed **Verification Summary Attestation** (VSA) — an in-toto/DSSE
statement, Ed25519-signed, that binds an audited tree (by its SBOM digest) to a policy hash and an
aggregate verdict — turning Sentinel from a pure consumer of trust into a *producer* of it, and
creating a deploy-time trust primitive that works fully offline.

## Decisions (brainstorm outcomes)

1. **Standard format: an in-toto `Statement` wrapped in a DSSE envelope, Ed25519-signed over the
   DSSE PAE.** The professionally-correct attestation format — the same shape Sentinel already
   parses for provenance (Phase 9), now emitted. Full SLSA-verifier interop is bounded by the
   custom `predicateType` (a documented boundary), but the envelope/statement are standard.
2. **Subject = the CycloneDX SBOM's sha256.** The SBOM (Phase 14) is the portable artifact that
   travels with a build; binding to its digest lets a deploy gate recompute + match.
3. **Signing is operator-side (CLI), never on the proxy.** The proxy is the shared audit service;
   the attestation *signing key* is the operator's secret (key hygiene, mirroring policy signing).
4. **Verification is pure/offline/total** — `verifyAttestation` never fetches, never throws, and a
   tampered/malformed envelope is `invalid` (fail-closed), never `unknown` (Phase 9's rule).

## Section 1 — Architecture

A new pure `packages/core/src/attest.ts` that both **produces** and **verifies** a Sentinel audit
attestation, reusing repo crypto (`node:crypto` Ed25519, as `policy.ts` does) and the in-toto
shapes Phase 9 established.

- **Produce:** `buildAuditStatement(tree, opts)` → an in-toto `Statement`; `signAttestation(stmt,
  privateKeyPem, keyid)` → a DSSE envelope (Ed25519 sig over the DSSE PAE).
- **Verify:** `verifyAttestation(envelope, publicKeyPem, opts?)` → `{ valid, statement, predicate }
  | { valid: false, reason }` — pure, offline, total, fail-closed.
- **Signing lives in the CLI** (`sentinel attest`), which fetches the tree audit from the proxy,
  writes the SBOM, and signs locally with the operator's key. The proxy never holds the signing key.
- **Invariant #1 untouched** — the attestation is over the deterministic audit result; scoring is
  unchanged.

## Section 2 — The statement, predicate, and signing (DSSE/PAE)

- **`buildAuditStatement(tree: TreeAuditResult, opts: { sbomDigest: string; sbomName: string; now: string }): InTotoStatementV1`** — pure, injected `now`:
  ```
  {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: <sbomName>, digest: { sha256: <sbomDigest hex> } }],
    predicateType: "https://sentinel.dev/attestation/audit-summary/v1",
    predicate: {
      verifier: { name: "sentinel", version: <ENGINE_VERSION> },
      policyHash: <tree.policyHash>,        // which policy the tree was scored under
      verdict: <tree.aggregate.verdict>,    // allow | warn | block
      gated: <tree.aggregate.gated>,
      counts: <tree.aggregate.counts>,      // { allow, warn, block, error }
      packageCount: <tree.packages.length>,
      timestamp: <now>                      // injected
    }
  }
  ```
  A summary predicate (SLSA-VSA-style), not the full per-package report — small, portable, and
  everything a deploy gate needs: *what* (SBOM digest), *under what policy* (`policyHash`), *result*
  (`verdict`/`gated`). `tree.policyHash` comes from a new **optional** `TreeAuditResult.policyHash?`
  that the `/-/audit-tree` route sets (the proxy has `policyHash` in scope) — optional so no existing
  literal changes.
- **`pae(payloadType: string, payload: Buffer): Buffer`** — the DSSE Pre-Authentication Encoding:
  `"DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload` (byte
  lengths, space-separated). A ~6-line pure helper (new — the repo had only the verify side).
- **`signAttestation(statement, privateKeyPem, keyid): DsseEnvelope`** — `payload =
  base64(canonicalJSON(statement))`, `payloadType = "application/vnd.in-toto+json"`, `sig =
  base64(edSign(null, pae(payloadType, payloadBytes), privateKey))` → `{ payloadType, payload,
  signatures: [{ keyid, sig }] }`.
- **`attestationKeyid(publicKeyPem): string`** — `"SHA256:" + base64(sha256(spki-der))`, matching
  Phase 8's `NPM_SIGNING_KEYS` keyid convention, so a verifier with multiple pinned keys selects the
  right one.
- **Determinism** — Ed25519 is deterministic and the only time input is the injected `now`, so the
  same `(tree, sbomDigest, now, key)` yields a byte-identical envelope; the sign/verify round-trip is
  exact.

## Section 3 — Verification, the CLI surfaces, the deploy gate

- **`verifyAttestation(envelope, publicKeyPem, opts?): VerifyResult`** — pure, offline, total:
  1. structurally validate the envelope; recompute PAE; Ed25519-verify each signature against the
     pinned key → none verifies ⇒ `{ valid: false, reason: "invalid-signature" }`.
  2. parse the payload as a Statement; `predicateType` must be the Sentinel audit type ⇒ else
     `{ valid: false, reason: "wrong-predicate" }`.
  3. `{ valid: true, statement, predicate }`. Optional `opts` narrow the gate decision:
     `expectedSbomDigest` (subject binding), `expectedPolicyHash`, `requireVerdict`
     (`allow` | `allow-or-warn`) — a mismatch ⇒ `{ valid: false, reason: "subject-mismatch"
     | "policy-mismatch" | "verdict-<v>" }`. A malformed/tampered envelope ⇒ `invalid`, never
     `unknown` (fail-closed).
- **CLI surfaces:**
  - **`sentinel attest keygen [--out <prefix>]`** — `generateKeypair()`; write `<prefix>.pub.pem`
    and `<prefix>.key.pem` (`mode: 0o600`); print the `keyid`.
  - **`sentinel attest <lockfile> --key <priv.pem> --sbom <file> --out <att.json> [-p <proxy>]`** —
    `fetchTree` (reuse), write the CycloneDX SBOM, compute its sha256, `buildAuditStatement` +
    `signAttestation`, write the DSSE envelope. Print the subject digest + verdict.
  - **`sentinel verify-attestation <att.json> --key <pub.pem> [--sbom <file>] [--policy-hash <h>] [--require allow|allow-or-warn]`** —
    offline `verifyAttestation` with the narrowing opts; print the verified claim; **exit non-zero on
    any failure** — a drop-in deploy gate.
- **Deploy-gate story (the payoff):** a CI job runs `sentinel attest` and publishes the SBOM +
  attestation as artifacts; a later deploy step (any environment, fully offline, pinned public key)
  runs `sentinel verify-attestation` — no proxy, no network, no re-audit. This extends Sentinel's
  enforcement from install/CI time to **deploy time** via a portable, verifiable artifact.

## Section 4 — Testing & Definition of Done

*Testing (hermetic, deterministic):*
- **Round-trip unit tests** (pure) — `buildAuditStatement(tree, { now })` → `signAttestation` →
  `verifyAttestation` ⇒ `{ valid: true }`, statement intact; a fixed `now` + key yields a
  byte-identical envelope (determinism); the subject digest equals the sha256 of the given SBOM
  bytes; the predicate carries verdict/policyHash/counts.
- **Tamper/negative tests** — flip a byte in `payload` ⇒ `invalid-signature`; wrong public key ⇒
  `invalid-signature`; wrong `predicateType` ⇒ `wrong-predicate`; malformed/truncated envelope ⇒
  `{ valid: false }` (never throws); `expectedSbomDigest`/`expectedPolicyHash`/`requireVerdict`
  mismatches ⇒ the specific `reason`. Fail-closed (tampered ⇒ `invalid`, never `unknown`) asserted.
- **PAE conformance** — a known statement produces the exact DSSE PAE string (`DSSEv1 <lenType>
  <type> <lenPayload> <payload>`), so the envelope is standard, not bespoke.
- **CLI e2e** (in-process proxy + `LocalFixtureUpstream`, async `execFile`) — `sentinel attest
  keygen` writes a `0600` private key + a public key; `sentinel attest <lockfile>` against a fixture
  lockfile incl. the malicious `color-stream` writes a valid SBOM + DSSE attestation whose predicate
  verdict is `block`; `sentinel verify-attestation` exits 0 with the right key, and non-zero on a
  wrong key / a mutated attestation / `--require allow` when the verdict is `block` / a `--sbom`
  whose digest doesn't match.
- **Determinism / invariant #1** — attestation is over the audit result; scoring untouched; the
  `scoring is deterministic across runs` test unaffected; `verifyAttestation` is pure/offline (a
  grep-level check that it makes no network call).

*Definition of done:* `npm run build` clean; `npm test` green (record count); the malicious fixture
still blocked (and its attestation verdict is `block`); private keys written `0o600`; ADR-0032
recorded; ARCHITECTURE (the attestation produce/verify layer + deploy-gate flow), CLAUDE (phase
summary + `sentinel attest`/`verify-attestation` + count), and README (attestation usage + the
deploy-gate story) updated.

## Out of scope (deferred beyond Phase 19)

- **The GitHub Action producing/uploading the attestation automatically** — the Action can already
  invoke `sentinel attest`; a turnkey `--attest` input is a thin follow-on.
- **A transparency log / Rekor entry** for the attestation (a public, tamper-evident log) — the
  attestation is offline-verifiable against a pinned key this phase.
- **Multi-signer / threshold attestations** — one signer this phase.
- **A per-package (not summary) attestation** — the predicate is a summary VSA; a full per-package
  in-toto statement is a follow-on.
- **Auto-fetching the pinned public key** from a well-known location — the verifier passes `--key`.

## Invariants preserved

1. **Deterministic score** — the attestation is built *over* the audit result; `remediate`-style
   pure/offline; scoring is untouched; Ed25519 + injected `now` make the envelope reproducible.
2. **LLM never scores** — untouched; the attestation is crypto/metadata, no LLM.
3. **Sync gate cheap** — attestation production is a CLI/batch operation (fetch tree + sign), never
   the inline tarball gate; verification is offline and local.
4. **Cache key = integrity** — unchanged; the attestation subject is the SBOM digest, derived, not a
   cache key.
5. **Proxy transparency** — the proxy only gains an optional `policyHash` on the audit-tree response
   (which it already computes); packument/tarball handling is unchanged; signing is off the proxy.
6. **Rules fail open / audit never crashes** — `verifyAttestation` is total (malformed ⇒ invalid,
   never throw); `buildAuditStatement`/`signAttestation` operate on an already-produced tree result.
7. **Private namespaces authoritative** — unchanged; the attestation attests whatever tree the audit
   produced through the existing routing.
