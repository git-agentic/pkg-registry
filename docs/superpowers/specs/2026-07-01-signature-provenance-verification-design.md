# Sentinel Phase 8 — signature & provenance verification (design)

**Date:** 2026-07-01
**Status:** Approved (brainstorming) — ready for implementation planning
**Implements:** offline verification of the npm registry signature + a policy-driven
provenance/signature requirement gate, replacing today's lossy `signatureStatus` flattening.
**Sequence context:** Phases 1–7 are built (auditing proxy + scoring; approval gate, signed
policy, private registry; macOS/Linux sandbox enforcement; `install --enforce`; `audit-tree`
whole-tree gate). The threat model has always listed "unsigned/tampered artifacts → surface
signature/provenance status," and `upstream.ts` already parses `dist.signatures`/`dist.attestations`
— but both are flattened into one lossy enum and no rule or policy acts on them. Phase 8 makes
that signal real.

---

## 1. Goal & threat model

Sentinel is a proxy between npm and the client. Today `normalizeVersion` collapses
`signed || provenance → "signed"` and discards the detail, so a rule can only ever see one
lossy value and nothing verifies anything. Phase 8:

- **Offline-verifies the npm registry signature** — ECDSA P-256, SHA-256, **DER** encoding
  (Node's default; the common "IEEE-P1363" assumption is wrong for npm — confirmed against the
  live `/-/npm/v1/keys` endpoint this session, where `left-pad@1.3.0` verified with the DER
  default and failed under `ieee-p1363`), over the payload `${name}@${version}:${integrity}`,
  against a configured key set matched by `keyid`. An **`invalid`** signature means the
  upstream/mirror served tampered bytes → **critical** finding → hard-block. This is a genuine
  compromised-mirror / MITM defense for the proxy.
- **Surfaces provenance presence** (`dist.attestations`) and lets policy **require** it, so a
  hijacked or typosquatted publish that lacks provenance in a protected namespace is blocked.

Full Sigstore/Rekor attestation-bundle verification is network-bound and therefore cannot sit
on the sync gate (invariant #3); it is a **named async-enrich follow-up**, not part of this phase.

**Value/verifiability inversion (explicit):** the signal we can verify cheaply and offline
(registry signature) is the *lower*-value one — it catches a tampered mirror, not a malicious
publish (npm signs whatever an attacker published). The *high*-value signal (provenance = "built
by the real CI from the real repo") is network-bound, so this phase gates on provenance
**presence** and defers cryptographic provenance verification.

**Success criteria**
1. A package whose registry signature verifies against a configured key → `signature: "verified"`,
   no signature finding.
2. A package whose signature bytes do not verify (tampered) → `signature: "invalid"` → a
   **critical** finding → **block** under the default policy.
3. A package with no `dist.signatures` → `signature: "unsigned"`; a signature whose `keyid`
   matches no configured key → `signature: "unknown"`.
4. A package with `dist.attestations` → `provenance: "present"`, else `"absent"`.
5. A policy listing a package in `requireSignature` blocks it unless `signature === "verified"`;
   `requireProvenance` blocks it unless `provenance === "present"`.
6. Verification is deterministic and offline: same `(payload, signatures, keys)` ⇒ same verdict,
   no network on the audit path (invariant #3).
7. Tests are hermetic (invariant): synthetic test keys only, **never live npm** in `npm test`.

---

## 2. Data-model un-flattening

Replace the lossy `PackageMeta.signatureStatus: "signed" | "unsigned" | "unknown"` with two
precise fields:

- `signature: SignatureVerdict` where `type SignatureVerdict = "verified" | "invalid" | "unsigned" | "unknown"`
- `provenance: "present" | "absent"`

`UpstreamVersion` stops flattening and carries the raw material so core can verify:
- `signatures: RegistrySignature[] | null` where `interface RegistrySignature { keyid: string; sig: string }` (`sig` is base64, as npm serves it)
- `hasProvenance: boolean` (from `Boolean(dist.attestations)`)

**Blast radius (all mechanical once the types change):** `packages/core/src/types.ts`
(the definition), `packages/proxy/src/upstream.ts` (`UpstreamVersion`, `normalizeVersion`,
`LocalFixtureUpstream`), `packages/proxy/src/server.ts` (meta assembly + the private-package
path), `packages/cli/src/index.ts` (`scan` meta), `scripts/make-fixtures.ts`, the test metas in
`packages/core/test/{audit,capabilities,score}.test.ts` and
`packages/proxy/test/private-serve.test.ts`, `fixtures/registry.json` + `fixtures/index.json`,
and `packages/proxy/public/index.html`.

Respects invariant #5: the packument passthrough still rewrites **only** `dist.tarball`; the new
fields are derived internally for scoring, not stripped from or synthesized onto the npm document.

---

## 3. Offline verification (`packages/core/src/signature.ts`, new)

A pure, offline, deterministic module:

- `interface NpmSigningKey { keyid: string; spkiPem: string; expires: string | null }`
- `NPM_SIGNING_KEYS: NpmSigningKey[]` — npm's published signing key(s) from `/-/npm/v1/keys`,
  bundled as a maintained constant. (The key's `key` field is base64 SPKI DER; convert to SPKI
  PEM once when bundling. Structure verified live this session.)
- `verifyRegistrySignature(payload: { name: string; version: string; integrity: string }, signatures: RegistrySignature[] | null, keys: NpmSigningKey[]): SignatureVerdict`
  - `signatures` null/empty → `"unsigned"`.
  - For the first signature whose `keyid` matches a key in `keys`: build
    `Buffer.from(\`${name}@${version}:${integrity}\`)`, `crypto.verify("sha256", payload, publicKey, Buffer.from(sig, "base64"))`
    (DER default — no `dsaEncoding` override) → `"verified"` on pass, `"invalid"` on fail.
  - No `keyid` match → `"unknown"`.

Verification runs in the audit-assembly path (`runAudit`), which gains an optional
`signingKeys?: NpmSigningKey[]` (default `NPM_SIGNING_KEYS`). The proxy threads its configured
keys (`ServerOptions.signingKeys ?? NPM_SIGNING_KEYS`) through `auditVersion`. The raw
`signatures` + `hasProvenance` arrive as inputs to the audit; `runAudit` calls
`verifyRegistrySignature` and sets `meta.signature`; `meta.provenance = hasProvenance ? "present" : "absent"`.
Keys are a **static input, never fetched at audit time** (invariant #3). Rules stay pure —
verification happens before rules run.

**Audit input shape change:** `AuditTarballInput.meta` drops `signatureStatus`; the audit input
gains `signatures: RegistrySignature[] | null` and `hasProvenance: boolean` (raw material in,
verdict out). `integrity` is already available (from `meta.integrity` or computed from the tarball).

---

## 4. Detection rule (`packages/core/src/rules/provenance.ts`, new)

Add `"provenance"` to the `Category` union. A pure `Rule` (`(AuditInput) => Finding[]`) reading
the already-verified `meta`, using `mkFinding` so weights + diff-multiplier apply:

- `meta.signature === "invalid"` → **critical**, message "registry signature failed verification
  — possible tampering". (Hard-blocks under the default `hardBlockSeverity: "critical"`.)
- `meta.signature === "unsigned"` → **low**, "package has no registry signature".
- `meta.signature === "unknown"` → **info**, "signature present but no trusted key to verify it".
- `meta.provenance === "absent"` → **info**, "no build provenance attestation".
- `verified` + `present` → no finding.

Evidence for these findings is metadata-level (no file/line); `mkFinding` handles empty evidence.
Registered in `rules/index.ts`.

---

## 5. Policy gate (`packages/core/src/policy.ts` + `score.ts`)

Two optional pattern lists on `EnterprisePolicy` (both optional, default `[]` — like `treeGate`,
so the default-policy canonical hash does not churn):

- `requireSignature?: string[]` — a matched package must be `signature === "verified"`.
- `requireProvenance?: string[]` — a matched package must have `provenance === "present"`.

In `score.ts`, beside the existing `denied`:
```
const reqSig  = (policy.requireSignature  ?? []).some((p) => matchPackage(p, audit.meta.name)) && audit.meta.signature !== "verified";
const reqProv = (policy.requireProvenance ?? []).some((p) => matchPackage(p, audit.meta.name)) && audit.meta.provenance !== "present";
if (denied || hardBlock || reqSig || reqProv) verdict = "block";
```
Record the block reason (e.g. `requireSignature: <pattern>`) alongside the existing denial
reasons. Validate both fields in `parsePolicy` exactly like `privateNamespaces` (array of strings
when present). `matchPackage` (existing, used by allow/deny) does the pattern matching.

---

## 6. Surfacing

- `packages/cli/src/format.ts` `formatReport`: render a `signature` line
  (green `verified` / red `invalid` / yellow `unsigned` / gray `unknown`) and a `provenance` line
  (green `present` / gray `absent`), replacing the current single `signature` line.
- The `manifest` endpoint already returns `meta`, so both fields reach the CLI/JSON with no
  endpoint change.
- `packages/proxy/public/index.html`: display `signature` + `provenance` in place of the old
  `signatureStatus` span.

---

## 7. Fixtures & hermetic testing

`scripts/make-fixtures.ts` generates a **test P-256 keypair** (deterministic is not required —
generated once per fixture build), and after packing each fixture (so `integrity` is known)
signs `${name}@${version}:${integrity}` with the test private key (DER) and writes:
- a `signatures: [{ keyid, sig }]` array into each signed version's `registry.json` entry,
- an `attestations` marker for versions that should carry provenance,
- the test **public** key(s) to `fixtures/signing-keys.json` (structure: `NpmSigningKey[]`).

Tests load `fixtures/signing-keys.json` and pass it as `signingKeys` to `createServer` /
`runAudit`, so verification is fully hermetic. Fixture coverage:
- a validly-signed benign package → `verified`;
- a **tampered** fixture (signature over a wrong payload, or a flipped byte) → `invalid` →
  critical → **block** under default policy;
- an unsigned fixture (no `signatures`) → `unsigned`;
- a fixture with `attestations` → `provenance: "present"`; one without → `"absent"`;
- unit tests for `verifyRegistrySignature` (verified / invalid / unsigned / unknown-keyid) with
  synthetic keys, including the DER-default round-trip and tamper rejection;
- policy tests: `requireSignature`/`requireProvenance` patterns block a missing-signal package
  and pass a satisfying one.

The malicious `color-stream` fixture remains scored-as-text and never executed. No test hits
live npm; `NPM_SIGNING_KEYS` (the real bundled key) is validated manually, not in the suite.

---

## 8. Non-goals (deferred)

- **Full Sigstore/Rekor attestation-bundle verification** — network-bound; the async-enrich
  follow-up. This phase gates on provenance *presence* only.
- **Treating key expiry as auto-invalid** — expiry is surfaced/recorded, not enforced (avoids
  false criticals on packages signed under a since-rotated key). A later refinement.
- **Automatic key-set refresh** from `/-/npm/v1/keys` — keys are a static configured input.
- **Verifying provenance contents** (which source repo / which builder identity) — belongs with
  the Sigstore follow-up.

---

## 9. ADR-0021

**ADR-0021 — signature & provenance verification.** Records: offline registry-signature
verification (ECDSA P-256 / SHA-256 / **DER**, correcting the IEEE-P1363 assumption, with the
live-endpoint evidence); a configured key set matched by `keyid` with rotation/expiry noted as a
static input (never fetched on the audit path, invariant #3); un-flattening `signatureStatus`
into `signature` + `provenance`; the rule-surfaces / policy-gates split (verification can't live
in a pure rule); and full Sigstore verification as the async-enrich follow-up.
