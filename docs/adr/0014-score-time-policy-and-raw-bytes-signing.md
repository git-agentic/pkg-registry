# ADR-0014: Score-time policy application and raw-bytes Ed25519 signing

**Status:** Accepted
**Date:** 2026-06-25
**Phase:** 2 (refines ADR-0012; amends ADR-0002/0008)

## Context

ADR-0012 makes policy per-enterprise, versioned, and signed. Two mechanics were
unspecified: where scoring weight is computed, and how a policy is signed/verified.

## Decision

1. **Weight moves out of finding-creation into scoring.** `runAudit` produces
   policy-independent findings (`severity` + `onChangedFile`, no weight) cached by
   integrity. `score(audit, policy)` applies `severityWeight`, `diffMultiplier`,
   rule enable/disable, allow/deny waivers, thresholds, and the hard-block override,
   producing the verdict and per-finding weight. This is what makes "findings are
   policy-independent, re-scored per policy" actually true. `auditTarball` survives
   as `score(runAudit(...), DEFAULT_POLICY)` for the offline CLI and tests.
2. **A waiver excludes a finding from BOTH the penalty sum AND the hard-block
   severity check**, while keeping it visible (`waived` + `waivedBy`). `deny` forces
   `block`; `allow` cannot rescue a denied package.
3. **Sign the raw policy bytes** with Ed25519 (`node:crypto`); verify the file
   as-is (`crypto.verify(null, raw, pubKey, sig)`); `policyHash = sha256(raw bytes)`.
   The in-code `DEFAULT_POLICY` (no file) is hashed via canonical JSON. No JSON
   canonicalization on the verify path.
4. **Fail closed.** No policy configured → built-in default (logged). Configured but
   invalid (missing/parse/sig/pubkey/schema) → the proxy exits non-zero; it never
   silently degrades to the default.

## Consequences

- The determinism invariant (ADR-0002) becomes "same bytes + same policy ⇒ same
  verdict"; the existing determinism test pins the default policy.
- ADR-0008's diff multiplier is now a score-time, policy-owned value.
- Caching: findings are computed policy-independently; the proxy runs one policy per
  process, so the report scored under that policy is cached by integrity and persisted
  entries scored under a different `policy.hash` are dropped on load.
- One signed policy per process (ADR-0012 D-tenancy); per-request multi-tenant
  routing, key rotation, and multiple signers are deferred.
