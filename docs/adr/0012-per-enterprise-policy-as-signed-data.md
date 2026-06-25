# ADR-0012: Per-enterprise policy as versioned, signed data

**Status:** Accepted
**Date:** 2026-06-24
**Deciders:** Founder/Eng, Security lead
**Phase:** 2

## Context

Phase 1 keeps all tuning — severity weights, the diff multiplier, verdict
thresholds, the hard-block severity — in a single `POLICY` object in
`packages/core/src/score.ts` (ADR-0002/0008). That is deliberately *data, not code*
so it can become per-enterprise without code changes. Enterprises need to set their
own risk appetite (a fintech may block at a stricter threshold than a hobbyist),
maintain allowlists (e.g. clear `esbuild`'s legitimate network postinstall without
weakening detection — see ADR-0009's live spot-check), and do so under change
control and audit. Policy that varies per customer and affects security verdicts
must be **distributed, versioned, and tamper-evident**.

## Decision

Promote `POLICY` to a first-class, per-enterprise **policy document**: weights,
thresholds, diff multiplier, rule enable/disable, package/namespace allowlists and
denylists, and the permission-manifest defaults (ADR-0011). Policy documents are
**versioned** and **cryptographically signed**; the proxy loads a customer's signed
policy and records a `policyHash` alongside each verdict. Because the same bytes can
yield different verdicts under different policies, the verdict cache key becomes
`(integrity, policyHash)` (extending ADR-0004); findings remain integrity-keyed and
policy-independent.

## Options Considered

### Option A: Versioned, signed policy documents per enterprise (chosen)
| Dimension | Assessment |
|-----------|------------|
| Multi-tenant correctness | High — verdicts are reproducible *given* a policy version |
| Auditability | High — signed, versioned, every verdict carries its policyHash |
| Tamper resistance | High — signature verified before load |

**Pros:** Each customer's risk appetite is explicit and change-controlled; verdicts
stay reproducible (determinism invariant holds *per policy version*); a verdict can
always be explained by "engine vX + policy hash Y"; allowlists tame false positives
without code edits.
**Cons:** Policy distribution, signing, and key management infrastructure; cache and
reporting must carry the policy dimension; need tooling to author/validate policies.

### Option B: Policy as plain config (env/YAML), unsigned
**Pros:** Simple to ship.
**Cons:** No tamper evidence on a security-critical input; hard to prove which
policy produced a historical verdict; drift between environments. Weak for an
enterprise control. Rejected.

### Option C: Keep one global policy (status quo)
**Pros:** Simplest; nothing to manage.
**Cons:** One size cannot fit fintech and hobbyist; no per-customer allowlists;
blocks the enterprise sale. Fine for the MVP, insufficient for Phase 2. Superseded.

## Trade-off Analysis

The non-negotiable is that **a security verdict must remain reproducible and
explainable** even when policy is customer-specific. Signed, versioned documents
preserve exactly that: determinism is now "same bytes + same policy version ⇒ same
verdict," and every stored verdict carries the `policyHash` needed to reproduce it.
The added infrastructure (signing, distribution, policy-aware caching) is the
standard cost of multi-tenant security configuration and is justified by the
enterprise requirement. Unsigned config would be cheaper but undermines the
auditability that is the whole point.

## Consequences

- **Easier:** per-customer risk appetite and allowlists without code changes;
  defensible audit trail (engine version + policy hash per verdict); false-positive
  management (allowlist `esbuild`-style cases) becomes policy, not patches.
- **Harder:** policy signing/key management and distribution; cache key and all
  reporting gain a policy dimension; need a policy authoring/validation tool and a
  safe default policy.
- **Revisit:** the determinism test (ADR-0002) is reframed as "deterministic given a
  fixed policy version"; ADR-0004's cache key extends to `(integrity, policyHash)`.

## Action Items
1. [ ] Define the policy schema (weights, thresholds, rule toggles, allow/deny lists, manifest defaults).
2. [ ] Sign + version policy documents; verify signature before load; record `policyHash` per verdict.
3. [ ] Extend the verdict cache key to `(integrity, policyHash)`.
4. [ ] Ship a default policy + a policy authoring/validation CLI.
