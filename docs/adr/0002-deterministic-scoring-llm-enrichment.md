# ADR-0002: Deterministic heuristic scoring; the LLM never sets the score

**Status:** Accepted
**Date:** 2026-06-24
**Deciders:** Founder/Eng, Security lead
**Phase:** 1

## Context

The product's core output is a 0–100 safety score and a verdict. The original
brief calls for an "LLM-backed diff-audit pipeline." But the buyers are
enterprises adopting a security gate, and a security gate has non-negotiable
properties: the verdict must be **reproducible** (same input ⇒ same output),
**auditable** (explainable from fixed rules), and **available offline** (no
dependency on a third-party model's uptime, rate limits, or pricing for a
deploy-blocking decision). LLM outputs are non-deterministic, can drift across
model versions, and add latency and a network dependency.

We must reconcile "LLM-backed" with "a security verdict you can trust and test."

## Decision

The score and verdict are produced **entirely by deterministic heuristic rules**
(`packages/core/src/rules/`). The LLM is a **pluggable enrichment adapter**
(`LlmAuditAdapter`) that runs only in the asynchronous enrich phase and may only
add a human-readable `llmSummary` and *supplementary* findings — it can never
change the score or the verdict. The default adapter is `NoopLlmAdapter`; the
engine is fully functional with no model and no API key.

## Options Considered

### Option A: Heuristic core + LLM enrichment adapter (chosen)
| Dimension | Assessment |
|-----------|------------|
| Determinism | High — pure functions over bytes |
| Testability | High — "catches the malware" is a hard assertion |
| Offline | Yes |
| Explainability of findings | High (rules) + optional prose (LLM) |

**Pros:** Reproducible/CI-gateable; degrades gracefully when the model is down or
the key is missing; cheap inline; still gets model-quality explanations where they
help.
**Cons:** Rules require manual authoring and tuning; novel attacks need a new rule
(the LLM can *flag* them in enrichment but can't move the score until a rule exists).

### Option B: LLM produces the score
**Pros:** Potentially catches novel/obfuscated attacks the rules miss; less rule
authoring.
**Cons:** Non-deterministic verdicts; model-version drift silently changes
security posture; network + latency + cost on the hot path; prompt-injection from
package contents could manipulate the score; "why was this blocked?" becomes
"the model said so." Disqualifying for a gate.

### Option C: Hybrid where the LLM can override within a band
**Pros:** Blends signals.
**Cons:** Reintroduces non-determinism into the verdict and makes the score
un-reproducible; the worst of both for testing and audit. Rejected.

## Trade-off Analysis

We trade some recall on novel attacks (Option B's upside) for determinism,
testability, and availability — the properties that make the output usable as an
enforcement gate. The LLM's value (explaining *why* an obfuscated blob is
dangerous, summarizing a diff in plain English, surfacing candidate findings for a
human to promote into a rule) is fully captured in the enrich phase without
contaminating the verdict. This keeps the determinism invariant (ADR tested by
`scoring is deterministic across runs`) intact.

## Consequences

- **Easier:** verdicts are reproducible and unit-testable; the engine runs with no
  external dependency; security review of the scorer is tractable.
- **Harder:** detecting genuinely novel patterns depends on rule authoring cadence;
  we must build a workflow to turn LLM-surfaced findings into reviewed rules.
- **Revisit:** if enrichment consistently surfaces real findings the rules miss,
  consider a human-in-the-loop "promote to rule" pipeline — but the score stays
  rules-only.

## Action Items
1. [x] `LlmAuditAdapter` interface with `NoopLlmAdapter` default; `AnthropicLlmAdapter` stub.
2. [x] Keep the determinism test green.
3. [ ] Build the async enrich worker (out of Phase 1 inline scope) and a
       "candidate finding → rule" review queue.
