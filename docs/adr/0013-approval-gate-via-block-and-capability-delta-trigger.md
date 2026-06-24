# ADR-0013: Approval gate via the block path; capability-delta-vs-prior-approved trigger

**Status:** Accepted
**Date:** 2026-06-24
**Phase:** 2 (refines ADR-0011 stage B)

## Context

ADR-0011 stage B adds an install-time approval flow without a sandbox. Two
concrete mechanics were left open: how an approval gates an install, and what
re-triggers approval across versions.

## Decision

1. **Gate via the existing `block` policy**, not a new policy mode. Under `block`
   the proxy `403`s on `verdict==='block'` OR an unapproved capability delta
   (`approval required` / `approval denied`). Under `observe` the manifest is
   advisory (headers only). This reuses the Phase 1 `403` path and keeps the
   policy surface a single knob.
2. **Re-approval triggers on a capability delta vs the prior _approved_ version.**
   First sight of any capability requires approving the full set; later versions
   only re-prompt when a NEW (kind, target) atom appears. Capabilities are a
   complete, deterministic inventory in `@sentinel/core` (schema 2); approval is
   mutable proxy state keyed by integrity.

## Consequences

- Because gating folds into `block`, *every* first-sight capable package `403`s
  under enforcement. npm aborts on the first `403`, so a dependency tree must be
  cleared via a **preflight → batch-approve → install** workflow (documented in
  the design + `sentinel preflight`), not per-package retry.
- Two diffs coexist: `capabilityDelta` (vs prior published version, in the report)
  is informational; `approvalRequired` (vs prior approved version, at the gate) is
  the set a user/agent acts on.
- **Approval API authentication is out of scope** for stage B (trusted
  single-tenant context); it is a prerequisite for multi-tenant/untrusted
  deployment and is deferred to the ADR-0012 era.
- Determinism invariant holds for capabilities (pure function of files); approval
  state is deliberately excluded from the deterministic report.
