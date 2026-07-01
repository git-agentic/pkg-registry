# ADR-0020: Whole-tree lockfile audit via proxy fan-out + server-side aggregate

**Status:** Accepted (Phase 7)
**Date:** 2026-07-01

## Context

Verdicts existed only per package — via `sentinel audit <pkg>` or as a side effect of
the proxy serving a tarball. There was no single-pass answer to a CI pipeline's question:
"is my whole resolved dependency tree acceptable under policy?" A malicious transitive
dependency was scored like any other tarball, but nothing rolled per-package verdicts into
one gate with a process exit code.

## Decision

Add `sentinel audit-tree [lockfile]`. The CLI parses the npm `package-lock.json` (v2/v3)
into registry coordinates (lockfile-format knowledge is a client concern) and POSTs them to
a new `POST /-/audit-tree` endpoint. The proxy fans out over the existing integrity-cached
`auditVersion()` path — reusing byte acquisition, the enterprise policy, and private-store
handling — and computes the aggregate + gate decision server-side, where the policy lives.

- **Bytes come from the proxy, not a local cache.** Rejected an offline/local-cache backend:
  it would re-implement byte acquisition + policy loading and diverge from the
  proxy-owns-the-store architecture. Proxy-backed composes with install (mostly cache hits).
- **Aggregation is worst-case-wins** (`block` ⊐ `warn` ⊐ `allow`), computed by pure,
  order-independent reduction (invariant #1).
- **The gate threshold is policy data:** a new `treeGate` field on `EnterprisePolicy`
  (default `"block"`), not a hardcoded verdict comparison.
- **Full-mode per package** — a pinned set, so the ADR-0008 diff multiplier does not apply.
- **Errors fail open per package** (invariant #6): an unresolvable dependency is a surfaced
  `error` row that never sets the aggregate verdict or trips the gate.

## Consequences

- CI gets a real gate: `sentinel audit-tree` exits non-zero on a gated tree.
- Requires a running proxy (consistent with `sentinel audit`).
- Deferred: CycloneDX SBOM output; lockfile-integrity-vs-served-integrity tamper detection;
  yarn/pnpm lockfiles; treating unresolved deps as a hard gate failure.
- **The CLI exit code reflects only the policy verdict.** `error` rows (unresolvable
  packages, or audits that throw) are surfaced in `counts.error` and per-row, but never
  trip the gate. A tree that is entirely `error` rows — mass resolution failure, or the
  proxy unreachable per-package — yields `verdict:"allow"`, `gated:false`, and exits `0`:
  a deliberate fail-open when the auditor can't audit. A `--fail-on-error` flag to make
  error rows gate is deferred.

## Rejected

- **Local/offline aggregation** — would duplicate byte acquisition, policy loading, and
  private-store handling already owned by the proxy; diverges from the proxy-owns-the-store
  architecture this repo is built around.
- **Hardcoded gate verdict comparison** — the threshold is per-enterprise policy, not code,
  matching how every other threshold in the scoring path is data (`POLICY` in `score.ts`).

Extends ADR-0001 (proxy wedge), ADR-0004 (integrity cache key), ADR-0008 (diff multiplier,
which this path deliberately does not apply); supersedes nothing.
