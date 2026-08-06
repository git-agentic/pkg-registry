# ADR-0055: Bind cached audit reports to package coordinate and integrity

**Status:** Accepted
**Date:** 2026-08-06
**Extends:** ADR-0004 (integrity-hash cache key), ADR-0012 (policy-bound verdicts)

## Context

ADR-0004 correctly requires the actual tarball integrity in every cache key so
changed bytes can never reuse a stale verdict. It also states that the logical
identity is `(name, version, integrity)`. The implementation did not match that
logical identity: `AuditStore` stored and looked up reports in a map keyed only
by `integrity`.

An `AuditReport` is not a pure function of tarball bytes. Several deterministic
rules also consume the requested coordinate or its packument context:

- `typosquat` consumes the package name;
- known advisories and vulnerabilities consume name and version;
- release anomaly consumes version history and release metadata;
- report metadata, remediation, and last-known-good output repeat the requested
  name and version.

Two package coordinates may legitimately serve byte-identical tarballs. With an
integrity-only report map, whichever coordinate was audited first owned the
cache entry. A later `GET /-/explain/:name/:version` returned that first
coordinate's metadata and finding set. This was reproduced hermetically with
`express@1.0.0` and the lookalike `expres@1.0.0` sharing one fixture tarball:
the second response identified itself as `express` and omitted its `typosquat`
finding.

## Decision

`AuditStore` keys every cached report by the exact tuple:

```
(normalized package name, version, actual tarball integrity)
```

The implementation uses an unambiguous NUL-delimited internal key. Persistent
schema-3 rows are re-indexed from their stored `name`, `version`, and report
integrity on load. Every report-serving cache lookup supplies all three
dimensions; there is no integrity-only serving fallback.

The actual bytes hash remains mandatory and load-bearing. A re-publish or
tampered mirror that changes bytes changes the integrity dimension and therefore
misses the cache exactly as ADR-0004 requires. Adding coordinate dimensions does
not weaken content addressing; it prevents byte-identical coordinates from
sharing coordinate-dependent findings.

The proxy runs one active enterprise policy per `AuditStore`, and persisted
reports whose `policy.hash` differs from that active policy are rejected during
load (ADR-0012). This ADR does not add the policy hash to the in-memory tuple
because the active store already provides that isolation.

Approval, approval-request, and violation writes continue to record their
serve-time overlay by integrity. Approval requests and violations already submit
name/version and use the exact tuple. For backward compatibility, the older
approval endpoint may omit name/version; that integrity-only lookup succeeds only
when exactly one cached coordinate has those bytes. Shared-byte ambiguity fails
closed and requires the caller to submit name/version, preventing an arbitrary
coordinate's report from being borrowed.

## Consequences

- `/-/explain`, `/-/audit`, `/-/manifest`, tarball serving, and `/-/audit-tree`
  all receive the report for the requested coordinate even when another package
  uses identical bytes.
- `AuditStore.stats().total` and `recent()` count coordinate-bound audit records,
  not unique tarball blobs. This matches their report/history semantics.
- Cache hits remain sub-millisecond map lookups and still require the actual
  integrity computed from fetched bytes.
- Existing persisted schema-3 rows remain readable; they are indexed under the
  corrected tuple at startup. Schema-1/2 rejection is unchanged.
- Engine/scorer-version invalidation is separate from coordinate identity. A
  calibration after detection changes must still use a cold store until an
  explicit engine-version cache dimension or migration policy is designed.

## Rejected alternatives

### Keep integrity-only reports and rewrite `meta` on response

Rejected. Name/version are inputs to findings, not presentation-only fields.
Rewriting metadata would still reuse incorrect typosquat, advisory,
vulnerability, and release-anomaly results.

### Cache byte-only extraction and rerun coordinate rules on every hit

Potentially valid as a deeper cache split, but rejected for this fix. The current
public cache stores complete `AuditReport` objects, and separating byte-derived
observations from coordinate-derived rules would require a new persisted schema.
The tuple key fixes correctness without changing the audit pipeline.

### Key only by `(name, version)`

Rejected for the original ADR-0004 reason: changed or tampered bytes under the
same version label must never reuse a verdict.
