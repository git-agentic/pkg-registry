# ADR-0029: Release-anomaly signals — maintainer change, dormancy, new-package, capability novelty

**Status:** Accepted (Phase 16)
**Date:** 2026-07-08

## Context

Every rule through Phase 13 (`install-scripts`, `secret-exfil`,
`network-egress`, `obfuscation`, `provenance`, `typosquat`) plus the
score-time `dependency-confusion` gate scores a release **in isolation** —
`AuditInput` carries the audited version's own files and metadata, never
anything about the versions that came before it. That blind spot hides an
entire attack class: a package with a long clean history whose *release*
is anomalous relative to that history. Three concrete shapes:

- **Account/ownership takeover** — a maintainer swap on an established
  package (the `event-stream` pattern: the new maintainer ships a version
  the old one never would have).
- **Dormancy resurrection** — a package silent for a year or more suddenly
  publishes again; legitimate revivals happen, but so does an attacker
  reviving an abandoned name.
- **Fresh-malware / throwaway package** — a brand-new package (`versionCount
  === 1`) that already runs install scripts, or that ships a dangerous
  capability (network/process) it had no reason to add relative to its own
  prior version.

ADR-0026 named "maintainer-change anomalies" explicitly as **out of scope**
for Phase 13 — "both checks are name-only" — and deferred it. Phase 15
(ADR-0028) added `HistoryDb`, a durable, queryable record of past audits,
but that store is opt-in observability, not an input to scoring; it doesn't
give the rule pipeline a per-package "what happened last time" signal by
itself. Phase 16 closes ADR-0026's deferred gap using data Sentinel already
has on hand at audit time — the npm packument — rather than requiring
`HistoryDb`.

## Decision

- **`release-anomaly` — a pure rule** (`packages/core/src/rules/
  release-anomaly.ts`, registered in `RULES`, rule count 7). It reads a new,
  optional `AuditInput.releaseContext: ReleaseContext | undefined` and is a
  no-op when absent. Three signals:
  1. **Maintainer change.** If `releaseContext.previousMaintainers` is known
     and none of them remain in the current maintainer set, `high` severity
     ("possible account/ownership takeover"). If the set changed but at
     least one previous maintainer remains, `low` severity ("added a new
     maintainer").
  2. **Dormancy resurrection.** If the gap between
     `previousPublishedAt`/`currentPublishedAt` is ≥365 days, `low`
     severity.
  3. **New-package risk.** If `versionCount === 1` and
     `meta.hasInstallScripts`, `medium` severity — a first-ever version that
     already runs install scripts.
- **`capabilityNoveltyFindings` — a pure helper, not a rule**
  (`packages/core/src/rules/capability-novelty.ts`), called from
  `buildAudit` (`packages/core/src/audit.ts`) rather than added to `RULES`.
  Reason: it needs `capabilityDelta`, which `buildAudit` computes *after*
  `runRules` returns (the delta is diffed against a baseline extraction,
  not available inside the synchronous rule-input shape). Signal 4: if
  `capabilityDelta.added` contains a `network` or `process` capability *and*
  `releaseContext.previousVersion` exists (a predecessor to be novel
  relative to), `medium` severity, `metadata` category, ruleId
  `capability-novelty`.
- **`ReleaseContext`** (`packages/core/src/types.ts`) is a new, all-optional
  type: `previousVersion`, `previousMaintainers`, `previousPublishedAt`,
  `currentPublishedAt`, `versionCount`. `AuditInput.releaseContext?` carries
  it into the rule pipeline. The server derives it once per audit:
  `UpstreamPackument.time?: Record<string, string>` (mapped from the
  packument's `time` field in `NpmUpstream` and `LocalFixtureUpstream`) feeds
  the new, exported, pure `buildReleaseContext(pm, version)` in
  `packages/proxy/src/server.ts`, which is passed into `runAudit` from
  `auditVersion`. No new upstream call — `time` and per-version
  `maintainers` are already present on the packument document that
  `auditVersion` fetches for every audit.
- **All four signals are `metadata`-category weighted findings** — none is
  added to the hard-block condition in `score()`. Power comes from
  compounding, not from any single signal blocking on its own.
- **Inert by default.** No `releaseContext` (e.g. a private-store package
  that bypasses `auditVersion`'s upstream branch entirely, or an upstream
  that doesn't supply `time`) ⇒ `release-anomaly` returns `[]` and
  `capabilityNoveltyFindings` returns `[]`. No opt-in policy field is
  required — the signal only fires when the underlying packument data is
  present.

## Determinism (invariant #1 untouched)

Both the rule and the helper are pure functions of their inputs: no I/O, no
policy, no wall-clock. `daysBetween(a, b)` (`release-anomaly.ts`) parses two
*given* ISO timestamps with `Date.parse` — it never calls `Date.now()` or
constructs `new Date()` with no argument. "Dormant ~N days" is computed
entirely from the packument's own `time` map, so "fresh" here is intrinsic
to the release pair being compared (previous publish timestamp vs. current
publish timestamp), never relative to when the audit itself runs — the same
audit re-run tomorrow, next month, or next year against the same packument
data produces the identical finding set. `capabilityNoveltyFindings` reads
only the already-computed, already-deterministic `capabilityDelta` (Phase 9)
and the injected `releaseContext` — no independent I/O of its own. A grep
guard in the Phase 16 test suite (`packages/core/test/
rules-release-anomaly.test.ts`, `packages/core/test/
capability-novelty.test.ts`) asserts neither source file calls
`Date.now()`/`new Date()` with no argument, so a future edit that
reintroduces a clock read fails CI rather than silently breaking the pinned
`scoring is deterministic across runs` test.

## Consequences

- The server derives `releaseContext` from the packument it has *already*
  fetched to resolve the audited version (`auditVersion`'s existing
  `upstream.getPackument(pkg)` call) — no new network round-trip, no new
  upstream method.
- Weighted, not single-signal-blocking: a legitimate maintainer handoff (one
  new co-maintainer added, old ones still present) costs only `low`, and
  even the `high` full-takeover signal alone (100 → 75 under default
  weights) lands at `warn`, not `block` — an operator who wants a harder
  stance raises `hardBlockSeverity`, adds to `deny`, or waives a known-good
  transfer via `policy.allow`/`policy.rules.disabled`, the same escalation
  path ADR-0026 established for `typosquat`/`dependency-confusion`.
- Four more findings can now compound into a single score alongside the
  existing behavior/identity findings, so a package that trips both, e.g., a
  maintainer-change *and* a capability-novelty signal will read noticeably
  lower than the same tarball audited without `releaseContext` — expected
  and by design, not a regression.
- `LocalFixtureUpstream` needed a real fix to exercise this at all: it had
  been hardcoding `maintainers: []` per version rather than reading the
  fixture registry's per-version maintainer list, which would have made
  signal 1 permanently inert in tests. `make-fixtures` now emits per-package
  `time` and per-version `maintainers`, and three new synthetic multi-version
  fixtures (`steady-lib`, `hijacked-lib`, `freshdrop`) exercise the
  no-anomaly, full-takeover, and new-package-risk paths respectively.

## Deferred

- **Per-enterprise dormancy threshold** — 365 days is a fixed constant
  (`DORMANCY_DAYS` in `release-anomaly.ts`), not a policy field; an operator
  who wants a shorter or longer resurrection window can't tune it yet.
- **Version-cadence / semver-jump anomalies** — no signal for "this package
  usually patch-bumps monthly and just major-bumped after a week," or for a
  suspicious jump in the semver itself.
- **Maintainer-reputation graph** — a maintainer name appearing on this
  package for the first time is not cross-checked against that maintainer's
  history on *other* packages; `release-anomaly` only ever compares a
  package against its own immediately-previous version.
- **`HistoryDb`-backed comparison** — Phase 15's durable store could in
  principle supply a richer "previous version" than the packument's own
  adjacent-version lookup (e.g. across a longer history, or reconciling
  server-observed vs. packument-claimed state), but `release-anomaly`
  reads only the packument today; wiring `HistoryDb` as an alternate or
  corroborating source is future work.
- **`_npmUser` / registry-authenticated publisher identity** — the rule
  compares the packument's `maintainers` array (package-level ACL), not the
  actual authenticated publisher (`_npmUser`) of a given version, which
  npm's registry API exposes on some documents but which `UpstreamPackument`
  does not currently surface.

## Rejected

- **A `Date.now()`-based freshness signal** ("this release happened within
  the last N days of *right now*") — rejected outright: it would make the
  same `(audit, policy)` pair produce a different finding set depending on
  *when* the audit runs, breaking invariant #1 and the pinned determinism
  test. Every signal in this ADR compares two points already fixed in the
  immutable packument (previous publish vs. current publish, or previous
  maintainers vs. current maintainers) — never "now."
  - *Nuance (invariant #4, not #1):* `versionCount`/`previousVersion` are
    derived from the packument, which grows as sibling versions publish — so
    the same tarball `integrity` can rescore over a package's life (e.g. a
    first release's `new-package-risk` finding disappears once a v2 exists).
    This is not a wall-clock read (a given run is still fully deterministic and
    the pinned test holds); the drift is monotonic and *conservative* — the
    `versionCount === 1` penalty only ever *lifts* as a package matures, never
    tightens — and every signal is weighted-never-block, so a re-score can't
    flip a benign verdict to `block`.
- **A standalone hard-block for maintainer change** — rejected as too
  false-positive-prone: legitimate ownership transfers (a maintainer
  handing a package to a new owner, a company reorganizing its npm org)
  are common and can't be distinguished from a takeover by maintainer-set
  membership alone. A weighted `metadata` finding that compounds with other
  signals — the same posture ADR-0026 took for `typosquat`/
  `dependency-confusion` — lets an operator escalate via policy if their
  risk tolerance demands it, without Sentinel itself blocking every
  legitimate handoff by default.

Extends ADR-0026 (supply-chain identity heuristics — completes the
maintainer-anomaly gap ADR-0026 explicitly deferred; both share the
weighted-`metadata`/inert-by-default/compounding posture and the same
escalation path via `deny`/`hardBlockSeverity`/`policy.allow`). Also
extends ADR-0008 (diff-audit weighting — all four Phase 16 findings are
metadata-only with no `onChangedFile` signal, so none is ever
diff-multiplied, matching how `provenance` and the Phase 13 findings
behave) and ADR-0013 (capability-delta trigger — `capability-novelty` is a
downstream consumer of the same `CapabilityDelta`/`capabilityDelta` ADR-0013
introduced for the approval-gate trigger, reused here as a scoring signal
rather than an approval trigger). Supersedes nothing.
