# Phase 16 — Maintainer & Release-Anomaly Signals

**Date:** 2026-07-08
**Status:** Approved design, pre-implementation
**Extends:** ADR-0026 (supply-chain identity heuristics — completes its explicitly-deferred
maintainer-anomaly work) and ADR-0002 (deterministic scoring — the hard constraint this
design is built around). Reuses the existing predecessor mechanism (`previousVersion` /
`baselineTarball` / `capabilityDelta`) for the version-to-version comparison. (ADR-0029 will
verify and cite the exact baseline/diff ADR number before recording.) Supersedes nothing.

## Problem

Sentinel scores every release **in isolation**. Its rules detect what a package *does*
(install scripts, network egress, obfuscation, secret exfil), what it *is* (signatures,
provenance), and whether its *name* is a look-alike (typosquat, dependency-confusion) — but
nothing detects that a release is anomalous **relative to the package's own history**. The
highest-severity real-world supply-chain attacks are exactly this shape: an attacker takes
over a trusted maintainer account and ships a malicious release of an established, popular
package (event-stream, ua-parser-js, node-ipc). A brand-new maintainer, a package resurrected
after long dormancy, or a package that *never ran install scripts suddenly running one* are
signals invisible to per-release analysis. Phase 15 gave Sentinel durable history; ADR-0026
explicitly deferred maintainer-anomaly detection. Phase 16 delivers it.

## Decisions (brainstorm outcomes)

1. **A new pure rule + one audit-level helper**, not a score-time policy gate. The signals are
   intrinsic to the release-vs-history comparison (policy-blind), so they belong in the rule
   pipeline like `typosquat`, priced by POLICY weights.
2. **Determinism is the binding constraint.** Every signal derives from **immutable** packument
   data (two versions' maintainer sets, two immutable publish timestamps, the version ordinal).
   No `Date.now()`/wall-clock. "Fresh/throwaway package" is expressed intrinsically ("this is the
   package's first version and it already requests dangerous capabilities"), never "published <
   N days ago."
3. **Weighted, never a standalone hard block** — consistent with the identity-heuristics
   precedent (ADR-0026). The power is compounding: the engine sums penalties, so
   maintainer-change + dormancy + capability-novelty on one release stack into a high score
   without any single signal over-blocking a benign version bump.
4. **Inert by default** — no `releaseContext` (first-ever version, direct tarball audit, or an
   upstream without `time`) ⇒ the rule and the helper produce nothing; every existing test is
   unaffected.

## Section 1 — Architecture & the determinism constraint

New pure rule `packages/core/src/rules/release-anomaly.ts`, registered in `rules/index.ts`,
following the existing rule contract — `(AuditInput) => Finding[]`, policy-blind, wrapped by
`runRules` (fails open), emitting `metadata`-category **weighted** findings via `mkFinding()`.

- **New data plumbing:** `AuditInput` gains an optional `releaseContext`:
  `{ previousVersion?: string; previousMaintainers?: string[]; previousPublishedAt?: string;
  currentPublishedAt?: string; versionCount?: number }`, derived by `server.ts` from the
  already-fetched packument. `buildAudit` accepts it in `opts` and places it on the `input` it
  passes to `runRules`.
- **Determinism (the hard constraint):** every signal is computed from immutable inputs — two
  versions' maintainer sets, two immutable publish timestamps, the version ordinal. No
  `Date.now()`. A grep-level test asserts neither new source file references the clock. The
  `scoring is deterministic across runs` test stays green.
- **Inert by default:** a first-ever version has no predecessor, so maintainer-change and
  dormancy simply don't fire; a missing `releaseContext` ⇒ the rule is a no-op.

## Section 2 — The signals

Four deterministic, intrinsic release-vs-history signals, all `metadata`-category weighted
findings (never a standalone hard block):

1. **Maintainer change** (headline) — the current release's maintainer set differs from the
   previous version's. Two gradations:
   - *new maintainer added* (current ⊋ previous — an addition; medium signal),
   - *ownership turnover* (previous maintainers gone / fully replaced — the account-takeover
     shape; higher signal).
2. **Dormancy resurrection** — a large gap between the previous version's publish timestamp and
   this release's (both immutable packument `time` values). Threshold a sensible constant in the
   rule (e.g. ≥ 365 days). Low-weight alone; compounds with the others.
3. **New-package risk** — the audited release is the package's **first** published version
   (`versionCount === 1`, intrinsic — no clock) **and** it carries an install-script or
   network-egress capability. The throwaway/fresh-malware pattern, distinct from takeover.
   (Signals 1–3 live in the pure rule.)
4. **Capability novelty** — a dangerous capability (install-script or network) present in this
   release that the **previous version did not have**. Sourced from Phase 9's already-computed
   `capabilityDelta.added` — see Section 3.

Thresholds (the dormancy cutoff) are sensible constants **in the rule**; POLICY prices the
resulting severities (the rule decides *if* a finding fires, POLICY decides its cost — the
established rule/policy split). Per-enterprise threshold tuning is out of scope (deferred).

## Section 3 — Data plumbing & capability-novelty sourcing

- **Packument → `releaseContext`:** `server.ts` already fetches the packument and computes
  `prev = previousVersion(Object.keys(pm.versions), version)`. It builds `releaseContext` from
  immutable packument data: `pm.time[version]` / `pm.time[prev]` (publish timestamps),
  `pm.versions[prev].maintainers` (predecessor maintainer set), and
  `Object.keys(pm.versions).length` (version count). It threads this into the audit call →
  `buildAudit` → `AuditInput.releaseContext`. `PackumentDoc`/`VersionMeta` in `upstream.ts` gain
  a `time` map; `NpmUpstream` maps it from the real packument's `time` object, and
  `LocalFixtureUpstream` serves it from the fixture registry.
- **Capability novelty (signal 4) reuses Phase 9's baseline — emitted where the delta exists.**
  `runRules` runs on `AuditInput = {meta, files, mode, releaseContext}` **before** `buildAudit`
  computes `capabilities`/`capabilityDelta`. So signal 4 cannot live in the pure rule (the delta
  isn't computed yet). Instead, a small **pure** helper
  `capabilityNoveltyFindings(capabilityDelta, releaseContext): Finding[]` is called in
  `buildAudit` immediately after `capabilityDelta` is computed, and its findings are concatenated
  onto the rule findings. It fires only when `capabilityDelta.added` contains a *dangerous*
  capability (install-script/network) and a predecessor exists (`releaseContext.previousVersion`
  present, so it's a real "newly added vs prior version", not a first release). Same
  `metadata`-category weighted finding family as signals 1–3, so all four compound in the score.
  A null `capabilityDelta` (no baseline) ⇒ no finding (inert).
- **Backward-compatible:** `releaseContext` is optional throughout. An audit with no context
  yields no release-anomaly findings; the rule and the helper are inert; every existing test that
  doesn't provide context is unaffected.

## Section 4 — Testing, fixtures & Definition of Done

*Testing (hermetic, deterministic):*
- **Pure rule unit tests** — synthetic `AuditInput` with crafted `releaseContext`: maintainer
  superset (→ *added*), ownership turnover (→ *takeover*), a large prev→current publish gap
  (→ dormancy), `versionCount === 1` + an install-script/network capability in `meta`/files
  (→ new-package-risk). The critical **false-positive guard**: a normal patch by the *same*
  maintainers with a small time gap yields **no** findings.
- **Capability-novelty helper unit test** — a `capabilityDelta` whose `added` holds a dangerous
  capability (with a predecessor present) → finding; a benign/empty delta → none; null delta (no
  baseline) → none; added capability but no predecessor → none.
- **Multi-version fixtures** (new) — the fixture registry gains `time` + per-version
  `maintainers`. Three synthetic fixtures: a benign package with a same-maintainer v2 (no
  anomaly), an **account-takeover** fixture (v1 maintainer A → v2 maintainer B + a newly-added
  install script + long dormancy → signals 1/2/4 compound into a high score), and a
  **fresh-malware** first-version package (install-script/network → new-package-risk). All
  malicious fixtures keep the `SYNTHETIC FIXTURE` header, RFC 5737 documentation IPs
  (198.51.100.0/24, 203.0.113.0/24), and are **scored as text, never executed**.
  `scripts/make-fixtures.ts` emits the `time`/`maintainers` metadata into `registry.json`.
- **E2E through the proxy** — the takeover fixture scores high (via `LocalFixtureUpstream` +
  the in-process proxy), and the existing malicious fixture still **blocks**; a benign version
  bump does not regress.
- **Determinism (invariant #1)** — the rule and the novelty helper read only immutable inputs
  (no `Date.now()`); a grep-level check asserts neither new file references the clock; the
  `scoring is deterministic across runs` test stays green.

*Definition of done:* `npm run build` clean; `npm test` green (record count); `npm run fixtures`
regenerated; the malicious fixture still blocked; ADR-0029 recorded; ARCHITECTURE (the new rule
+ `releaseContext` plumbing + capability-novelty helper), CLAUDE (phase summary, rule count → 7,
test count), and README (the release-anomaly signals) updated.

## Out of scope (deferred beyond Phase 16)

- Per-enterprise tunable thresholds for the dormancy cutoff (POLICY prices the finding; the
  day-threshold is a rule constant this phase).
- Version-cadence/semver-jump anomalies (a suspicious major-version leap) — lower signal;
  add when demand appears.
- Cross-package maintainer reputation / a maintainer graph (this phase compares a release only
  against its own predecessor, not a global maintainer corpus).
- Using the Phase 15 `HistoryDb` as the comparison source (this phase reads the packument
  directly, which is authoritative and always present; history-backed comparison is a follow-on).
- `_npmUser` (per-version publisher identity) — richer than `maintainers` but not reliably in the
  standard packument; `maintainers`-set comparison is the portable signal this phase.

## Invariants preserved

1. **Deterministic score** — every signal reads immutable packument data; no `Date.now()` in the
   rule or the helper; the determinism test is unaffected.
2. **LLM never scores** — untouched.
3. **Sync gate cheap** — `releaseContext` is built from the packument already fetched on the audit
   path (no new network call); the rule and helper are pure in-memory computation.
4. **Cache key = integrity** — unchanged; `releaseContext` is derived, not cached; the cache key is
   still the tarball integrity.
5. **Proxy transparency** — the packument passthrough is unchanged; the server only *reads* `time`
   / per-version `maintainers` to build `releaseContext`; it does not synthesize or strip
   packument fields on the npm path.
6. **Rules fail open / audit never crashes** — the new rule is wrapped by `runRules` (try/catch per
   rule); the capability-novelty helper is a pure total function guarded against null delta /
   missing predecessor; a malformed `releaseContext` yields no findings, never a crash.
7. **Private namespaces authoritative** — unchanged; release-anomaly scoring applies equally to
   whatever version was resolved through the existing routing.
