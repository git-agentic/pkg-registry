# Phase 18 — Actionable Remediation (explain & fix)

**Date:** 2026-07-08
**Status:** Approved design, pre-implementation
**Extends:** ADR-0002 (deterministic scoring — remediation is a separate *advisory* layer that
never feeds the score). Reuses Phase 11's request-not-grant approval-request mechanism
(`POST /-/approval-requests`) for the waiver template, `auditVersion` for the last-known-good
walk, and Phase 17's `renderPrComment`. (ADR-0031 will verify and cite the exact approval-gate /
request-not-grant ADR numbers before recording.) Supersedes nothing.

## Problem

Seventeen phases taught Sentinel to detect, contain, record, and gate — but never to **guide**.
A `Finding` carries `message`/`severity`/`evidence`; there is no remediation field, no
`explain`, no "safe version" suggestion, nothing that turns a block into a next action. Phase 17
put verdicts in front of developers in their pull requests, which makes "so how do I get green?"
the immediate, urgent question — and Sentinel's only answer today is "blocked." Phase 18 adds the
missing **"so what do I do?"** layer: per-finding remediation guidance, a computed last-known-good
version, and a ready-to-use waiver, surfaced in the CLI, the PR comment, and the MCP agent surface.

## Decisions (brainstorm outcomes)

1. **Remediation is a new advisory layer on top of the audit**, parallel to scoring — it reads
   findings + metadata and emits *guidance*, never a score and never a mutation. Invariant #1
   (deterministic scoring) is untouched.
2. **Advisory-only, never auto-edits.** Sentinel *suggests* ("pin to v1.9.3", "request this
   waiver") but never rewrites a lockfile. An auto-fix (`sentinel fix`) is explicitly out of scope:
   mutating a developer's dependency tree is their decision, and a wrong auto-pin could break a
   build. This preserves the trust model — remediation is derived from deterministic audits but is
   advice a human/agent chooses to act on.
3. **Split by dependency:** the per-finding guidance + waiver template are a pure function of the
   report (`@sentinel/core`); the last-known-good walk needs to audit *other* versions, so it lives
   in the proxy `explain` route, off the inline gate path (invariant #3).

## Section 1 — Architecture & the advisory-only principle

- **Pure `remediate(report: AuditReport): Remediation` in `@sentinel/core`** — maps each finding
  (by `ruleId`, with a `category` fallback) to structured `{ summary, action }` guidance and
  generates a minimal waiver / approval-request template from `report.meta`. Pure, deterministic,
  no network; never touches `score.ts`.
- **`GET /-/explain/:pkg/:version` (proxy)** — audits the target (`auditVersion`), runs
  `remediate`, and walks back a bounded window of prior versions to compute **last-known-good** (the
  newest that scores `allow`). Off the inline tarball gate (invariant #3).
- **Advisory-only** — remediation suggests; it never rewrites a lockfile or applies a change.
- **Surfaced across the three established consumption points:** `sentinel explain <pkg>@<version>`
  (CLI), the Phase 17 PR comment (a per-offender remediation hint + an `explain` pointer), and an
  MCP `sentinel_explain` read tool (agent-native; the agent can then act via the existing
  `sentinel_request_approval` write tool — no new grant capability).

## Section 2 — The `remediate` core: per-finding guidance + waiver generation

```ts
interface RemediationItem { ruleId: string; severity: Severity; summary: string; action: string; }
interface WaiverTemplate {
  name: string; version: string; integrity: string | null;
  approveCommand: string;               // ready-to-run `sentinel approve …`
  requestPayload: { name: string; version: string; integrity: string | null; reason: string };
}
interface Remediation {
  items: RemediationItem[];             // one per finding, ordered worst-first
  waiver: WaiverTemplate | null;        // present when verdict is warn/block
  guidance: string;                     // one-line headline
}
export function remediate(report: AuditReport): Remediation;
```

- **Per-finding guidance** — a pure mapper (`REMEDIATIONS`, keyed by `ruleId`, category fallback)
  authored in one place (`packages/core/src/remediation.ts`), so guidance is maintainable and the
  7 rules stay pure. Representative entries: `install-scripts` → "runs lifecycle scripts; review
  them, approve the capability manifest (`sentinel approve …`) if required, else prefer a
  script-free alternative"; `release-anomaly` → "release differs from the package's history
  (maintainer change / dormancy); confirm it's legitimate, else pin to a known-good earlier version
  (see `sentinel explain`)"; `provenance` → "no build provenance; request an exception or choose a
  package publishing SLSA attestations"; `integrity-mismatch` → "the lockfile pins a hash the
  registry no longer serves; regenerate the lockfile from a trusted source or investigate
  tampering"; `typosquat`/`dependency-confusion` → "name resembles a popular/claimed package;
  confirm you meant this exact package". Items are ordered worst-severity first.
- **Waiver / approval-request template** — when verdict is `warn`/`block`, `remediate` emits a
  `WaiverTemplate` derived from `meta`: the `sentinel approve …` invocation and the exact
  `POST /-/approval-requests` payload (`{ name, version, integrity, reason }`, the Phase 11
  request-not-grant shape), so a block becomes a pending approval request in one step with no
  hand-assembled coordinates.
- **Deterministic & crash-safe** — same report ⇒ same `Remediation`; an `allow` verdict ⇒
  `waiver: null` and items only for informational findings; an unknown `ruleId` ⇒ category-generic
  fallback, never a throw.

## Section 3 — Last-known-good, the explain endpoint, the surfaces

- **`GET /-/explain/:pkg/:version` (proxy, regex route mirroring `/-/audit/:pkg/:version`)** —
  audits the target, runs `remediate(report)`, and computes **last-known-good**: from
  `upstream.getPackument(pkg)` it takes prior versions (semver-sorted, strictly older than the
  target), newest-first, capped at a documented window (the most recent **10** prior releases),
  audits each via the integrity-keyed cached `auditVersion` path, and returns the newest scoring
  `allow` — or `null` if none in-window is clean. Response:
  `{ report, remediation, lastKnownGood: { version: string; score: number } | null }`. It
  short-circuits on the first clean version; the window cap is documented so "no suggestion" never
  silently means "didn't look far enough". Off the inline gate (invariant #3).
- **`sentinel explain <pkg>@<version>` (CLI)** — calls the endpoint; a pure `formatExplain` renders
  the verdict, each finding with its `{ summary, action }`, the last-known-good line ("`v1.9.3` was
  the most recent clean release — consider pinning"), and the waiver's `sentinel approve …` command
  + request payload. Async `execFile` in e2e.
- **Phase 17 PR comment** — `renderPrComment` gains a per-offender **remediation hint**: the audit-
  tree route adds `topFindingRuleId` to each `TreePackageRow` (from `report.findings[0]?.ruleId`),
  and a pure `remediationHint(ruleId): string` (a short form of the `action`) renders beside the
  offender; plus a footer pointer: "Run `sentinel explain <pkg>@<version>` for a suggested safe
  version and a ready waiver." Last-known-good stays out of the batch comment (the per-package
  `explain`'s job) so the CI path stays cheap.
- **MCP `sentinel_explain` tool** — a thin read tool: `ProxyClient.explain(pkg, version)` hits the
  endpoint and returns the structured `{ report, remediation, lastKnownGood }` so an agent gets
  machine-actionable guidance, then acts through the existing `sentinel_request_approval`.

## Section 4 — Testing & Definition of Done

*Testing (hermetic, deterministic):*
- **`remediate` unit tests** (pure) — a synthetic `AuditReport` per rule → assert the mapped
  `{ summary, action }`; an unknown `ruleId` → category-generic fallback (no crash); an `allow`
  report → `waiver: null`; a `block` report → a `WaiverTemplate` with the correct
  `name`/`version`/`integrity`, the `sentinel approve …` string, and the `POST /-/approval-requests`
  payload shape; determinism (same report ⇒ same `Remediation`).
- **Last-known-good e2e** (in-process proxy + `LocalFixtureUpstream`) — `GET /-/explain/…` on the
  Phase 16 `hijacked-lib` fixture (v2 blocks, v1 clean) → `lastKnownGood` returns `1.0.0`; a package
  with no clean in-window version → `lastKnownGood: null`; the response carries `report` +
  `remediation`. The malicious fixture still blocks.
- **CLI e2e** — `sentinel explain hijacked-lib@2.0.0` against the in-process proxy → output shows
  the findings + actions, the last-known-good line, and the waiver command. Async `execFile`.
- **PR-comment remediation** — extend the Phase 17 `renderPrComment` test: a block/warn offender
  carries the top finding's remediation hint + the `sentinel explain` pointer; an all-allow tree
  shows none.
- **MCP tool test** — `sentinel_explain` returns the `{ report, remediation, lastKnownGood }` shape
  (fixture-backed).
- **Determinism / invariant #1** — `remediate` is pure and never feeds scoring; the
  `scoring is deterministic across runs` test is unaffected; last-known-good reuses the same
  deterministic per-version scores.

*Definition of done:* `npm run build` clean; `npm test` green (record count); the malicious fixture
still blocked; ADR-0031 recorded; ARCHITECTURE (the remediation layer + explain endpoint +
last-known-good), CLAUDE (phase summary + `sentinel explain` + count), and README (the
explain/remediation feature) updated.

## Out of scope (deferred beyond Phase 18)

- **Auto-fix / `sentinel fix`** that rewrites the lockfile to the last-known-good — advisory-only
  this phase (the safety principle); auto-mutation is a separate, opt-in, carefully-gated follow-on.
- **Cross-package remediation** (e.g. "these 3 blocked packages share a transitive cause") — per
  package this phase.
- **Auditing the *entire* version history** for last-known-good — a bounded recent window this
  phase; a full-history search is a follow-on.
- **Remediation for tree-level aggregate gates** beyond per-package hints — the PR comment points to
  per-package `explain`.
- **Fix-suggestion for a specific alternative package** (a "use X instead of Y" recommender) — the
  guidance names *classes* of alternatives, not a specific replacement.

## Invariants preserved

1. **Deterministic score** — `remediate` is pure and never feeds the score; last-known-good reuses
   deterministic per-version audits; the determinism test is unaffected.
2. **LLM never scores** — untouched; remediation is rule/metadata-derived, not LLM-generated.
3. **Sync gate cheap** — the explain endpoint (audit + last-known-good walk) is a separate route,
   never the inline tarball gate; the PR comment's per-offender hint is a cheap `ruleId → string`
   lookup with no extra audits.
4. **Cache key = integrity** — last-known-good audits reuse the integrity-keyed cached path.
5. **Proxy transparency** — the explain route only *reads* audits + the packument; packument/tarball
   handling is unchanged.
6. **Rules fail open / audit never crashes** — `remediate` is total (unknown ruleId → fallback);
   the explain route wraps its walk and returns `lastKnownGood: null` rather than crashing on an
   unauditeable prior version.
7. **Private namespaces authoritative** — the explain route resolves through the same routing;
   last-known-good audits prior versions through the same private/public path.
