# Phase 13 — Supply-Chain Identity Heuristics (typosquatting + dependency confusion)

**Date:** 2026-07-07
**Status:** Approved design, pre-implementation
**Extends:** ADR-0002 (deterministic scoring — both signals are pure/weighted, no
new gate mechanism), ADR-0008 (diff-audit weighting — the rule uses `mkFinding`),
ADR-0010 (private-namespace claims — the dependency-confusion gate leverages them),
ADR-0014 (score-time policy — the gate lives beside `requireSignature`/
`provenanceIdentities`). Supersedes nothing.

## Problem

Sentinel's six detection rules find malicious *code* (obfuscation, network-egress,
secret-exfil, install-scripts) or verify *cryptographic identity* (signature,
provenance). None detect the *social-engineering* supply-chain attacks that are how
most real npm compromises actually land: **typosquatting** (a look-alike name for a
popular package) and **dependency confusion** (a public package shadowing a name an
organization owns internally). Sentinel is blind to the entire identity/naming attack
class — and it already holds the one piece of data that makes dependency confusion
detectable with near-zero false positives: the operator's claimed private namespaces
(ADR-0010), currently used only for routing.

Phase 13 adds the missing detection pillar as two deterministic signals.

## Decisions (brainstorm outcomes)

1. **Two signals: a pure typosquat rule + a score-time dependency-confusion gate**,
   not detonation and not typosquat-only. Both deterministic given (name, corpus,
   policy) — they fit the existing engine and invariant #1 as weighted findings, no
   new gate mechanism. Rejected: dynamic detonation (non-deterministic, platform-heavy,
   architecturally awkward beside a deterministic engine); typosquat-only (leaves the
   dependency-confusion vector Sentinel is uniquely positioned to catch on the table).
2. **The architectural split** mirrors Phases 8/9/12: the typosquat check is a pure,
   policy-blind `Rule` (name vs a bundled static corpus); the dependency-confusion
   check is a score-time gate in `score.ts` (it needs the policy's claimed namespaces,
   which rules can't see).
3. **Bundled curated corpus** (~1–2k popular npm names), a static input shipped in
   `packages/core` like the trust material — never fetched at audit time (invariant #3).
4. **Weighted findings, not hard-blocks.** Typosquat = `medium`; dependency confusion =
   `high`. Under the default policy neither alone forces a block (medium −12 → 88 =
   allow; high −25 → 75 = warn); they compound with code findings, and operators can
   escalate via policy weights or a waiver. This keeps false positives to *warnings*,
   not blocked installs.

## Section 1 — Architecture & data flow

- **Pure typosquat rule** `packages/core/src/rules/typosquat.ts` — `(AuditInput) =>
  Finding[]`, policy-blind. Compares `meta.name` to a bundled corpus
  (`packages/core/src/typosquat-corpus.ts`, or a committed JSON asset loaded once).
  Emits a `medium` finding when the name is a near-miss of a popular name (distance +
  patterns) but is *not itself* in the corpus. Registered in `rules/index.ts`; uses
  `mkFinding()` so the diff multiplier + policy weights apply consistently.
- **Score-time dependency-confusion gate** in `score.ts`, beside the
  `requireSignature`/`provenanceIdentities` logic — it needs `policy.privateNamespaces`
  (rules are policy-blind by design, ADR-0014). It appends a normally-weighted `high`
  finding (`ruleId: "dependency-confusion"`, `category: "metadata"`) when the audited
  name is a confusable near-match of a claimed namespace. Contributes to the score
  like any finding; does **not** force a block (no new gate flag) — stays purely in the
  deterministic-score model.
- **Shared helpers** `packages/core/src/name-distance.ts` — `normalizeName(s)` (strip
  `@`, collapse `/`,`-`,`_`, lowercase) and `damerauLevenshtein(a, b)` + a
  `typosquatMatch(name, target)` predicate, consumed by both the rule and the gate (DRY).
- Both are **deterministic** — pure functions of (name, corpus, policy). Invariant #1
  holds; the default policy has no `privateNamespaces`, so the gate is inert by default
  and the pinned determinism test is unaffected.

## Section 2 — The typosquat rule

- **Corpus:** a curated ~1,000–2,000 of the most-popular / most-targeted npm names,
  committed as a static asset with a header documenting its source (a curated
  popular-npm snapshot) and snapshot date. Reproducible, offline, never fetched
  (invariant #3). Length-bucketed at load so a lookup only compares against corpus
  names within ±2 characters (keeps the scan bounded/cheap — the sync gate stays cheap,
  invariant #3).
- **Detection = Damerau-Levenshtein distance + specific typosquat patterns** (raw
  distance alone is too noisy). A `medium` finding fires when `meta.name` matches a
  distinct popular target via any of:
  - edit distance 1 (short names) or ≤2 (longer names), transposition-aware
    (Damerau — transposition is the most common real typo);
  - character doubling / de-doubling (`expres`, `expresss` vs `express`);
  - homoglyph / confusable substitution (`l↔1`, `o↔0`, `rn↔m`);
  - separator / scope tricks (`node-fetch` vs `nodefetch` / `node_fetch`; `@types/x`
    vs `types-x`).
- **False-positive controls:** (a) never flag a name that *is* in the corpus (a popular
  package is not a squat of another); (b) the matched target must be a *distinct*
  popular name; (c) skip names < 4 chars (too many innocent collisions). Severity
  `medium` — raises the score meaningfully but does not hard-block alone.
- The finding names the target: `` `expres` resembles the popular package `express` —
  possible typosquat``. `category: "metadata"`.

## Section 3 — The dependency-confusion score-time gate

- **Lives in `score.ts`** (needs `policy.privateNamespaces`). For each claimed
  namespace, it normalizes both the claim and the audited name (`normalizeName`) and
  flags a public package whose normalized name equals or is distance-close to the
  claim's normalized form. Since ADR-0010 already routes *exact-claim* names to the
  private store, the residual surface is public look-alikes of a namespace the operator
  owns — the textbook dependency-confusion flatten.
  - Claim `@acme/*` normalizes to `acme`; public `acme-internal`, `@acme-labs/util`,
    `acme_utils` → flagged; unrelated `lodash` → not.
- **Severity `high`** (−25) — the operator explicitly claimed the namespace, so a
  public look-alike is a strong, low-false-positive signal (higher confidence than the
  general typosquat `medium`). It is a normally-weighted finding contributing to the
  deterministic score, **not** a categorical hard-block; an operator can escalate the
  weight or waive per-package via existing policy mechanisms.
- **Policy source:** reuses the existing `privateNamespaces` claims — no new required
  field. An optional `protectedNamespaces` list (brand names to confusion-protect
  *without* private-serving them) is a natural extension, **deferred**.
- The finding names the collision: `` `acme-internal` resembles your claimed private
  namespace `@acme/*` — possible dependency confusion``. `ruleId:
  "dependency-confusion"`, `category: "metadata"`.

## Section 4 — Fixtures, testing, DoD

*Fixtures (all benign — these are name/metadata signals; no malicious code needed):*
- **typosquat**: a benign fixture whose name is a near-miss of a corpus entry (e.g.
  `expres` → `express`) with entirely benign content — detection fires on the *name*.
- **negative control**: a benign fixture whose name *is* in the corpus → must NOT be
  flagged (proves the name-in-corpus FP control).
- **dependency-confusion**: a benign public `acme-internal` audited under a policy
  claiming `privateNamespaces: ["@acme/*"]` → flagged `high`; plus a test that an
  *exact* claim is routed to the private store (unchanged ADR-0010 path) and never
  reaches this public gate.

*Testing (hermetic, deterministic):*
- Pure unit tests for `name-distance.ts`: transposition / doubling / homoglyph /
  separator matches all hit; a corpus name and a <4-char name produce nothing (FP
  controls); `damerauLevenshtein` correctness on known pairs.
- The typosquat rule over crafted names → correct `medium` findings + target naming; a
  clearly-unrelated name → nothing.
- The dependency-confusion gate under a `privateNamespaces` policy → look-alike gets
  the `high` finding; unrelated name → nothing; a claimed name is private-served and
  never reaches the gate.
- **Invariant #1:** the `scoring is deterministic across runs` test stays green — both
  signals are pure; the default policy has no `privateNamespaces` so the gate is inert
  by default, leaving the pinned default-policy score unchanged. Add or update a test
  proving the new rule's contribution is stable. The malicious fixture still blocks.

*Corpus provenance:* the asset ships with a source + snapshot-date header; static data,
never fetched at audit time.

*Definition of done:* `npm run build` clean; `npm test` green (new suites +
determinism); the malicious fixture still blocked; ADR-0026 recorded; ARCHITECTURE
(rules list + the score-time gates section; both findings use the existing `metadata`
`Category`, so no new category is added) + CLAUDE (phase
summary + count) + README (the two new signals + the corpus note) updated.

## Out of scope (deferred beyond Phase 13)

- `protectedNamespaces` policy field (brand names to confusion-protect without
  private-serving) — reuse `privateNamespaces` this phase.
- Metadata-novelty signals (package age / first-publish + install-script + network) —
  needs packument publish-time plumbed into the audit input; a separate data flow.
- Maintainer / ownership-change anomalies (needs historical state).
- Download-count-weighted corpus ranking (the curated list is unranked; ranking would
  need a bundled popularity metric).
- Auto-updating / fetching the corpus (stays a static, committed, operator-updated
  asset).

## Invariants preserved

1. **Deterministic score** — both signals are pure functions of (name, corpus, policy);
   they add weighted findings, no clock/network/state. The determinism test stays green.
2. **LLM never scores** — untouched.
3. **Sync gate cheap** — the typosquat scan is a bounded, length-bucketed comparison
   over a ~1–2k static corpus; the dependency-confusion check is a handful of string
   comparisons against the claimed namespaces. No network, no I/O at audit time.
4. **Cache key = integrity** — unchanged; the findings are part of the integrity-keyed
   audit.
5. **Proxy transparency** — detection only; packument passthrough and the tarball path
   are untouched.
6. **Rules fail open individually / audit never crashes** — the typosquat rule is
   wrapped by `runRules`'s per-rule try/catch like every rule; the gate is a pure
   computation in `score.ts` guarded against a malformed name.
7. **Private namespaces authoritative** — unchanged; the dependency-confusion gate
   *reads* the claims for detection and never alters routing (exact claims stay
   private-served).
