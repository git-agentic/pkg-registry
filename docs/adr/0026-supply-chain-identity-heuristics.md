# ADR-0026: Supply-chain identity heuristics — typosquat rule + dependency-confusion gate

**Status:** Accepted (Phase 13)
**Date:** 2026-07-07

## Context

The five rules that exist before this phase (`install-scripts`, `secret-exfil`,
`network-egress`, `obfuscation`, `provenance`) plus the signature/provenance
verification machinery (ADR-0021/0022) all detect **what a package does** or
**verify its cryptographic identity**. None of them detect the older,
social-engineering attack class that doesn't touch code at all: a malicious
package published under a name close enough to a popular or claimed name that
a human or an automated install picks it by mistake. `event-stream`,
`ua-parser-js`, and the broader typosquat/dependency-confusion literature are
this class — the attacker's payload can be entirely unremarkable; the exploit
is in the *name*, not the bytes. Sentinel is also the only layer in this
stack that already holds an operator's claimed namespaces
(`policy.privateNamespaces`, ADR-0010/0015) — a signal no generic linter or
scanner has — so a dependency-confusion check here can compare a public
package's name against namespaces the operator has actually claimed, not just
a generic popularity list.

## Decision

- **Two checks, one shared distance library.** `packages/core/src/name-distance.ts`
  exports `canonical` (lowercase, strip `@`/scope separators, then fold a
  small set of visually-confusable substitutions — `rn`→`m`, `0`→`o`, `1|`→`l`,
  `5`→`s`), `normalizeName` (flattens `@acme/utils` → `acme`, drops `*`/separators,
  for comparing a name against a *namespace claim* rather than another package
  name), and `damerauLevenshtein` (optimal-string-alignment: insertion,
  deletion, substitution, and adjacent transposition all cost 1).
  `typosquatMatch(name, target)` is `true` when `name !== target` and either
  their canonical forms collide outright, or their edit distance is within a
  length-scaled threshold (`≤2` once the target's canonical form is 7+
  characters, else `≤1` — short names need a tighter bound or almost anything
  matches).
- **`typosquat` — a pure rule** (`packages/core/src/rules/typosquat.ts`),
  registered in `RULES` like any other rule. It scans a bundled static corpus
  of ~150 popular npm package names (`packages/core/src/typosquat-corpus.ts`,
  a curated, dated snapshot) bucketed by canonical length so a lookup only
  compares against nearby-length candidates, and flags the *first* corpus
  name the audited package's name is a likely typosquat of. `metadata`
  category, `medium` severity.
- **`dependencyConfusion` — a score-time check**, not a rule. It lives beside
  `deny`/`requireSignature`/`requireProvenance` in `score.ts`, because
  (like those) it needs the policy — specifically `policy.privateNamespaces`
  — and a pure rule can't see policy. For each claimed namespace, it
  normalizes the claim (`normalizeName`) and flags a public package name
  whose canonical form equals, prefixes, or is a `typosquatMatch` of the
  normalized claim. `metadata` category, `high` severity, ruleId
  `dependency-confusion`. This is a direct extension of the pure-rule /
  score-time-gate split ADR-0014 established for `requireSignature`/
  `requireProvenance` and ADR-0021 restated for `provenance`: detection that
  needs policy state is a score-time gate, not a rule.
- **Both findings share one `Category`.** Neither adds a new finding
  category — both are `metadata`, alongside the existing `provenance` rule's
  findings — so no downstream consumer (dashboard, `audit-tree` rollup,
  `x-sentinel-*` headers) needs a new case to render them.

## Determinism (invariant #1 untouched)

Both checks are pure functions of their inputs. `typosquatRule` is `(files,
ctx) => Finding[]` over the audited package's name and the bundled corpus —
no I/O, no policy, no clock. `dependencyConfusion(name, privateNamespaces)`
is a pure function of the package name and the policy's namespace-claim list;
it is computed inside `score()` (already a pure function of `(audit,
policy)`) and its result is spliced into `rawFindings` before the normal
weight/waiver pipeline runs, so it gets ordinary `allow`/`disabled` waiver
treatment like any other finding. **The default policy ships no
`privateNamespaces`, so `dependencyConfusion` returns `null` for every
package under the default policy — it is inert by default**, exactly like
`requireSignature`/`requireProvenance` were inert until an operator opted in
(ADR-0021). The typosquat-corpus file itself is a static, committed input —
never fetched, updated, or scored at audit time (invariant #3) — so the same
`(audit, policy)` pair always produces the same findings, satisfying the
pinned `scoring is deterministic across runs` test unchanged.

## Weighted, not hard-block

Neither finding is added to the hard-block condition in `score()`. Under the
default policy (`severityWeight: { medium: 12, high: 25 }`,
`hardBlockSeverity: "critical"`, `thresholds: { allow: 80, warn: 50 }`), a
lone `typosquat` finding (medium, −12) drops a clean package from 100 to 88 —
still `allow`. A lone `dependency-confusion` finding (high, −25) drops it to
75 — `warn`, not `block`. Both compound with any code-behavior findings the
package also trips (e.g. a typosquat that also has a suspicious
`postinstall` script stacks the −12 with that rule's weight), and an
operator who wants either to hard-block outright can raise
`hardBlockSeverity`, add the name/rule to `deny`, or match it into
`requireSignature`/`requireProvenance`-style enforcement in their own policy.
An operator who has a known false positive can waive it the same way as any
other finding — `policy.allow` by package + ruleId/category, or
`policy.rules.disabled`. This mirrors ADR-0021's stance on `signature`/
`provenance` findings: detection surfaces a weighted signal by default; only
an explicit, opt-in policy choice turns it into a block.

## False-positive controls

- **`typosquat`**: never flags a name that is itself in the corpus (an exact
  corpus hit is the *legitimate* popular package, not a squat of itself);
  skips names under 4 characters (edit-distance-1 against a 3-character
  target matches almost anything); `typosquatMatch` requires the candidate
  and target to be distinct strings, so a package can never "typosquat"
  itself.
- **`dependency-confusion`**: the operator's own legitimate claimed package
  is checked first and short-circuited — `privateNamespaces.some((c) =>
  matchPackage(c, name))` returns `null` before any distance comparison runs,
  so the real `@acme/utils` publishing under its own claimed namespace is
  never flagged as confusing itself. A normalized claim shorter than 3
  characters is skipped (same short-name-noise reasoning as the 4-character
  floor above).

## Consequences

- Catches the `event-stream`/`ua-parser-js`-class attack: a package that is
  behaviorally unremarkable but published under a name a human or an
  automated `npm install <typo>` would pick by mistake, or under a name a
  supply-chain-confusion attacker chose specifically to collide with an
  operator's internal package scope.
- The corpus is a curated, versioned, operator-extensible seed (~150 names
  today) rather than a live popularity feed — an operator who wants broader
  coverage edits and re-ships `typosquat-corpus.ts`; nothing about the rule
  changes.
- Two more findings compound into every score, which is by design (weighted
  signal, not a new block path) but means an operator relying purely on the
  default `allow`/`warn`/`block` thresholds should expect scores for
  near-miss names to sit a little lower than before this phase, even with a
  clean tarball.

## Deferred

- **A `protectedNamespaces` policy field** distinct from `privateNamespaces`
  — today's dependency-confusion check reuses the same field that gates
  private-store serving (ADR-0010/0015); a namespace an operator wants
  *protected from confusion* but not necessarily *claimed for private
  serving* has no separate knob yet.
- **Metadata-novelty/age signals** (package first-published date, publish
  velocity) — no notion of "how new is this name" feeds either check today.
- **Maintainer-change anomalies** (a sudden maintainer swap on a
  long-established package) — out of scope for this phase; both checks are
  name-only.
- **Download-weighted corpus ranking** — the bundled corpus is an unranked
  set; there's no signal for "how popular is the target I'm squatting,"
  which could tune severity further.
- **Corpus auto-update** — the corpus is a manually curated, committed
  snapshot; there is no fetch-and-refresh path (deliberately, per invariant
  #3 — see Rejected).

## Rejected

- **Dynamic detonation / sandboxed execution to detect confusion at
  install-time behavior** — rejected: non-deterministic (network-dependent,
  timing-dependent, environment-dependent), heavyweight (needs the full
  sandbox machinery from Phases 3–6 on the audit path), and violates
  invariant #3 (the inline gate is sync and cheap; nothing slow or networked
  belongs on the request path). Name-distance comparison against a static
  corpus is O(bucket size) and needs no execution.
- **Typosquat-only, no dependency-confusion gate** — rejected: a generic
  popularity corpus can never know about an operator's private namespaces,
  which is exactly the asset Sentinel already holds and no other layer in
  this stack has access to. Shipping only the typosquat rule would leave the
  higher-value, Sentinel-specific signal — a public look-alike of *your*
  internal scope — undetected.

Extends ADR-0002 (deterministic scoring — both checks are pure functions of
audit input plus policy, computed once, never re-scored), ADR-0008 (diff
weighting — the `dependency-confusion` finding is metadata-only and carries
no `onChangedFile` signal, so it is never diff-multiplied, matching how the
existing `provenance` finding behaves), ADR-0010 (private-namespace
claims — `dependencyConfusion` reads `policy.privateNamespaces`, the same
field ADR-0010 introduced for private-store serving, rather than inventing a
parallel claims list), and ADR-0014 (score-time policy application — the
pure-rule/score-time-gate split this ADR uses for `dependency-confusion`
mirrors the split ADR-0014 established for `requireSignature`/
`requireProvenance`). Supersedes nothing.
