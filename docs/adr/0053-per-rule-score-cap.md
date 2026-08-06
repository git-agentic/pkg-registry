# ADR-0053: Per-rule score cap — bound repeated-finding penalty accumulation

**Status:** Accepted
**Date:** 2026-08-06
**Amends:** ADR-0008/0014 (score-time weighting), ADR-0012 (policy is signed data)

## Context

`score()` summed `severityWeight × (diffMultiplier?)` linearly over every
finding **instance**, with no bound on how many instances one rule could
contribute. Several rules emit one finding per offending file —
`obfuscation` per pattern-hit file, `network-egress`/`secret-exfil` per file
citing an endpoint/credential read, `install-scripts` per lifecycle-script
file. A package that ships the same risk signal across many files (e.g. 14
minified files) was penalized 14× a single-instance weight for what is, at
the verdict level, one risk signal ("this package ships minified code"),
not fourteen independent ones.

A real calibration run (2,739 packages across four production dependency
trees) measured the blast radius: 148 packages blocked across three
known-good, in-production trees, every one a false positive by
construction. All 148 were score-driven — the sum of uncapped per-instance
weights clamped the score to (or near) zero — not severity-forced; zero
involved `hardBlockSeverity`. 92 of the 148 scored exactly 0 (penalties
summing to ≥100). Dominant rules: `obfuscation` (90 blocks),
`network-egress` (28), `secret-exfil` (19), `install-scripts` (7).

The fix has to stay a pure aggregation change: no rule's detection logic
moves, and severity still must matter — a package should not out-score a
truly worse one just because its evidence happens to cluster in fewer
files. The signal that "N occurrences is worse than 1" must survive; what
must not survive is "N occurrences of the same rule is worse than N times
independent signals."

## Decision

Cap each rule's total penalty contribution at a policy-configured multiple
of **that rule's own single worst-instance weight** within the audit:

```
ruleContribution(rule) = min(Σ weight(f) for f in rule's findings,
                              capMultiplier × max weight(f) for f in rule's findings)
penalty = Σ ruleContribution(rule) over all rules present
```

**One-sentence verdict-facing explanation:** *a rule's contribution is capped
at `capMultiplier` (default 3) times its single worst finding, so repeated
evidence of the same signal establishes it without alone driving the score
to zero.*

- **Policy data, per CLAUDE.md's "Tune policy" rule.** New field
  `EnterprisePolicy.scoring.perRuleCapMultiplier?: number`
  (`packages/core/src/policy.ts`), validated fail-closed by `parsePolicy`
  (finite, `>= 1`) exactly like every other scoring knob. `DEFAULT_POLICY`
  sets it to the exported constant `DEFAULT_PER_RULE_CAP_MULTIPLIER = 3`.
  The field is **optional** so every already-signed policy — including the
  committed self-audit policy `policy/sentinel-policy.json`, which this
  change does not and cannot re-sign — keeps parsing unchanged and
  inherits the code default at score time (`policy.scoring
  .perRuleCapMultiplier ?? DEFAULT_PER_RULE_CAP_MULTIPLIER`), zero behavior
  change for any policy that doesn't set it explicitly.
- **Grouped by `ruleId`, not `(ruleId, severity)`.** A single rule
  (`obfuscation`) can legitimately emit findings at different severities
  in the same audit (`eval()` = high, a base64 blob = medium). Grouping by
  `ruleId` alone and taking the group's own max as the cap basis means a
  rule with one bad (high) file and several milder (medium) files is
  capped by its worst evidence, not diluted by the mild ones.
- **Waivers consume no budget (ADR-0014 compatibility).** A waived finding
  already carries `weight: 0`; it is filtered out **before** grouping, so
  it neither adds to a rule's sum nor can set that rule's cap. Waiving an
  entire rule (via `rules.disabled` or an `allow` entry) still zeroes that
  rule's contribution completely, same as before this change.
- **Monotonic.** For a fixed rule, adding any additional finding (weight
  `w >= 0`) can only leave the sum and the max non-decreasing, so both
  `sum` and `capMultiplier × max` are non-decreasing — and `min` of two
  non-decreasing sequences is non-decreasing. Total penalty is a sum of
  independent per-rule contributions, each individually non-decreasing, so
  the total is too. More findings from the same rule never improve
  (lower) the score. Proven directly by test (`packages/core/test
  /score.test.ts`, "monotonic: more identical findings...").
- **Per-finding `ScoredFinding.weight` stays raw, uncapped.** The cap
  applies only to the aggregate `penalty` that becomes `score`; individual
  findings in `report.findings` keep reporting their own true
  per-instance weight, unmodified. This is a deliberate divergence: once a
  rule exceeds the cap, `100 - Σ findings[i].weight` no longer equals
  `report.score`. Findings stay individually informative (an operator or
  `sentinel explain` reader can still see each file's real weight); only
  the aggregate the verdict is derived from is bounded. Any code that
  re-derives a score from `findings[].weight` instead of trusting
  `report.score` will now diverge — there is no such code in this repo
  (`remediate()` only sorts/labels findings; it never sums weights) but
  this is called out explicitly for anyone extending the schema.

## Options Considered

### Option A: Count each distinct `(ruleId, severity)` once
**Pros:** Simplest possible dedup; trivially bounded.
**Cons:** Rejected outright — a package with one `obfuscation (high)`
finding would score *identically* to one with fifty, discarding the
"breadth of evidence" signal entirely. Fails the explicit requirement that
more occurrences must never score better than fewer.

### Option B: Diminishing-returns curve (e.g. `weight × (1 + log2(n))`)
**Pros:** Smoother than a hard cap; every additional instance still adds
*something*.
**Cons:** Rejected. Unbounded in the limit (just slow-growing), so a
sufficiently pathological file count still approaches full clamp — the
exact failure mode this ADR exists to close — unless paired with a hard
cap anyway, at which point the curve is extra complexity on top of the
real fix. Also fails "explicable in one sentence to someone reading a
verdict": a multiplier is `3×`; a log curve requires plotting a graph.

### Option D: A flat per-rule point cap (e.g. every rule capped at 75
points, independent of severity)
**Pros:** Simplest to state as a single number.
**Cons:** Rejected. Decouples the cap from the existing `severityWeight`
system: a flat cap below a severity's own weight would clamp even a
**single** critical/high finding to less than its configured weight,
silently overriding `severityWeight` for high-severity rules — an
inconsistent, surprising interaction between two policy knobs. Tying the
cap to a multiple of the rule's own instance weight (Option C) keeps a
single instance always unaffected by construction (`sum == max <=
capMultiplier × max` whenever `capMultiplier >= 1`).

### Option C: Fixed multiplier of the rule's own worst-instance weight (chosen)
**Pros:** Monotonic, deterministic, composes cleanly with the existing
severity-weight system (a cap of `3×` a `critical` finding is a bigger
cap than `3×` a `low` one, matching intuition), and stated in one
sentence. A rule that fires once is provably unaffected.
**Cons:** The cap basis (`max` within the rule) means a rule dominated by
mild findings but with one severe outlier gets the outlier's (larger) cap
for all its instances — accepted as simple and still strictly safer than
uncapped (see Deferred).

## Consequences

- Repeated file-level evidence of the same rule now saturates the score
  contribution instead of scaling penalty unboundedly with file count — by
  default, three instances of a rule already register its full capped
  penalty; a fourth-plus instance changes the visible finding list but
  never the score.
- **This alone does not clear the 148 calibration false positives.** For
  the reported worst case — 14 × `obfuscation (high)` under the unchanged
  default weights/thresholds — the capped penalty is `3 × 25 = 75`
  (score 25), which still sits below the default `warn` threshold (50)
  and is reported below as the before/after. Retuning `severityWeight`,
  `thresholds`, or `perRuleCapMultiplier` itself toward the calibration
  numbers is a separate policy decision, deliberately **not** bundled into
  this change — the calibration re-measurement is a pre-registered
  experiment against this exact aggregation fix and must not be entangled
  with an unmeasured second change.
- `perRuleCapMultiplier` is additive, optional policy data: every
  already-signed policy (including `policy/sentinel-policy.json`, left
  untouched and unresigned by this change) parses unchanged and inherits
  `DEFAULT_PER_RULE_CAP_MULTIPLIER = 3` at score time.
- `lintPolicy` gained `bad-per-rule-cap-multiplier` (error: non-finite or
  `< 1`) and `aggressive-per-rule-cap` (warning: exactly `1`, meaning
  repetition of a rule adds nothing at all to the score).
- The `scoring is deterministic across runs`/`for a fixed policy` tests
  (invariant #1) are unaffected in *value*, not just determinism, for the
  currently-committed malicious fixture (`color-stream`): every rule in
  that fixture fires at most 3 times, so `min(sum, 3×max) == sum` holds
  for each and the fixture's score stays `0`, verified by direct
  calculation before this change was written — not merely assumed. New
  coverage for the general N-instance case lives in
  `packages/core/test/score.test.ts` against synthetic `Audit` objects
  (no new fixture — this is aggregation math, not a new attack shape, so
  it doesn't need a fixture under `fixtures/` per the fixture safety
  rules in `CLAUDE.md`).

## Deferred

- The cap basis is "the rule's own max instance weight," not a true
  per-severity cap — a rule that fires mostly `medium` but once `high`
  gets the `high` cap applied to its `medium` instances too. Accepted for
  simplicity and because it only ever makes the cap *more* generous
  (larger), never a new way to suppress a real signal; revisit if this
  proves too lenient in a future calibration pass.
- `/-/explain` and the raw finding list do not yet surface "N further
  instances of this rule were capped, contributing 0 additional penalty"
  as an explicit annotation — today a reader can infer it by comparing
  `Σ findings[].weight` (for that rule) against the rule's share of
  `100 - report.score`, but nothing states it directly.
