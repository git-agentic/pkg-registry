# ADR-0008: Diff-audit — weight files changed in a release more heavily

**Status:** Accepted
> **Amended (2026-06-25, ADR-0014):** the diff multiplier is now applied at **score
> time** in `score(audit, policy)`, not baked into the finding at creation. Findings
> carry `onChangedFile`; the multiplier value lives in the enterprise policy.
**Date:** 2026-06-24
**Deciders:** Founder/Eng, Security lead
**Phase:** 1

## Context

The highest-impact supply-chain attacks are **trojaned updates** of previously
trusted packages: event-stream (a malicious `flatmap-stream` dependency added in a
minor release), ua-parser-js (compromised maintainer account pushing malicious
patch versions), and many copycats. The signal that matters is not just "does this
package contain risky code" but "did risky code **appear in this release**." A
`postinstall` that exfiltrates secrets is far more alarming when it shows up in a
patch of a long-clean package than when it was present from v0.0.1.

## Decision

Support a **diff mode**: when auditing `pkg@X`, the engine can take the previous
published version's file set as a `baseline` and mark added/changed files. Findings
that cite changed files receive a weight multiplier (`POLICY.diffMultiplier = 1.6`).
The proxy auto-selects the immediate predecessor version as the baseline, so updates
are audited as diffs by default; a full-content audit remains the fallback when no
predecessor exists.

## Options Considered

### Option A: Full-content audit + diff weighting overlay (chosen)
| Dimension | Assessment |
|-----------|------------|
| Catches trojaned updates | Strong — newly-introduced risk is amplified |
| Catches born-bad packages | Yes — full-content audit still runs |
| Complexity | Med — fetch + extract the predecessor |

**Pros:** Models the real threat (malice introduced in an update) without losing
coverage of packages that were malicious from the start; the multiplier is a single
tunable in policy.
**Cons:** Requires fetching/extracting a second tarball on a cold update audit
(mitigated by async/caching); "previous version" selection has edge cases
(prereleases, yanked versions).

### Option B: Diff-only audit (score only changed files)
**Pros:** Cheapest; laser-focused on what's new.
**Cons:** Misses packages that are malicious from their first release, and misses
risk in unchanged files that becomes dangerous in new context. Unsafe. Rejected.

### Option C: Full-content audit only (no diff awareness)
**Pros:** Simplest; one tarball.
**Cons:** Cannot distinguish "always had install scripts" from "just added an
exfiltrating postinstall" — exactly the event-stream signal. Weaker on the most
important attack class. Rejected as the default.

## Trade-off Analysis

Diff weighting is an **overlay, not a replacement**: full-content scanning still
guarantees we catch born-malicious packages, while the multiplier sharpens our
response to the trojaned-update pattern that dominates real incidents. The price is
one extra tarball fetch on cold update audits, which the async/caching design
(ADR-0003/0004) absorbs. The multiplier lives in `POLICY` so it can be tuned per
enterprise later (ADR-0012).

## Consequences

- **Easier:** strong, explainable signal on the most damaging attack class; the
  verdict explanation can say "new in this release."
- **Harder:** predecessor selection and a second extraction add complexity and
  edge cases; very first releases have no baseline (fall back to full).
- **Revisit:** consider richer diff semantics (semantic AST diff vs. text diff) and
  multi-version trend analysis in the async enrich phase.

## Action Items
1. [x] `baseline` support in `extractTarball`; `changed` flag per file; `1.6×` multiplier.
2. [x] Proxy auto-selects the immediate predecessor as baseline.
3. [ ] Handle prerelease/yanked predecessors explicitly; add a semantic-diff experiment in enrich.
