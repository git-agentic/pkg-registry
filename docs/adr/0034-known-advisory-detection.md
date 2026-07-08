# ADR-0034: Known-advisory (known-malicious) detection

**Status:** Accepted (Phase 21)
**Date:** 2026-07-09

## Context

Every rule through Phase 16 (`install-scripts`, `secret-exfil`,
`network-egress`, `obfuscation`, `provenance`, `typosquat`,
`release-anomaly`) is **heuristic or behavioral**: it infers risk from what a
package's files *do*, what its cryptographic identity *is*, or how its
release history *looks*. None of them consult a **known-bad** signal — there
is no check anywhere in Sentinel that says "this exact package version has
already been confirmed malicious and publicly documented." That is the
lowest-false-positive, highest-confidence signal a supply-chain scanner can
offer (an OSV/GHSA "malicious-packages" record is a human-reviewed incident,
not an inference), and every comparable product in this space (Socket,
Chainguard, npm's own audit) ships one. Sentinel had no equivalent.

## Decision

- **A bundled, static advisory corpus** — `packages/core/src/advisory-corpus.ts`
  exports `interface Advisory { name; version; id; severity?: "critical" |
  "high"; reference? }` and `KNOWN_ADVISORIES: readonly Advisory[]`, a
  curated snapshot of real, publicly-documented compromised npm releases
  (`event-stream@3.3.6`, `flatmap-stream@0.1.1`, `ua-parser-js@0.7.29/0.8.0/
  1.0.0`, `node-ipc@10.1.1`, `coa@2.0.3`, `rc@1.2.9`) with their real GHSA
  advisory ids. The corpus is **metadata only** — `(name, version, id)`
  triples and a reference URL, never malware code, and it ships in the same
  synthetic-fixtures-safe spirit as CLAUDE.md's fixture rules even though
  these are real identifiers, not fixtures: nothing here is executable.
  `buildAdvisoryIndex` builds a `name → Advisory[]` lookup once;
  `parseAdvisories` is a pure, total parser for an operator-supplied JSON
  array (drops malformed entries, `[]` on garbage — never throws).
- **`known-advisory` — a pure rule** (`packages/core/src/rules/
  known-advisory.ts`), registered in `RULES` (rule count is now **8**). For
  the audited `(name, version)`, it checks the bundled corpus **union** any
  operator-supplied `input.advisories` for an exact match. A hit emits one
  `metadata`-category finding at the advisory's own `severity` (default
  `critical`) naming the advisory id and reference. Under the default policy
  (`hardBlockSeverity: "critical"`), a `critical` known-advisory finding
  **hard-blocks** regardless of score — the one finding type in Sentinel
  that should never be a nudge.
- **Operator-overridable, additively.** `AuditInput.advisories?: Advisory[]`
  is threaded through `buildAudit`/`runAudit` exactly like Phase 16's
  `releaseContext`; the rule checks bundled ∪ operator-supplied, so an
  operator extends coverage without forking the bundled file. (Loading and
  proxy-side wiring of `SENTINEL_ADVISORIES` was Phase 21 Task 2's concern —
  see ARCHITECTURE.md §3.20 for the loader.)
- **A `known-advisory` remediation entry** in `REMEDIATIONS`
  (`packages/core/src/remediation.ts`, ADR-0031's map): summary "listed as
  known-malicious in a security advisory," action "remove it and pin to a
  version published before the compromise (or a patched later release); do
  not waive" — the one remediation entry that explicitly tells the operator
  not to waive, because waiving away a confirmed-malicious version defeats
  the entire point of the signal.

## Determinism (invariant #1 untouched)

`KNOWN_ADVISORIES` is a static, committed array — never fetched, updated, or
scored at audit time (invariant #3, same posture as the typosquat corpus,
ADR-0026). `knownAdvisoryRule` is a pure `(AuditInput) => Finding[]`: no I/O,
no clock, no network — an exact string-equality lookup against a prebuilt
index plus whatever `input.advisories` the caller passed in. Given the same
`(name, version)` and the same advisory set, the finding is byte-identical
every time, so the pinned `scoring is deterministic across runs` test stays
green with no special-casing. The rule is registered exactly like any other
`Rule` in `RULES` — no new code path in `score()` or `runRules`.

## Consequences

- Adds the one detection dimension every comparable scanner treats as
  table-stakes: a confirmed-malicious release is now caught even if its
  behavior evades every heuristic rule (a known-malicious package can be
  behaviorally unremarkable, exactly like a typosquat — the exploit is in
  *identity*, not necessarily in obviously-suspicious code).
- **The bundled snapshot goes stale.** New malicious releases are discovered
  continuously; a committed array frozen at authoring time will miss
  anything published after that date. This is the direct cost of invariant
  #3 (never fetch at audit time) applied to a known-bad list instead of a
  popularity corpus — mitigated, not eliminated, by the operator-override
  path (`SENTINEL_ADVISORIES`, merged at rule-eval time) and by
  `scripts/make-advisories.ts`, a documented regenerator an operator or a
  maintainer runs against a local OSV/GHSA export to refresh the bundled
  file out of band.
- **Exact-match only.** The rule matches `(name, version)` literally; it
  does not understand semver ranges (`>=3.3.0 <3.3.6`) the way a real
  advisory record often specifies. A malicious release one patch version
  away from a listed one is not caught unless it, too, has its own corpus
  entry.
- The corpus is data, not code — extending coverage never touches
  `known-advisory.ts` itself, matching the "add a rule" story CLAUDE.md
  already documents for `typosquat-corpus.ts`.
- Operator-supplied advisories are threaded into the **public install audit
  path** (`auditVersion`); the bundled corpus applies wherever the rule
  pipeline runs. `SENTINEL_ADVISORIES` coverage does not currently extend to
  the private-namespace publish path.

## Deferred

- **Semver-range advisory matching** — real OSV/GHSA records commonly
  specify a range; today's rule requires an exact published version.
- **Live OSV/GHSA fetch or sync at startup or on a schedule** — deliberately
  out of scope; see Rejected.
- **A full CVE/vulnerability (non-malware) feed** — this phase is scoped to
  *known-malicious* packages (OSV `type: malicious` / GHSA `type: malware`),
  not general dependency CVEs (e.g. a legitimate package with a disclosed
  RCE), which is a different signal with different false-positive economics.
- **Auto-refresh of the bundled corpus** — `make-advisories.ts` is a manual,
  reviewed regenerator, not a cron job or a build-time fetch.
- **Operator-advisory coverage on the private-namespace or publish paths** —
  `SENTINEL_ADVISORIES` today only reaches the public install audit path.

## Rejected

- **Fetching OSV/GHSA at audit time** — rejected outright: it puts a network
  call on the sync inline gate (invariant #3 — the request path is static
  analysis over bytes already in memory, nothing slow or networked belongs
  there) and makes scoring non-deterministic on transient fetch failures or
  upstream feed changes (invariant #1 — same input + same policy must always
  produce the same score). A static, committed corpus plus an explicit,
  operator-run refresh script keeps the audit path exactly as fast and
  deterministic as every other rule.
- **A severity-below-`critical` default** — rejected: a version already
  confirmed malicious by a human-reviewed advisory is not a "maybe, weigh
  it" signal the way `typosquat` or `release-anomaly` are. Defaulting to
  anything short of `critical` (hard-block under the default policy) would
  let a confirmed-malicious install pass with a warning, which defeats the
  purpose of shipping a known-bad list at all. An operator who disagrees can
  still override per-entry via `severity: "high"` in their own
  `SENTINEL_ADVISORIES` file, or waive via the existing `policy.allow`/
  `policy.rules.disabled` machinery like any other finding — but the
  *default* has to hard-block.

Extends [ADR-0002](./0002-deterministic-scoring-llm-enrichment.md)
(deterministic scoring — `known-advisory` is a pure function of audit input,
computed once, never re-scored, exactly like every other rule) and
[ADR-0026](./0026-supply-chain-identity-heuristics.md) (the "bundled, static,
offline corpus + pure rule" shape this ADR reuses verbatim for a known-bad
list instead of a popularity list). Supersedes nothing.
