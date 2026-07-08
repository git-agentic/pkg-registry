# ADR-0033: Policy authoring + impact preview — pure lint, dry-run replay against history

**Status:** Accepted (Phase 20)
**Date:** 2026-07-08

## Context

Every verdict Sentinel produces is `score()` applied to an `EnterprisePolicy`
(ADR-0002, ADR-0012, ADR-0014) — the policy is the single lever that decides
what "allow" means for an enterprise. But authoring one is hand-editing JSON
with no help beyond ADR-0012's keygen/sign/verify tooling: nothing checks
that `thresholds.allow` isn't below `thresholds.warn`, that
`severityWeight.critical` isn't accidentally `0`, or that a package sits in
both `allow` and `deny`. Worse, nothing shows an operator what a candidate
edit *does* before they sign it — an operator raising a threshold "a
little" to cut noise has no way to see, ahead of time, that it also
silently lets a dozen previously-blocked packages back in. Phase 15's
`HistoryDb` (ADR-0028) already durably stores every audited report; Phase 20
is the first phase to read it back for anything other than dashboards and
metrics.

## Decision

- **`lintPolicy(policy): { errors: LintFinding[]; warnings: LintFinding[] }`**
  (`packages/core/src/policy-lint.ts`) is a pure, total structural + semantic
  lint of an `EnterprisePolicy`. **Errors** mark a policy an operator should
  not sign: out-of-range or inverted thresholds (`allow < warn`), an invalid
  `hardBlockSeverity`, a non-finite or negative `severityWeight`, a
  non-positive `diffMultiplier`, a malformed (non-string/empty) entry in
  `privateNamespaces`/`requireSignature`/`allow`/`deny`, or a package
  listed in both `allow` and `deny`. **Warnings** flag suspicious-but-legal
  values: non-monotonic severity weights, a `hardBlockSeverity` of
  `info`/`low`, an `allow` threshold low enough that a lone critical
  finding still scores "allow", an `allow` threshold of `100` (only a
  finding-free package ever passes), and a `diffMultiplier` below `1`.
  `lintPolicy` never scores anything — it inspects the policy document
  alone. `DEFAULT_POLICY` lints clean (zero errors, zero warnings).
- **`HistoryDb.allReports(limit = 1000)`** (`packages/proxy/src/history-db.ts`)
  reads back every stored `audit_events.report_json` row, newest-first,
  skipping a corrupt row rather than throwing (invariant #6).
- **`POST /-/policy/preview`** (`packages/proxy/src/server.ts`) is an open
  read route (no role gate — it doesn't mutate anything) that takes a
  candidate policy body, calls `allReports()`, and re-scores each stored
  report under the candidate via the existing pure `score()` — the same
  function every live audit already calls. This works because a
  `ScoredFinding` is structurally a `Finding`: a stored `AuditReport` is cast
  back to an `Audit` and handed to `score()`, which reads the base finding
  fields and recomputes weights/thresholds/hard-block from the *candidate*
  policy — no bespoke replay logic, no second scoring path to keep in sync.
  The response is `{enabled, total, transitions, changed}`: `transitions`
  buckets every report into one of the six verdict-flip counts
  (`allowToWarn`, `allowToBlock`, `warnToAllow`, `warnToBlock`,
  `blockToAllow`, `blockToWarn`) plus `unchanged`; `changed` lists up to
  100 flipped packages, worst-verdict-first, each with
  `{name, version, from, to, fromScore, toScore}`. No `HistoryDb`
  configured ⇒ `501 {enabled: false}`, matching ADR-0028's existing
  disabled-route contract; a malformed candidate body ⇒ `400` via
  `parsePolicy`'s existing structural validation, never a crash.
- **`sentinel policy init --out <file>`** scaffolds a policy file from
  `DEFAULT_POLICY`. **`sentinel policy validate <file>`** parses + lints it
  and prints the findings; it exits non-zero **iff there are errors** —
  warnings-only output still exits `0`, so `validate` is a clean CI gate
  that doesn't block on advisory noise. **`sentinel policy preview <file>
  [-p proxy]`** POSTs the candidate to `/-/policy/preview` and renders the
  transition summary + flipped-package table; a `501` prints "history not
  enabled" instead of a raw HTTP error.
- **The preview is a dry-run, full stop.** The candidate policy is never
  applied to the live server, never stored, never signed by this endpoint —
  it exists only for the duration of the request, inside the re-scoring
  loop. Signing (`sentinel policy sign`, ADR-0012) and loading the signed
  policy onto the proxy remain entirely separate, existing steps an
  operator still does by hand after a preview looks acceptable.

## Determinism (invariant #1 untouched, exercised)

The preview *is* the deterministic scorer, replayed: `score(report as
Audit, candidate)` is the exact function the live gate calls, so an
identical candidate policy against the same history replays to
`unchanged === total` — same inputs, same verdict, every time. `lintPolicy`
is pure and reads only the candidate document; it makes no I/O call, no
network call, and consults no history. This phase does not introduce a
second scoring code path to drift from the first — it re-enters the one
that already exists, over stored inputs instead of a live tarball request.
The live scoring path (`runAudit`, the inline gate, `AuditStore`) is
byte-for-byte untouched; only a new *read* of already-scored history is
added.

## Consequences

- An operator can answer "what will this policy change do?" before signing
  it, instead of discovering the blast radius after it's live.
- The preview requires the opt-in `HistoryDb` (`SENTINEL_HISTORY_DB`) —
  a proxy that has never enabled durable history has nothing to replay
  against and returns `501`, same as Phase 15's other history-gated routes.
- The replay is bounded: `allReports(1000)` caps how much history a single
  preview call re-scores, so the impact estimate is a sample of the most
  recent audits, not a full-fleet guarantee, on a proxy with more than
  1000 stored reports.
- `validate` gives CI a cheap, offline gate on policy edits (no proxy
  needed); `preview` requires a running proxy with history enabled, so it's
  a separate, heavier step an operator runs deliberately before signing.
- The live scoring path gains no new branch, flag, or code path — this
  phase is entirely additive tooling layered on `score()` and `HistoryDb`.

## Deferred

- **Auto-apply / hot-reload** — a preview never becomes the live policy on
  its own; loading a newly signed policy is still the existing manual step.
- **A visual policy editor** — authoring stays hand-edited JSON, now with
  lint feedback; no GUI or form-based editor.
- **`policy diff A B`** — no text/structural diff between two policy
  documents; only single-candidate-vs-history impact.
- **Preview against a lockfile** — the preview replays *stored history*,
  not a fresh `audit-tree` run over a given `package-lock.json`.
- **An auto-tuner** — nothing suggests threshold or weight values; lint and
  preview surface facts, an operator still decides the numbers.

## Rejected

- **CLI-side replay, shipping all `report_json` rows to the client** —
  rejected: heavier (the CLI would need to fetch and hold potentially
  thousands of full reports), and it leaks the full audit history payload
  off the proxy for a computation the proxy can already do locally in one
  pass. Keeping the replay server-side means only the aggregate result
  (`transitions`/`changed`, capped at 100 rows) ever leaves the proxy.
- **A `policy` field on every rule** — rejected: rules already receive the
  active policy through `score()`'s existing weighting step; adding a
  per-rule policy parameter would duplicate a seam that already exists and
  give rules a scoring role they don't have (rules produce findings,
  `score()` alone applies policy — see ADR-0002).

Extends ADR-0002 (deterministic heuristic scoring — the preview replays the
same pure `score()`, never a second scoring implementation), ADR-0012
(per-enterprise policy as signed data — lint/preview operate on the same
`EnterprisePolicy` document, upstream of signing), and ADR-0028 (durable
history — the preview is the first consumer of `HistoryDb.allReports`
beyond dashboards/metrics). Supersedes nothing.
