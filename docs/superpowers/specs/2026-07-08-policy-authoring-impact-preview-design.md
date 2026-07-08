# Phase 20 — Policy Authoring + Impact Preview

**Date:** 2026-07-08
**Status:** Approved design, pre-implementation
**Extends:** ADR-0002 (deterministic scoring — the preview is that scorer replayed under a
candidate policy; nothing about scoring changes), the per-enterprise signed-policy mechanism
(adds `init`/`validate`/`preview` beside the existing `keygen`/`sign`/`verify`), and Phase 15's
durable audit history (`HistoryDb.report_json` is the replay corpus). Supersedes nothing.
(ADR-0033 will verify and cite the exact policy/history ADR numbers before recording.)

## Problem

The `EnterprisePolicy` governs **every verdict** — severity weights, verdict thresholds, the diff
multiplier, the hard-block severity, private namespaces, per-package allow/deny. Yet it is
hand-authored JSON, and `sentinel policy` offers only `keygen`/`sign`/`verify` — no way to scaffold
a policy, catch a dangerous value (an inverted threshold, a zero diff multiplier, a mis-typed
severity), or understand what a change would **do** before signing and shipping it. A single bad
weight silently re-scores every package. Phase 20 matures the scoring foundation: `policy init`
scaffolds, `policy validate` lints, and `policy preview` **replays the durable audit history under a
candidate policy** to show the verdict deltas — answering the currently-unanswerable question "what
will this policy change do?" while the scoring engine stays fully deterministic.

## Decisions (brainstorm outcomes)

1. **`lintPolicy` is a pure core function** — structural + semantic checks over the policy shape; it
   never scores anything.
2. **The impact preview runs server-side** (`POST /-/policy/preview`) by re-scoring the `HistoryDb`'s
   stored audits under a candidate policy — keeping the full `report_json` in the DB and reusing the
   exact deterministic `score()`. It requires history (opt-in); no history ⇒ an explicit disabled
   response.
3. **The candidate is a dry-run** — the preview never applies, stores, or requires a signature on the
   candidate; it is a read-only "what if".
4. **Determinism is exercised, not endangered** — the replay is `score(audit, candidatePolicy)`; same
   inputs ⇒ same verdict, always. Invariant #1 is untouched.

## Section 1 — Architecture

- **Core `packages/core/src/policy-lint.ts`** — `lintPolicy(policy: EnterprisePolicy): { errors:
  LintFinding[]; warnings: LintFinding[] }`, pure; inspects `scoring.severityWeight`/`thresholds`/
  `diffMultiplier`/`hardBlockSeverity`, `allow`/`deny`, `privateNamespaces`/`requireSignature`. Never
  scores.
- **Proxy `POST /-/policy/preview`** — a candidate policy in, verdict deltas out, computed by
  re-scoring `HistoryDb.allReports()` under the candidate via `score()`. Requires history (else `501
  { enabled: false }`). Off the inline gate.
- **CLI under the existing `sentinel policy`** — `init` (scaffold from `DEFAULT_POLICY`), `validate
  <file>` (`parsePolicy` + `lintPolicy`, non-zero exit on errors), `preview <candidate>` (POST + render
  the impact).
- **Determinism (invariant #1)** — the preview *is* the deterministic scorer replayed; `lintPolicy` is
  pure; the candidate is never applied/signed by the preview.

## Section 2 — `lintPolicy` (errors vs warnings), `validate`, `init`

`lintPolicy(policy): { errors: LintFinding[]; warnings: LintFinding[] }`, `LintFinding = { code:
string; message: string }`.

**Errors** (a dangerously-broken policy; `validate` exits non-zero):
- `thresholds.allow` or `thresholds.warn` outside `0–100`, or `allow < warn` (inverted).
- `hardBlockSeverity` not one of `info|low|medium|high|critical`.
- any `severityWeight[sev]` negative or non-finite, or a missing severity key.
- `diffMultiplier` ≤ 0.
- a package present in BOTH `deny` and `allow` (contradiction), or a malformed
  `allow`/`deny`/`privateNamespaces`/`requireSignature` entry (non-string / empty pattern).

**Warnings** (suspicious but legal; `validate` still exits 0):
- `severityWeight` non-monotonic (a lower severity weighs ≥ a higher one).
- `thresholds.allow` so low that even a critical-only package still scores `allow`, or so high that
  nothing reaches `allow` (computed against the weights).
- `diffMultiplier` < 1 (weakens the changed-file signal).
- `hardBlockSeverity` = `info` or `low` (fires a hard block on trivial findings).

**`sentinel policy validate <file>`** — `parsePolicy(readFileSync(file))` (a parse/structural failure
is itself an error) then `lintPolicy`; print grouped `✗ error` / `⚠ warning` lines with codes; **exit
non-zero iff there are errors** (a clean CI gate for a policy repo). **`sentinel policy init --out
<file>`** — write `DEFAULT_POLICY` as pretty JSON (a valid, signable starting point) and print
next-steps to stdout (JSON carries no comments): edit weights/thresholds/namespaces → `policy
validate` → `policy sign`. Both reuse the existing `parsePolicy`/`DEFAULT_POLICY`; `lintPolicy` is the
only new core code.

## Section 3 — The impact preview: endpoint, replay, CLI

- **`HistoryDb.allReports(limit = 1000): AuditReport[]`** (new, in `history-db.ts`) — `SELECT
  report_json FROM audit_events ORDER BY audited_at DESC LIMIT ?` → `JSON.parse` each. Bounded
  (documented cap).
- **`POST /-/policy/preview`** (proxy) — body `{ policy: <candidate EnterprisePolicy JSON> }`. If no
  `HistoryDb` → `501 { enabled: false }`. The candidate is structurally validated (`parsePolicy` on it)
  — a malformed body ⇒ `400`, not a crash. For each stored `report`, reconstruct an `Audit`
  (`{ schema, meta, findings, capabilities, capabilityDelta, engine, auditedAt, durationMs }` — a
  `ScoredFinding` *is* a `Finding`, so `report.findings` feeds `score()` directly) and call
  `score(audit, candidate)`; compare the new verdict to the stored `report.verdict`. Response:
  ```
  {
    enabled: true,
    total: <n replayed>,
    transitions: { allowToWarn, allowToBlock, warnToAllow, warnToBlock, blockToAllow, blockToWarn, unchanged },
    changed: [ { name, version, from, to, fromScore, toScore } ]   // capped, worst-first
  }
  ```
  Pure/deterministic (`score()`); read/dry-run — the candidate is never applied/stored/signed. Off the
  inline gate (invariant #3).
- **`sentinel policy preview <candidate> [-p proxy]`** (CLI) — read + `parsePolicy` the candidate
  locally first (fail fast), `POST /-/policy/preview`, render: a headline (`142 audits replayed · 6
  would change`), the transition matrix (`allow→block: 2 · warn→block: 3 · block→allow: 1 · …`), and a
  worst-first table of changed packages (`name@version  allow → block  (88 → 41)`). On the disabled
  response, print "history not enabled — set `SENTINEL_HISTORY_DB` on the proxy to preview impact."

## Section 4 — Testing & Definition of Done

*Testing (hermetic, deterministic):*
- **`lintPolicy` unit tests** (pure) — clean `DEFAULT_POLICY` → no errors/warnings; inverted
  thresholds, out-of-range threshold, bad `hardBlockSeverity`, negative `severityWeight`,
  `diffMultiplier ≤ 0`, `deny`∩`allow` → the specific error `code`; non-monotonic weights /
  `diffMultiplier < 1` / aggressive `hardBlockSeverity` → the specific warning `code`. Determinism.
- **`HistoryDb.allReports` test** — record a few `AuditReport`s → returns them parsed; the limit caps.
- **Preview replay e2e** (in-process proxy + `:memory:` HistoryDb) — seed audits scored under
  `DEFAULT_POLICY` (some `allow`, some `block`); `POST /-/policy/preview` with a **stricter** candidate
  → `transitions` show the expected shifts and `changed[]` lists them; a candidate **identical** to the
  stored policy → `unchanged === total`, `changed` empty (faithful replay); no `HistoryDb` → `501 {
  enabled: false }`; a malformed candidate → `400`.
- **CLI e2e** (async `execFile`) — `policy init` writes a policy that `policy validate` passes (exit 0);
  a hand-mutated bad policy (inverted thresholds) → `validate` exits non-zero with the error;
  `policy preview <candidate> -p <proxy>` against the seeded proxy prints the transition summary;
  against a no-history proxy prints the enable hint.
- **Determinism / invariant #1** — the replay is pure `score()`; the `scoring is deterministic across
  runs` test is unaffected; `lintPolicy` is pure; the malicious fixture still blocks under
  `DEFAULT_POLICY`.

*Definition of done:* `npm run build` clean; `npm test` green (record count); the malicious fixture
still blocked; ADR-0033 recorded; ARCHITECTURE (the policy lint + impact-preview layer), CLAUDE (phase
summary + `policy init`/`validate`/`preview` + count), and README (the policy authoring + preview
workflow) updated.

## Out of scope (deferred beyond Phase 20)

- **Auto-applying / hot-reloading a policy** from the preview — the operator still signs + deploys the
  policy through the existing path; preview is advisory only.
- **A visual policy editor / dashboard** — CLI + JSON this phase.
- **Diffing two arbitrary policies** structurally (a `policy diff A B`) — the preview diffs *impact*,
  not the policy text; a text diff is a follow-on.
- **Previewing against a lockfile tree** (rather than the stored history) — history-backed this phase;
  a "preview against this project's current tree" mode is a follow-on.
- **Recommending policy values** (an auto-tuner that suggests weights) — lint flags dangerous values;
  it does not optimize them.

## Invariants preserved

1. **Deterministic score** — the preview replays `score(audit, candidate)`; same inputs ⇒ same verdict;
   `lintPolicy` is pure; the live scoring path is unchanged.
2. **LLM never scores** — untouched; lint + replay are rule/policy math, no LLM.
3. **Sync gate cheap** — `validate`/`lint` are local; the preview is a separate batch route
   (re-scoring stored audits), never the inline tarball gate.
4. **Cache key = integrity** — unchanged; the preview reads stored audits, re-scores in memory, caches
   nothing.
5. **Proxy transparency** — the preview route only *reads* the HistoryDb + re-scores; packument/tarball
   handling is unchanged; the candidate policy is never applied to the live server.
6. **Rules fail open / audit never crashes** — `lintPolicy` is total; the preview validates the
   candidate (`400` on malformed) and wraps the replay so a single un-scoreable stored report is
   skipped, never fatal.
7. **Private namespaces authoritative** — unchanged; `lintPolicy` inspects `privateNamespaces` but does
   not alter routing; the preview is a dry-run.
