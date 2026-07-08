# ADR-0031: Actionable remediation — explain, waiver templates, last-known-good

**Status:** Accepted (Phase 18)
**Date:** 2026-07-08

## Context

Seventeen phases built detect (rules, scoring), contain (sandbox, quarantine),
record (violation store, durable history), and gate (policy verdicts,
`treeGate`, control-plane auth) — but never *guide*. A `block` verdict tells
an operator or an agent *that* a package is dangerous and *which* findings
tripped it, but not what to do next: no per-finding action, no suggested
alternative, no ready-made waiver payload. Every surface (CLI panel, PR
comment, MCP tool) stops at the verdict. Phase 17's CI-native Action made
this gap acute — a blocked PR now shows up in front of a developer with no
Sentinel context, and "how do I get green?" became a real, recurring
question rather than a hypothetical one. Phase 18 closes it: remediation
guidance, not new detection — no rule, weight, or verdict logic changes.

## Decision

- **`remediate(report): Remediation`** (`packages/core/src/remediation.ts`)
  is a pure, total function over an already-computed `AuditReport`. It maps
  each finding to `{ ruleId, severity, summary, action }` guidance via a
  single `REMEDIATIONS` map keyed by `ruleId`, falling back to a
  per-`Category` guide (the real categories —
  `install-script`/`network`/`secret-exfil`/`obfuscation`/`metadata`/
  `provenance`, not an invented "capability" category) and finally to a
  generic guide, so an unrecognized `ruleId` never throws — it just gets
  the least specific applicable advice. Items are sorted worst-severity-first
  so the most urgent action leads. When `report.verdict !== "allow"`, it also
  returns a `WaiverTemplate`: the package's `name`/`version`/`integrity`, a
  ready `sentinel approve <name> <version> --reason "..."` command, and the
  same `{ name, version, integrity, reason }` shape Phase 11's
  request-not-grant approval-request mechanism (`POST /-/approval-requests`)
  already accepts. `remediationHint(ruleId)` is the short one-line projection
  used by compact surfaces that don't want a full audit re-run.
- **`GET /-/explain/:pkg/:version`** (`packages/proxy/src/server.ts`) audits
  the target version, runs `remediate` over the resulting report, and walks
  back a **bounded window** of the package's prior versions (newest of ≤10,
  sorted with `cmpSemver`) looking for the first one whose own audit verdict
  is `allow`, reusing the same cached, integrity-keyed `auditVersion` path
  every other route uses — no separate audit logic. The version list itself
  comes from the same `isClaimed` branch every other route already uses
  (invariant #7): `privateStore.versions()` for a name matching the policy's
  `privateNamespaces`, the public packument's version list otherwise — a
  claimed name's prior versions are never enumerated against public npm. The
  walk short-circuits on the first `allow` and treats any version-list fetch
  failure or per-version audit failure as "no last-known-good found" rather
  than surfacing an error, since this is advisory best-effort, not a gate.
  The route is deliberately off the inline tarball-request gate (invariant
  #3) — it is expected to be slower than the sync audit path.
- **Three surfaces, one shape.** All three consume the same
  `{ report, remediation, lastKnownGood }` response:
  - `sentinel explain <package> <version>` (CLI) prints the verdict, each
    finding's action, a "pin to `<version>`" suggestion when a last-known-good
    exists, and the ready waiver/approve command (`formatExplain`,
    `packages/cli/src/format.ts`).
  - The `audit-tree` PR comment gets a "how to fix" column: the proxy's
    audit-tree route now sets `TreePackageRow.topFindingRuleId` from the
    worst finding, and `renderPrComment` renders `remediationHint(ruleId)`
    next to each offending package — a cheap projection that needs no extra
    per-package audit — plus a footer pointing at `sentinel explain` for the
    full detail.
  - `sentinel_explain` (MCP, `packages/mcp/src/tools.ts`) is a sixth **read**
    tool; `ProxyClient.explain` throws on a non-OK response rather than
    fabricating a result (ADR-0024's contract).
- **Advisory-only.** Nothing in this phase writes to a lockfile, mutates a
  dependency tree, or auto-selects a version. `remediate` and `sentinel
  explain` only ever *suggest* — the operator (human or agent, through the
  existing request-not-grant path) decides.

## Determinism (invariant #1 untouched)

`remediate` is a pure function of an `AuditReport` it does not produce —
same report in, same `Remediation` out, always. It is never called from
`score.ts`, `runRules`, or anywhere on the scoring path; it consumes a
verdict, it never influences one. The `scoring is deterministic across runs`
test is unaffected because nothing in this phase touches rule evaluation or
policy weights. The last-known-good walk calls the same `auditVersion` every
other route calls, which is itself deterministic and integrity-cache-keyed
(ADR-0004) — walking back through prior versions is repeated application of
an already-deterministic function, not new nondeterminism, though the *set*
of prior versions it walks depends on the packument at call time (a new
release can move which version is "last known good" — expected, not a
determinism violation of the per-version score itself).

## Consequences

- Advisory-only preserves trust: Sentinel still never auto-edits a
  developer's or CI's lockfile, so the earlier phases' "we resolve and serve
  real packages transparently, only attach signal" posture (see CLAUDE.md)
  extends cleanly to remediation — it's still just signal, richer signal.
- `/-/explain` is off the gate path by design, so a slow or failing packument
  fetch for the last-known-good walk can never block or slow an install; it
  can only make the `explain` output less complete.
- The waiver template reuses Phase 11's request-not-grant payload shape
  verbatim, so an agent that calls `sentinel_explain` and then wants to act
  on the waiver still goes through the same human-approval choke point —
  this phase adds no new grant path.
- Last-known-good is a bounded 10-prior-version window, not a full history
  search — documented, not silent. A package whose last `allow` verdict is
  more than 10 versions back returns no suggestion rather than an expensive
  unbounded walk; the CLI/MCP output simply omits the "pin to" line in that
  case.
- `findLastKnownGood` mirrors `auditVersion`'s and the packument route's
  `isClaimed` branch (invariant #7): for a name matching the policy's
  `privateNamespaces` it enumerates prior versions via
  `privateStore.versions()`, never via `upstream.getPackument()` — a claimed
  name never reaches public npm, even for the enumeration-only walk-back.
  Everything else still resolves via the public packument, unchanged.
- `/-/explain` fans out to up to 11 audits per call (the target version plus
  ≤10 priors for the last-known-good walk), each integrity-cache-keyed so a
  repeat lookup is cheap — but a first-touch on a package with a long,
  never-audited history is roughly an 11x amplifier over a single `/-/audit`
  call. If the proxy is reachable beyond a trusted network, rate-limit or
  authenticate `/-/explain` the same way any other non-cached fan-out route
  would be protected.

## Deferred

- **`sentinel fix`** — an auto-fix command that would actually rewrite a
  lockfile/`package.json` to the suggested last-known-good version. This
  phase only ever prints the suggestion.
- **Cross-package remediation** — no reasoning about *replacing* a flagged
  package with a different, unrelated package; only pinning to an earlier
  version of the same package.
- **Full-history search** — the last-known-good walk is capped at 10 prior
  versions; no unbounded search of a package's entire release history.
- **Specific-alternative recommender** — no suggestion engine for "packages
  similar to X but without this finding."

## Rejected

- **A `remediation` field on every rule** — rejected: it would scatter
  operator-facing guidance across every rule file and couple rule authors to
  writing prose, when rules should stay focused on pure detection
  (`(AuditInput) => Finding[]`). Keeping all guidance in one `REMEDIATIONS`
  map in `remediation.ts` is one place to maintain and keeps rules pure per
  the existing "Add a detection rule" convention in CLAUDE.md.
- **Auto-editing the lockfile** — rejected as unsafe: silently rewriting a
  team's `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml` to a different
  resolved version has consequences (transitive resolution changes, breaking
  API changes between versions) Sentinel has no basis to evaluate. Advisory
  output that a human or an agent's human-in-the-loop approval path acts on
  is the safer boundary, consistent with ADR-0024's request-not-grant
  posture.

Extends ADR-0002 (deterministic scoring — `remediate` is a pure projection of
an already-deterministic report; the score path itself is untouched) and
reuses Phase 11's request-not-grant approval-request mechanism (ADR-0024) for
the waiver payload shape. Supersedes nothing.
