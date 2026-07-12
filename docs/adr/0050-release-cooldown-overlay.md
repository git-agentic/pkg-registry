# ADR-0050: Release-cooldown overlay — hold freshly-published versions by policy

**Status:** Accepted
**Date:** 2026-07-12

## Context

The jscrambler incident (ADR-0049; [`docs/research/jscrambler-supply-chain-attack.md`](../research/jscrambler-supply-chain-attack.md))
shipped all five malicious versions — two Gen-1, three Gen-2 — within hours of
each other. Static detection (raw-byte magic classification, the
`native-payload-loader` rule) closes the *what-is-this-file* gap for that
specific attack shape, but it's shape-specific: a future loader that acorn
can't correlate, or that doesn't touch the filesystem at all, wouldn't trip
it. A cheap, shape-independent mitigant for the same incident class is
**time**: most fast-moving supply-chain compromises are caught and pulled (by
npm, by the maintainer, by a scanner) within the first day or two, and an
install that simply refuses to resolve a version younger than some window
gives that detection-and-pull cycle a chance to run before the version
reaches an installer.

The trade-off is real, not hypothetical: a maintainer shipping a genuine
emergency fix — including a fix *for* a compromise like this one — would
also be held by an unconditional cooldown. A cooldown that can't be narrowed
per-package is a cooldown operators will disable the first time it blocks a
release they needed instantly.

## Decision

Add `releaseCooldown` as **policy data**, not an environment variable —
consistent with every other scoring/verdict knob in `DEFAULT_POLICY`
(invariant/"Tune policy" in CLAUDE.md): weights, thresholds, and now this are
signed, per-enterprise data, not code or ops config.

- **Policy field.** `EnterprisePolicy.releaseCooldown?: { hours: number;
  exempt?: string[] }` (`packages/core/src/policy.ts`). `parsePolicy` validates
  fail-closed at load time: `hours` must be a finite number in `(0, 8760]`
  (up to one year); `exempt`, if present, must be a string array. A
  malformed `releaseCooldown` block is a load-time error, the same posture as
  every other policy field — never a silently-ignored one.
- **Serve-time overlay, not a rule.** There is **no wall-clock read anywhere
  in `@sentinel/core`.** `runRules`/`score` stay pure and deterministic
  (invariant #1) — the same bytes audited under the same policy produce the
  same `AuditReport` regardless of when the audit runs. The cooldown decision
  is computed and applied entirely in the proxy (`packages/proxy/src/
  cooldown.ts`): `resolvePublishTime` picks the authoritative publish
  timestamp for the resolution origin, `cooldownDecision` compares it against
  an injected `now` to decide block/allow, and `applyCooldown` — mirroring
  `applyQuarantine` (ADR-0040) — returns a **new** `AuditReport` with
  `verdict: "block"` and a prepended `weight: 0` critical `release-cooldown`
  finding when blocking, or the input report unchanged otherwise. The cached
  `AuditReport` in `AuditStore` is never mutated; a later request past the
  cooldown window re-derives `{ block: false }` and serves the original
  score untouched.
- **Injectable clock.** `ServerOptions.now?: () => number` (default
  `Date.now`) is threaded into `cooldownDecision`'s `now` argument. Tests
  construct a server with a fixed/steppable `now` to assert cooldown
  transitions deterministically, without sleeping real wall-clock time.
- **Per-origin publish-time source.** `resolvePublishTime` takes the
  authoritative source for the resolution path, mirroring the same
  claimed-vs-public trust boundary invariant #7 already draws elsewhere:
  - **Public** (unclaimed name): the upstream packument's `time[version]`
    map — the same field `buildReleaseContext` already reads for
    release-anomaly scoring (ADR-0029).
  - **Private/claimed** (`isClaimed(pkg, policy)`): `PrivatePackageStore`'s
    `StoredVersion.publishedAt` — **never** the public packument's time map,
    which a claimed name must never consult at all (invariant #7; querying
    public npm for a claimed name is dependency-confusion reconnaissance).
- **Fail-closed on missing/unparseable time.** A matching, non-exempt
  package with no resolvable publish time (private store has no record;
  public packument fetch fails; the field is absent) or an unparseable one
  (`Date.parse` returns `NaN`) is **blocked**, not allowed through. A cooldown
  an attacker can defeat by omitting or corrupting the timestamp field would
  be worse than no cooldown at all.
- **Exemptions via `matchPackage`.** `cd.exempt` is a list of the same
  anchored-glob patterns `matchPackage` already evaluates for
  `privateNamespaces`/provenance carve-outs — no new pattern language. A name
  matching any exempt pattern short-circuits to `{ block: false }` before the
  publish-time lookup even runs. **Caveat, called out explicitly:** an
  exemption is a hole in a time-based control by design — anything matching
  it bypasses the "give the ecosystem time to catch a bad release" property
  entirely, on day one of publication. Keep exemption lists narrow (specific
  package names or a tight internal-namespace glob, not a broad wildcard) and
  treat every entry as a standing risk decision, not a convenience default.
- **Surfaces overlaid — every read and gate agree.** `cooldownFor` (per
  package/version, `packages/proxy/src/server.ts`) is a no-op returning
  `{ block: false }` when the policy has no `releaseCooldown`, so the overlay
  is inert by default. When active, it's applied consistently everywhere a
  verdict is served or reported, so no preflight surface can report `allow`
  for a coordinate the tarball gate is about to block:
  - the tarball serve gate (`gateAndSend`, composed with the quarantine
    overlay: `applyCooldown(applyQuarantine(report), cooldown)`);
  - `GET /-/audit/:name/:version`;
  - `GET /-/explain/:name/:version` (overlaid *before* `remediate()` runs, so
    remediation advice reflects the held verdict, not the stale cached one);
  - `POST /-/audit-tree`'s per-row audit (composed with quarantine, same as
    the tarball gate);
  - `GET /-/manifest/:name/:version`.
- **Enforcement semantics match the existing `SENTINEL_POLICY` gate.** Under
  `SENTINEL_POLICY=block` (default `observe`), a cooldown-forced `block`
  verdict at the tarball route 403s exactly like any other `block` verdict —
  no new status code or response shape. Under `observe` (default), the
  overlaid `block` verdict is reported everywhere above (headers, JSON
  bodies, `audit-tree` rows) but the tarball still serves, matching how
  `observe` already treats every other block reason.

## Consequences

- A version published inside the configured window is held **regardless of
  its score** — a `releaseCooldown` block is independent of and takes
  priority over whatever the rules/policy scoring produced, the same
  relationship quarantine already has to the cached score.
- Operators who want the mitigation but need a fast path for emergency
  releases get one (`exempt`), at the acknowledged cost of a per-package hole
  in the control — this is the documented trade-off, not an oversight.
- No wall-clock nondeterminism leaks into `@sentinel/core`; `npm test`'s
  "scoring is deterministic across runs" guarantee (invariant #1) is
  unaffected because the overlay lives entirely in the proxy, applied after
  scoring, never inside it.
- Adding `releaseCooldown` to a signed policy is a compatible, additive
  change for policies that don't set it — `parsePolicy` treats it as
  optional and every `cooldownFor` call is a no-op without it.

## Deferred

- No mechanism to shorten or waive an in-progress cooldown for a specific
  already-published version short of adding it to `exempt` and re-signing
  the policy (no per-version override).
- No visibility surface analogous to `sentinel violations` listing
  currently-held cooldown versions across a fleet; the overlay is
  recomputed per-request from `now`, not persisted as a distinct record.

## Rejected

- **Enforce cooldown as a core rule (`Rule` in `rules/index.ts`) instead of a
  proxy overlay** — rejected: a rule is pure `(AuditInput) => Finding[]` with
  no wall-clock input, and reading `Date.now()` inside `@sentinel/core` would
  make the same tarball score differently depending on when it's audited,
  breaking invariant #1 outright. The overlay pattern (already established
  for quarantine, ADR-0023/0040) keeps the score pure and puts the
  time-dependent decision where the request's actual clock lives.
- **A single global publish-time source (packument-only)** — rejected: a
  claimed/private package has no public packument entry to read at all, and
  even where one exists it's attacker-writable metadata for an unclaimed
  name (an attacker republishing under a spoofed `time` value). Splitting by
  origin (private-store `publishedAt` for claimed names, packument `time` for
  everything else) keeps the same trust boundary invariant #7 already
  enforces elsewhere.

Extends ADR-0023/ADR-0040 (the serve-time overlay pattern this ADR reuses
verbatim), ADR-0010/0015 (the claimed-namespace trust boundary
`resolvePublishTime`'s origin split relies on), and ADR-0029 (the packument
`time` map this overlay shares with release-anomaly scoring).
