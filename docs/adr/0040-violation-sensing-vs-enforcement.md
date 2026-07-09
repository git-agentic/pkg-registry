# ADR-0040: Violation sensing ≠ enforcement — quarantine is a server decision

Date: 2026-07-10
Status: Accepted
Supersedes: ADR-0023 (only its auto-quarantine default — `confirmed` client
`confidence` triggering quarantine unconditionally; ADR-0023's containment
and telemetry claims are otherwise unchanged and still Accepted).

## Context

ADR-0023 turned the sandbox into a sensor: `sentinel-script-shell` best-effort
POSTs a detected violation to `POST /-/violations`, and `ViolationStore`
quarantined the reported integrity whenever the *client-supplied*
`confidence` field was `"confirmed"`. The endpoint is deliberately
unauthenticated (ADR-0023's Auth posture section), on the reasoning that a
spoofed report is bounded — it can only target an already-audited integrity
and can only force `block`, never `allow`.

That bound is real, but the blast radius is bigger than a single install: the
`ViolationStore` key is `integrity` (invariant #4), so one forged or
anonymous `confirmed` report quarantines that exact tarball **fleet-wide**,
for every proxy instance and every caller, until an operator manually clears
it (`DELETE /-/violations/:integrity`). Any caller of the open, unauthenticated
endpoint — not just the legitimate `sentinel-script-shell` reporter — could
submit `{ confidence: "confirmed" }` for a real integrity and force a
fail-closed denial-of-service against it. This is issue #9: violation
*sensing* (an observation about what a sandboxed child did) was conflated
with violation *enforcement* (a decision to quarantine), and the enforcement
decision was being derived entirely from an unauthenticated client claim.

## Decision

Split sensing from enforcement:

- **Telemetry (recording) is always allowed.** `POST /-/violations` keeps
  accepting and storing every report — confirmed or suspected, authenticated
  or not — exactly as before. The 400-unless-already-audited bound from
  ADR-0023 is unchanged. Recording a violation is visibility, not action, and
  stays cheap and open.
- **Quarantine (enforcement) is a server decision, opt-in and auth-gated.**
  A new `SENTINEL_AUTO_QUARANTINE=1` environment variable, parsed once at
  startup (`resolveAutoQuarantine` in `packages/proxy/src/index.ts`, the same
  fail-closed-at-startup posture as `SENTINEL_AUTH_PUBKEY` and friends), is
  the only thing that can turn a recorded violation into a quarantine. Setting
  it **without** `SENTINEL_AUTH_PUBKEY` also configured is a startup FATAL
  (`process.exit(1)`) — auto-quarantine without auth would just re-introduce
  the anonymous-DoS path it's meant to close, so the combination is refused
  outright rather than silently downgraded.
- **Effective only when auth is enabled and the report is confirmed.**
  `createServer` computes `autoQuarantineEnabled = Boolean(opts.autoQuarantine)
  && authz.enabled` (`packages/proxy/src/server.ts`); the `/-/violations`
  handler passes `{ autoQuarantine: autoQuarantineEnabled && v.confidence ===
  "confirmed" }` into `ViolationStore.record`. `ViolationStore` (`packages/
  proxy/src/violations.ts`) no longer derives `quarantined` from the client's
  `confidence` field at all — it quarantines only when the caller passes
  `autoQuarantine: true`, or when the existing record was already
  quarantined (sticky, per ADR-0023: only `clear()` lifts it). Every
  quarantine that fires this way is therefore attributable to a request that
  passed through an enabled auth gate — the same signed-role-token
  boundary Phase 12 (ADR-0025) already put in front of every other mutating
  control-plane route.
- **Open mode (no `SENTINEL_AUTH_PUBKEY`) never quarantines.** With auth
  disabled, `autoQuarantineEnabled` is always `false` regardless of the env
  var, so a deployment running the historical open posture keeps recording
  violations exactly as before but never auto-quarantines from them — closing
  the anonymous-quarantine path entirely for that mode.
- **Default is record-only.** Unset `SENTINEL_AUTO_QUARANTINE` (the default)
  means every violation — confirmed or suspected — is stored and surfaced
  (`sentinel violations`, the dashboard panel, `x-sentinel-violations`) but
  never forces `block`. An operator who wants the ADR-0023 fleet-wide
  auto-quarantine behavior back opts in explicitly, and can only do so once
  they've also turned on token auth.

Nothing about *what* gets classified as a violation changes:
`classifyViolation`, `computeDenySet`, the sandbox runners, and
`sentinel-script-shell`'s best-effort reporting are all untouched by this
ADR. Nothing about the serve-time overlay changes either — `applyQuarantine`
still runs at the tarball serve gate and in `audit-tree`, still returns a
shallow copy with a `weight: 0` finding prepended, and still never mutates
the cached `AuditReport` (invariant #1 unchanged).

## Consequences

- **Supersedes ADR-0023's auto-quarantine default.** ADR-0023's description
  of "`confirmed` ⇒ quarantined" as an unconditional consequence of a client
  report is no longer accurate; quarantine now requires an operator opt-in
  plus enabled auth. ADR-0023's Status line is updated to note the
  supersession; its body is left as-is (an accurate history of what Phase 10
  built and why), since the containment and detection mechanics it describes
  are unchanged.
- **ADR-0023's containment claims are unchanged.** "A swallowed denial evades
  telemetry, not containment" still holds exactly as written — this ADR only
  touches what happens to a *recorded* violation, never what the sandbox
  itself denies at the syscall level. The sensor keeps sensing; only the
  action taken on what it senses moved behind an auth gate.
- **A deployment that wants the old behavior can still get it**, deliberately
  more expensive than a one-line flag flip: it must also turn on
  `SENTINEL_AUTH_PUBKEY`, meaning every mutating control-plane route (not
  just `/-/violations`) now requires a signed role token. This is treated as
  a feature, not a cost — an operator who cares enough about fleet-wide
  auto-quarantine to want it back is exactly the operator who should also
  want the rest of the control plane authenticated.
- **Server-verifiable evidence remains out of scope.** This ADR does not add
  any mechanism for the proxy to independently verify a violation report's
  contents (e.g. re-deriving the classification from raw sandbox output
  rather than trusting the reporter's `kind`/`confidence`/`evidence`
  fields). Trust in *what a report says happened* still rests entirely on the
  reporter's credential (a token that passed `authz.requireRole`) plus the
  standing bound that only an already-audited integrity can be targeted at
  all. Making the report itself independently verifiable — rather than just
  gating who is allowed to submit an actionable one — is deferred future
  work.
- **Record-only-by-default changes fleet behavior for existing deployments.**
  Anyone running with `SENTINEL_VIOLATIONS` persistence and no
  `SENTINEL_AUTH_PUBKEY`/`SENTINEL_AUTO_QUARANTINE` set will, after
  upgrading, see confirmed violations recorded and surfaced but no longer
  automatically force `block` at the serve gate. This is the intended fix for
  #9, not a regression: the previous behavior was exactly the anonymous
  fleet-wide-DoS vector this ADR closes.

## Deferred

- Server-verifiable violation evidence (see above) — authenticating *who*
  may report is in scope here; independently verifying *what* they report is
  not.
- Per-role scoping of who may set `autoQuarantine`-eligible reports (today
  any role that passes `authz.requireRole` for `POST /-/violations` — see
  Phase 12's role map — is equally trusted; a narrower "violation-reporter"
  role is not introduced by this ADR).
- Auto-quarantining on `suspected` confidence (ADR-0023 already deferred
  this; still deferred).
- Cross-version propagation and a central multi-proxy telemetry aggregator
  (ADR-0023's other deferrals; still deferred).

## Rejected

- **Authenticate `/-/violations` but keep confidence-derived quarantine as
  the default** — rejected: this still lets any caller holding *any* valid
  role token that can reach the endpoint force a fleet-wide quarantine by
  merely asserting `confidence: "confirmed"` in the payload, without the
  operator ever deciding auto-quarantine was a behavior they wanted. Gating
  the *decision* (opt-in flag) independently of gating the *endpoint*
  (auth) is what makes every quarantine attributable to a deliberate
  operator choice, not just a valid credential.
- **Silently downgrade `SENTINEL_AUTO_QUARANTINE=1` without auth to a no-op**
  instead of a startup FATAL — rejected: a silent downgrade is exactly the
  kind of "looks configured, isn't actually enforcing" gap this codebase
  avoids elsewhere (`SENTINEL_ADVISORIES`/`SENTINEL_VULNERABILITIES`/
  `SENTINEL_TARBALL_ORIGINS` all FATAL on a bad configuration rather than
  falling back quietly). An operator who typos their auth setup should find
  out at startup, not discover months later that auto-quarantine was never
  active.

Extends ADR-0023 (runtime violation telemetry — sensing, classification, and
the serve-time overlay, all unchanged), ADR-0025 (control-plane auth — the
signed-role-token gate this ADR reuses rather than inventing a new auth
mechanism), and ADR-0013 (approval/reconcile overlay precedent). Supersedes
ADR-0023 for the auto-quarantine default only, per above.
