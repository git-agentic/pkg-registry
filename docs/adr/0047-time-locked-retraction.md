# ADR-0047: Time-locked retraction

**Status:** Proposed (Phase 32 — design only, no implementation)
**Date:** 2026-07-11

Third of the four registry-evolution ADRs (0045–0048). Decision record for
[wayfinder ticket #39](https://github.com/git-agentic/pkg-registry/issues/39)
(map [#33](https://github.com/git-agentic/pkg-registry/issues/33)); prior art in
[docs/research/retraction-policy-prior-art.md](../research/retraction-policy-prior-art.md).
Scope: native/claimed packages only — the partition rule (ADR-0045) makes
Sentinel authoritative for exactly those; mirrored public npm is unaffected.

## Context

A registry that accepts writes must answer what a publisher may *unwrite*. The
survey of six ecosystems maps a spectrum: full delete (pre-left-pad npm) →
windowed delete (npm today: 72 h, or no-dependents + <300 weekly downloads +
single owner) → metadata-only yank (crates.io, PyPI PEP 592, NuGet unlist —
bytes stay, pinned users escape) → advisory retract over immutable storage
(Go) → no mechanism at all (Maven Central). Each point buys stability or
maintainer control at the other's expense, and each has a documented failure:
left-pad's cascading 404s were cured only by restoring the bytes; lockfiles
resolve yanked versions silently for years; Go's `retract` requires the author
to still hold publish access — useless in exactly the compromised-maintainer
case retraction most needs to serve.

This is the research-thesis tension in its sharpest form: Sentinel's product
thesis is deterministic, reproducible verdicts over immutable,
integrity-addressed content (ADR-0004) — yet the registry evolution exists
partly because maintainers legitimately need to pull a bad release, and a
proxy structurally cannot offer that. The survey also returned a load-bearing
negative result: **no registry bounds retraction by a hard cumulative
download count.** npm's usage conditions are a trailing-week rate; crates.io's
2025 windowed delete normalizes downloads per month of age. Sentinel's dual
bound has no precedent to cite and must be justified from first principles.

## Decision

1. **Dual-bound window: retraction is allowed while `age < 72 h` AND
   `cumulativeDownloads < 1,000`; past either bound, immutability is
   absolute.** Both values are policy data in `DEFAULT_POLICY`. The
   first-principles case: the two bounds cap *different* harms. The time bound
   caps the honest-mistake window — the figure npm and crates.io converged on
   independently. The download bound caps the actual harm unit of left-pad:
   builds retroactively broken. Elapsed time only proxies adoption; cumulative
   downloads *is* adoption — and unlike public registries, the authoritative
   instance serves every fetch of a native package and can count exactly
   (distinct tarball serves, deduped where the history DB, ADR-0028, allows).
   A version published Friday night with zero fetches is safely retractable
   Monday morning; a version that swept the fleet in an hour has already done
   its damage and must freeze. Requiring both under threshold takes the
   conservative intersection. *Tests: retraction at 71 h/999 succeeds; at
   73 h/5 and at 2 h/1,001 it is rejected with distinct errors; bounds read
   from policy.*
2. **Tombstone semantics: availability dies, history survives.** The
   retracted version is removed from the served `versions` (range resolution
   can never select it) and recorded in a packument-level
   `_sentinel.retractions[version] = {retractedAt, reason, advisoryId}` block
   (unknown fields are legal in packuments; clients ignore it, Sentinel
   tooling renders it). The tarball GET returns **410 Gone** with a JSON
   tombstone — "existed, deliberately removed," distinguishable from a
   never-existed 404. `latest` retargets to the highest remaining version;
   none remaining yields the known claimed-but-unpublished shape. The
   identifier `name@version` is **permanently spent**: republish-after-retract
   is a substitution attack (pull clean bytes, ship dirty ones under the same
   identifier) and is rejected forever — fixes ship as new versions. Audit
   records, in-toto/DSSE attestations (ADR-0032), and history-DB rows are
   retained byte-identically: an attestation binds bytes that existed, and
   retraction removes availability, never history. Already-fetched installers
   keep working from local caches — no phone-home pretense — and learn via the
   advisory path. *Tests: resolution never selects a retracted version;
   410 + tombstone on tarball GET; spent-identifier republish rejected;
   stored audit/attestation bytes unchanged.*
3. **Advisory emission at two honest speeds.** The act of retraction
   **synchronously appends** a `kind: "retraction"` advisory (the tombstone's
   `advisoryId`, reason, `name@version`) to the instance's operator advisory
   feed — the existing `input.advisories` merge channel of the known-advisory
   rule (ADR-0034). No new rule; nothing fetched at audit time; from that
   moment any `audit-tree` over a lockfile pinning the version flags it on the
   retracting instance. Fleet-wide, retractions in claimed namespaces land in
   the steward's next bundled corpus release (the ADR-0046 release train);
   corpus-cadence latency is stated plainly as the cost of the offline
   architecture. Severity is reason-coded from a required enum: `security` →
   high (blocks under default weights); `withdrawn` / `broken` / `legal` →
   moderate (warns). Weights are policy — an enterprise wanting
   reproducibility-hard posture escalates `withdrawn` to blocking in data,
   not code. *Tests: immediate flagging on the retracting instance; same
   lockfile + same corpus version ⇒ same verdict everywhere.*
4. **Fleet propagation reuses the serve-time quarantine overlay (ADR-0023),
   never mutating cached scores.** A serve whose `name@version@integrity`
   matches a retraction advisory gets the overlay treatment: tombstone finding
   injected, response forced to 410/block, while the cached `AuditReport`
   stays byte-identical. **Deliberate divergence from ADR-0040, argued:**
   auto-quarantine is opt-in (`SENTINEL_AUTO_QUARANTINE=1` + auth) because it
   is server-decided *heuristic judgment* requiring attributability.
   Retraction-quarantine is categorically different — an authoritative,
   publisher-initiated, steward-signed *fact*, attributed by the advisory
   entry itself. It therefore applies **by default, with no opt-in flag**:
   gating an authoritative retraction behind the heuristic-quarantine flag
   would let a config default silently keep serving bytes the publisher
   pulled. ADR-0040's attributability rationale is satisfied by a different
   mechanism, not bypassed. *Tests: a cached retracted version serves
   410 + tombstone while its stored report is unchanged; overlay active with
   no env flag; same-name non-retracted versions unaffected.*

**The tension, resolved:** maintainer control exists only inside a window
where breakage is provably small — both bounds under threshold. Past it,
immutability is absolute. Even inside it, only *availability* is mutable;
identity, history, audits, and attestations never are. The same rule bounds
retraction abuse: a widely-downloaded version cannot be retracted at all, so
griefing a popular dependency out of existence is impossible by construction.

## Consequences

- Reproducible builds get a stronger guarantee than npm offers: any version
  that survived 72 h or reached 1,000 downloads is permanently immutable on
  Sentinel — and unlike crates.io's rate-normalized delete, the bound cannot
  be aged around (cumulative counts never reset).
- Lockfiles pinning a retracted version fail closed at the next audited
  install with an explanation (`/-/explain` renders the tombstone), rather
  than silently resolving a pulled version for years — the yanked-but-locked
  divergence from the survey, answered.
- The compromised-maintainer case works even when the attacker rotates the
  org's credentials: the *operator* of the authoritative instance can retract
  within the window without a new publish — the failure mode that makes Go's
  `retract` unusable is avoided because retraction is an instance-side act,
  not a package-side one.
- The window values are unprecedented, so they carry measurement duty: the
  roadmap's exit criteria include recording window-hit telemetry (how often
  retraction is attempted outside the window) to revisit the defaults with
  data — in policy, not code.
- Retraction cannot serve as a takedown mechanism for widely-adopted
  packages, by design; legal takedowns are an operator/steward process
  outside this ADR, and the threat-model draft records that boundary.

## Alternatives considered

- **Full immutability (Maven Central / Go proxy).** Maximal reproducibility
  and the simplest story — but it leaves the honest-mistake and
  leaked-credential cases with no remedy except `deprecate`, and the registry
  evolution's charter names time-locked retraction as one of its two reasons
  to exist. Rejected as the default; note an enterprise can approximate it by
  setting both window values to zero (policy, not code).
- **npm-style time-only unpublish.** The simplest windowed model, but the
  research shows time alone misjudges both directions: it forbids retracting
  a zero-download version at hour 73 and permits retracting a
  thousand-install version at hour 71. The download bound exists precisely to
  fix this.
- **Unrestricted author delete (PyPI today).** Maximal maintainer control;
  the left-pad incident is the canonical demonstration of why not, and PyPI's
  own withdrawn PEP 763 shows the ecosystem consensus moving away from it.
- **Metadata-only yank (crates.io / PEP 592 / NuGet).** The industry's stable
  middle — but yank leaves the bytes servable to anyone who pins, which is
  the wrong default for the security-retraction case (`security` reason) that
  a security product must serve first. Sentinel's tombstone is deliberately
  one notch harder than yank inside the window, while the advisory channel
  preserves yank's best property (pinned users get a signal, not silence).
- **Retraction as a new-version directive (Go `retract`).** Elegant reuse of
  the publish path and fully offline — but it requires the author to still
  hold publish access, failing exactly the compromised-maintainer case, and
  it is advisory-only (a warning, not a gate).
- **Gating retraction-quarantine behind `SENTINEL_AUTO_QUARANTINE`.**
  Consistent flag surface at first glance, but it conflates heuristic
  judgment with authoritative fact and makes the safe behavior opt-in; a
  fleet that never set the flag would keep serving pulled bytes indefinitely.
  Rejected — the divergence from ADR-0040 is deliberate and argued in
  Decision 4.
