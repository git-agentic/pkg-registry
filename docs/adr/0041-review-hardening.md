# ADR-0041: Review hardening — unscanned-content signal + SLSA-predicate-required provenance

**Status:** Accepted (Phase 27)
**Date:** 2026-07-10

## Context

An external security review of this repo (issues #9–#12) found three gaps.
#9 was closed by ADR-0040 (violation sensing vs. enforcement). This ADR covers
the remaining two behavioral gaps plus one CI-hygiene item shipped in the same
branch:

- **#11 — silent scan blind spot.** `extractTarball` (`packages/core/src/
  extract.ts`) has always skipped files over `MAX_FILE_BYTES` (2 MiB) from
  text scanning, and never scanned native/binary extensions at all (there's
  no text content to run the rule engine's string matchers over). Both are
  reasonable scanning boundaries on their own, but neither was surfaced
  anywhere in the audit output — a tarball that shipped its actual payload as
  a 5 MB bundled `.js` or a `.node` addon scored identically to one with no
  such files, with nothing in the report hinting that a class of content
  never got looked at.
- **#12 — provenance `verified` didn't require SLSA.** ADR-0022's
  `verifyProvenance` iterates every attestation bundle and, for any bundle
  carrying the SLSA v1 predicate, extracts a build identity; but the final
  status returned `"verified"` whenever *any* bundle in the list
  cryptographically verified and bound to the subject — including the case
  where every present bundle was a valid non-SLSA attestation (e.g. an npm
  publish-only attestation with no build-provenance predicate) and none
  carried SLSA v1 at all. A package with a real, checkable signature but no
  build-provenance claim was reported exactly the same as one with a full
  SLSA v1 chain, silently overstating what had actually been established.
- **#10 — mutable Action tags.** Every third-party `uses:` in
  `.github/workflows/*.yml` and `action.yml` pinned to a mutable version tag
  (`@v4`, `@v3`, `@v7`) rather than a commit SHA — a tag can be repointed
  after review completes, which is exactly the supply-chain risk this project
  exists to flag in *other* people's dependency trees.

## Decision

### #11 — `unscanned-content` finding (extends the extract-coverage design)

- `ExtractResult` gains `unscanned: UnscannedEntry[]` (`{ path, size, kind:
  "large-code" | "native" }`), populated by `extractTarball` alongside the
  existing scan: a file over `MAX_FILE_BYTES` whose extension matches the new
  `CODE_EXT` (a subset of the existing `TEXT_EXT` — `.js`/`.mjs`/`.cjs`/`.ts`/
  `.mts`/`.cts`/`.jsx`/`.tsx`) is tracked as `"large-code"`; a file matching
  the new `NATIVE_EXT` (`.node`/`.wasm`/`.so`/`.dll`/`.dylib`/`.exe`) is
  tracked as `"native"` regardless of size. The list is capped at
  `MAX_UNSCANNED` (100 entries) to bound memory on a pathological
  many-binary tarball — the same "count, don't unbounded-collect" posture as
  ADR-0039's caps.
- `runAudit` synthesizes a `metadata`-category finding, `ruleId:
  "unscanned-content"`, when the list is non-empty: **low** by default,
  escalated to **medium** when at least one `"native"` entry co-occurs with
  a detected install script (`detectInstallScripts`) — the combination a
  reviewer would actually want flagged (a binary blob plus a lifecycle hook
  that can execute it at install time), not native content alone (many
  legitimate packages ship prebuilt `.node` addons with no install script
  drama). It is synthesized directly in `runAudit`, the same way Phase 26
  Part A's `resource-abuse` finding is — **not** a registered `Rule` in
  `rules/index.ts`, because it needs `ExtractResult.unscanned`, a value the
  pure per-file rule pipeline doesn't see. The rule count is unchanged.
- **Never a hard block on its own.** `metadata` category, `low`/`medium`
  severity — under the default policy this rides the same weighted-finding
  path as `typosquat`/`dependency-confusion`/release-anomaly. It's a
  visibility fix, not a new blocking signal: the point is that "some content
  wasn't scanned" is now in the report, not that unscanned content is
  presumed malicious.

### #12 — provenance `verified` requires an SLSA v1 predicate (extends ADR-0022)

- `verifyProvenance` now tracks whether **any** bundle in the list carried
  the SLSA v1 predicate (`sawSlsa`), in addition to the existing per-bundle
  crypto/chain/subject-binding checks. After the loop, if every bundle
  verified and bound but `sawSlsa` is `false`, the function returns
  `status: "unknown"` with `identity: null` and a `reason` string — **not**
  a new status value. `ProvenanceStatus` stays exactly `verified | invalid |
  absent | unknown`.
- This reuses `unknown`'s existing fail-open semantics rather than inventing
  a fifth status: ADR-0022 already defines `unknown` as "claimed, but
  something needed to establish `verified` is missing" (bundle unfetchable,
  no trust material). A cryptographically-valid-but-non-SLSA attestation is
  the same shape of gap — the *evidence needed to call it verified build
  provenance* is missing, even though the bundle itself didn't fail
  verification.
- **Nothing else about ADR-0022 changes.** The `invalid`-on-thrown-error
  fail-closed refinement is untouched (a crash over a *present* bundle is
  still `invalid`, never `unknown` — this ADR only touches the success path
  where every present bundle verified cleanly but none was SLSA). Subject-
  digest binding, the `requireProvenance` gate (still demands exactly
  `"verified"`), and the `provenanceIdentities` gate's exemption of
  `unknown` are all unchanged in code and behavior for any package that
  already carried a real SLSA v1 bundle — which is every legitimate npm
  package publishing today's provenance format, so ordinary `npm publish
  --provenance` packages keep scoring `verified` exactly as before. Only a
  publish-only (non-SLSA) attestation, previously misreported as
  `verified`, changes status.
- The provenance rule's `unknown` finding message is softened from
  "provenance attested but could not be verified (bundle unavailable or no
  trust material)" to "…not established as verified SLSA v1 provenance
  (unrecognized predicate, bundle unavailable, or no trust material)" to
  cover the new reachable case without implying every `unknown` is a missing
  bundle.

### #10 — Action SHA pinning (CI hygiene, same PR)

Every third-party `uses:` in `.github/workflows/ci.yml`,
`.github/workflows/codeql.yml`, `.github/workflows/sentinel-example.yml`, and
`action.yml` (`actions/checkout`, `actions/setup-node`,
`github/codeql-action/init`+`analyze`, `actions/upload-artifact`,
`actions/github-script`) is pinned to the commit SHA behind its current
version tag, with a `# vX.Y.Z` trailing comment for human readability.
CONTRIBUTING.md gets an "Updating pinned GitHub Actions" note: change the SHA
and its comment together after reviewing the release, and prefer Dependabot's
`github-actions` ecosystem (which raises SHA-pinned bump PRs) as the
maintenance path. This is packaging/CI hygiene, not a scoring or gate change —
it's included in this ADR only because it shipped in the same review-hardening
branch as #11/#12.

## Consequences

- **`unscanned-content` adds a new finding surface, not a new gate.** No
  policy field is added; it rides the existing `metadata`-category weight
  and `hardBlockSeverity` machinery. An operator who wants it to matter more
  tunes `severityWeight`/`hardBlockSeverity` the same way as any other
  weighted finding — nothing new to configure.
- **The rule count is unchanged (still registered-rule count as before this
  ADR).** `unscanned-content` is synthesized inline in `runAudit` from
  `ExtractResult`, the same placement as Phase 26 Part A's `resource-abuse`
  and Phase 16's `capabilityNoveltyFindings` — anything that needs data
  outside the pure per-file `Rule` signature lives here, not in
  `rules/index.ts`.
- **A policy that sets `provenanceIdentities` but not `requireProvenance`
  now lets a non-SLSA (publish-only) package through the identity gate.**
  Before this fix, a publish-only attestation was misreported as `verified`,
  so `provenanceIdentities` would check its (non-existent-in-reality)
  identity fields and could block on a mismatch. After this fix, that same
  package is `unknown`, and ADR-0022's identity gate **exempts `unknown` by
  design** (an attestation outage must not block ordinary installs) — so the
  package now passes the identity gate silently instead of being evaluated
  against it. **This is correct per ADR-0022's existing design, not a
  regression introduced here**: `unknown` was always meant to bypass the
  identity gate, and a publish-only attestation was never actually
  SLSA-identity-checkable in the first place — the pre-fix behavior was
  checking identity fields against a bundle that didn't carry them,
  which could only ever accidentally pass or arbitrarily fail, never
  meaningfully verify anything. Operators who want both "must have build
  provenance" and "build provenance must match these identities" enforced
  together should pair `requireProvenance` (which demands exactly
  `"verified"`, closing the `unknown` bypass) with `provenanceIdentities` on
  the same package patterns — restating and reinforcing ADR-0022's existing
  recommendation, now with a concrete new case (`unknown` via
  non-SLSA-but-valid) it applies to.
- **A previously-`verified` publish-only attestation now reports `unknown`.**
  Any operator relying on `verified` status for a package whose only
  attestation is a non-SLSA npm publish bundle will see that package's
  status change on upgrade. Real npm-provenance-published packages (`npm
  publish --provenance`) are unaffected — they carry a SLSA v1 bundle
  alongside the publish attestation and keep `verified`.
- **CI hygiene (#10) has no runtime effect** on the proxy, sandbox, or
  scoring — it only changes what commit a workflow step resolves to, closing
  a tag-repoint risk in this repo's own supply chain.

## Deferred

- A dedicated `unscanned-content` policy gate (e.g. a `requireFullScan` lever
  analogous to `requireProvenance`) — today it's advisory-only via the
  ordinary weighted-finding path; a hard-block lever is not introduced.
- Actually scanning large-code or native content (e.g. disassembly, WASM
  static analysis) — this ADR only makes the blind spot visible, it doesn't
  shrink it.
- A `requireProvenance`-equivalent that also demands `provenanceIdentities`
  be non-empty and matching (today the two gates remain independent opt-ins,
  as ADR-0022 already established).

## Rejected

- **A new `ProvenanceStatus` value (e.g. `"non-slsa"`) for the valid-but-
  non-SLSA case** — rejected: it would fan out every consumer of
  `ProvenanceStatus` (the rule, `requireProvenance`, `provenanceIdentities`,
  the dashboard, `explain`) to handle a fifth case, for a distinction that
  `unknown`'s existing "not enough to call this verified" semantics already
  covers. Reusing `unknown` keeps every downstream fail-open/fail-closed
  behavior correct by construction instead of by review.
- **Hard-blocking `unscanned-content` under the default policy** — rejected:
  a 2.1 MB legitimate bundled `.js` or a prebuilt `.node` addon with no
  install script is common and benign; blocking on the mere presence of
  unscanned content would be a high-false-positive tripwire. Escalating only
  the native+install-script combination to `medium` targets the actually
  suspicious pairing without punishing ordinary large bundles or
  script-free native addons.
- **Scanning large files instead of just flagging them** — rejected as
  out of scope for this ADR: it changes performance and memory
  characteristics of the hot audit path (invariant #3) and is better
  designed as its own follow-up (see Deferred) rather than folded into a
  "make the blind spot visible" fix.

Extends ADR-0039 (bounded tarball extraction — `unscanned` is tracked at the
same extraction boundary `extractTarball` already owns) and ADR-0022
(provenance deep-verify — the SLSA-predicate requirement narrows what
`verified` means without changing the status model, gate, or identity-
extraction logic it defined). Notes #10 (Action SHA pinning) as CI hygiene
shipped in the same branch. Supersedes nothing.

> Extended by [ADR-0049](0049-native-payload-loader-detection.md): raw-byte magic classification closes the disguised-container blind spot noted here.
