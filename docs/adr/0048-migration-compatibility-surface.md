# ADR-0048: Migration & compatibility surface

**Status:** Accepted (Phase 33 — implemented 2026-07-13)
**Date:** 2026-07-11

Last of the four registry-evolution ADRs (0045–0048). Decision record for
[wayfinder ticket #40](https://github.com/git-agentic/pkg-registry/issues/40)
(map [#33](https://github.com/git-agentic/pkg-registry/issues/33)); the
client-behavior evidence base is
[docs/research/npm-registry-api-surface.md](../research/npm-registry-api-surface.md).
Depends on ADR-0045 (partition, audit-gated import), ADR-0046 (claims),
ADR-0047 (retraction semantics).

## Context

The registry evolution must not cost Sentinel its founding property: npm,
pnpm, Yarn (1 and Berry), and bun work unmodified against it (ADR-0001/0005/
0007). The API-surface research established, from client source, exactly which
routes each client requires, which Accept headers they send, and how each
degrades when a route is absent. Three findings shape this ADR: Yarn Berry
never sends the abbreviated-packument Accept header and reads the full
document's `time` field; pnpm checks the `Content-Type` echo on abbreviated
responses and 400s dist-tag writes that carry the corgi Accept; and every
mutation flow (deprecate, unpublish) rides a `_rev` dance the clients own.

Two further forces: an operator who adopts registry mode must be able to
leave it — but under the ADR-0045 partition, disabling the claim corpus flips
previously-claimed names back to public-mirror, which is a dependency-
confusion resurrection for exactly those names; and the data model must hold
native and mirrored packages side by side without violating packument
transparency (ADR-0005) for the mirrored kind or integrity-keyed caching
(ADR-0004) for either.

## Decision

1. **The compatibility contract** for native/claimed namespaces, ratified
   from the research classification:
   - **MUST implement natively:** packument GET served **full** (including
     `time`) with corgi Accept negotiation and the
     `Content-Type: application/vnd.npm.install-v1+json` echo; tarball GET;
     publish `PUT /{package}` (base64 `_attachments`, optional `.sigstore`
     attachment — ADR-0046 trusted publishing); the `-rev` dance
     (`DELETE`/`PUT /{pkg}/-rev/{rev}` + tarball `DELETE …/-rev/{rev}`);
     dist-tag routes at `/-/package/{spec}/dist-tags[/{tag}]` (tolerant of
     the corgi-on-writes client trap); legacy auth
     `PUT /-/user/org.couchdb.user:{name}` (pnpm and Berry hard-require it);
     and a trivial `/-/whoami` (token-identity echo — Berry's auth-error path
     reads it).
   - **Proxied unchanged:** `/-/v1/search`, advisories-bulk audit, `/-/npm/v1/keys`,
     attestation fetches, the `/-/v1/login` web flow.
   - **Ignorable, degradation documented:** staged publish, profile/token/
     access/org/team routes, single-version manifest GET.
   - **`npm unpublish` IS the retraction UI.** The client's `-rev` delete
     maps to an ADR-0047 retraction request: window-enforced (403 carrying
     the window state past 72 h ∧ 1,000), tombstoning on success. There is no
     raw delete distinct from retraction. `npm deprecate` (metadata-only
     packument overwrite) remains freely available.
   - *Test: real npm/pnpm/Berry/bun binaries perform install and publish, and
     every mutation their CLI actually exposes (npm/pnpm/Berry dist-tag;
     npm/pnpm unpublish in-window and past-window). Berry exposes no
     unpublish command and bun exposes neither dist-tag nor unpublish, so
     those non-existent CLI cells are N/A; byte-identical request/response
     wire tests cover every shared proxied route.*
2. **The escape hatch: pure-proxy mode is one fail-closed switch, and
   reverting is loud, lossless, and lock-in-free.** Registry mode off ⇒ the
   claim corpus is ignored by resolution and the publish/retraction/claim
   routes return a distinct `registry-mode-disabled` error. The signed
   policy's `privateNamespaces` are untouched — they belong to the proxy
   (ADR-0010/0015), not registry mode. Flipping off **with native content
   present requires an explicit acknowledgment** (missing ⇒ startup FATAL,
   the ADR-0040 posture) and emits a **revert manifest** enumerating every
   name whose resolution class flips — each line a named dependency-confusion
   resurrection — plus the safe path (migrate those names into policy
   `privateNamespaces` first). The revert deletes nothing: native store,
   claim state, tombstones, and history stay on disk, and re-enabling
   registry mode restores byte-identical resolution. An export command emits
   native packages as standard republishable tarballs + packuments. *Tests:
   unacknowledged flip with native content ⇒ FATAL; manifest lists exactly
   the flipped names; flip/flip-back round-trips byte-identical; export
   output republishable to any registry.*
3. **The coexistence data model: derive, don't store; extend, don't fork.**
   `source(name)` remains the ADR-0045 pure function — there is **no stored
   source-class field** anywhere, so no second source of truth can drift.
   Mirrored names keep today's model literally unchanged: passthrough
   packuments with only `dist.tarball` rewritten (ADR-0005), tarballs and
   audit reports cached by integrity (ADR-0004). Native names extend
   ADR-0015's `PrivatePackageStore`: per version — manifest, tarball bytes,
   `integrity`, publish provenance (publisher identity, claim id, attestation
   ref), the publish-time `AuditReport` with `policyHash` and corpus
   versions, and ADR-0047 tombstones; packuments are **synthesized** full
   (including `time` and `_sentinel.retractions`). Both kinds share one
   integrity-keyed audit-cache discipline under the same `AuditReport`
   contract and never-mutate rule. **Audit-gated history imports preserve the
   upstream `integrity` verbatim**, so lockfiles written before a name was
   claimed keep resolving after it flips native — only `dist.tarball` URLs
   change, which is already the proxy's normal rewrite. *Tests: no
   source-class column exists; mirrored serving byte-identical to today
   except `dist.tarball`; synthesized packuments pass the compat matrix;
   pre-claim lockfile installs succeed post-import with unchanged integrity
   checks.*

## Consequences

- The native surface Sentinel commits to is small and bounded — two read
  routes it already serves, five write/auth routes, one echo header — and the
  compat matrix makes "npm clients work unmodified" a regression suite
  instead of a slogan.
- Mapping unpublish onto retraction means npm's own CLI enforces Sentinel's
  immutability window with no client changes — and closes the raw-delete
  hole: there is no code path that removes bytes outside ADR-0047 semantics.
- The revert manifest turns the escape hatch's genuine danger (resolution
  downgrade for previously-claimed names) from a silent config side effect
  into an explicit, enumerated operator decision — the threat-model draft
  records mode-revert as an attack surface precisely because the manifest
  makes it auditable.
- Deriving source class keeps resolution reproducible from (policy, corpus)
  alone — a store migration or restore can never change routing.
- Integrity-preserving imports commit Sentinel to serving upstream-built
  bytes under native names when history is adopted; the publish gate audits
  them on import (ADR-0045), and provenance records mark them `imported`, so
  the distinction survives in audit data without forking the model.

## Alternatives considered

- **Fork an existing registry (verdaccio et al.).** Fastest route to a
  complete npm API — but it imports a foreign codebase's parsing and storage
  semantics into the trust boundary the audit engine gates, and Sentinel's
  publish path already exists (ADR-0015); the delta worth building is the
  contract above, not a registry rewrite. Rejected.
- **Full mirror of public npm.** Makes every name native and eliminates the
  passthrough — but abandons ADR-0005's transparency (the proxy's founding
  wedge), takes on npm-scale storage for no signal gain, and turns Sentinel
  into the npm replacement ADR-0001 explicitly declines to be. Rejected.
- **A custom (non-npm) publish/resolve API.** Cleaner semantics than the
  couchdb legacy — and useless: every client in the fleet speaks the npm
  protocol, and the research shows the legacy routes are the compatibility
  floor. Sentinel-specific capability belongs on the existing `/-/` control
  plane, not in a parallel dialect. Rejected.
- **A stored source-class column.** Simpler queries, but a second source of
  truth that a partial restore, replication lag, or a bug can desynchronize
  from the policy/corpus — precisely the drift `source(name)`-as-pure-function
  makes impossible. Rejected.
- **Delete-on-revert.** A "clean" exit from registry mode — that destroys the
  only copy of native packages and forecloses re-enable; retention + export
  achieves the same operator freedom without the data loss. Rejected.
- **Silent revert (no acknowledgment, no manifest).** Symmetric with how
  other mode flags behave — but no other flag's default can silently re-open
  dependency confusion for named packages; the FATAL-without-acknowledgment
  posture is the same one ADR-0040 applies to auto-quarantine for the same
  reason (a config default must not decide a security posture change).
  Rejected.
