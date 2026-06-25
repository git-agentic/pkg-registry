# ADR-0015: Private-registry publish protocol, auth, and fail-closed routing

**Status:** Accepted
**Date:** 2026-06-25
**Phase:** 2 (implements ADR-0010 Option A)

## Context
ADR-0010 makes the proxy authoritative for claimed names. Realizing it as full
hosting requires an npm-compatible publish path and an authoritative serve path.

## Decision
1. **Claims live in the signed `EnterprisePolicy`** (`privateNamespaces` globs,
   reusing `matchPackage`). A claim is security-critical, so signing/versioning
   protects it; a tampered or malformed policy fails closed at boot (ADR-0014).
2. **Fail-closed routing:** for a claimed name the proxy serves only from the
   `PrivatePackageStore` and NEVER consults the public upstream — a claimed but
   unpublished name returns `404`. Non-claimed names pass through unchanged
   (the scoped exception to ADR-0005).
3. **Publish protocol (captured empirically from npm 11.x):** `PUT /:pkg` (scoped
   `%2f`-encoded), `Authorization: Bearer <token>`, JSON body with one new version
   in `versions` + its base64 tarball in `_attachments`. npm pre-GETs the packument
   (a `404` means "new package, proceed to PUT") and sends only the new version per
   publish — no client-side merge, no `_rev`. The store accumulates versions.
4. **Auth before parse:** publish requires a configured bearer token
   (`SENTINEL_PUBLISH_TOKENS`); the check runs in middleware BEFORE the body parser,
   and the global 1MB JSON parser is bypassed for `PUT` (a real tarball exceeds 1MB).
5. **Audited + policy-gated publish:** every publish is `runAudit` + `score(policy)`;
   a `block` verdict is rejected and not stored.
6. **Same install-time gate** for private packages (score + 0011 approval gate);
   publish and approval are orthogonal — publishing does not auto-approve.
7. **Telemetry** is local-only by default; the public-shadow probe is opt-in
   (`SENTINEL_SHADOW_PROBE`) because probing leaks claimed names to public npm.

## Consequences
- Sentinel takes on registry-authoritative duties (storage, availability) for claimed
  names. Deferred: unpublish/deprecate, dist-tags beyond `latest`, GC/durability,
  concurrent-publish locking, access levels, multi-user roles, federation.
- The transparency invariant (ADR-0005) now has a documented, claim-scoped exception.

## Notes & known asymmetries (from the implementation review)
- **No diff baseline for private audits.** The public path computes a `previousVersion`
  baseline so the policy `diffMultiplier` weights changed-file findings; the private
  publish/serve paths audit each version in isolation, so the multiplier never applies
  to private packages. A minor leniency on changed-file findings, not a fail-closed gap.
- **`GET /-/private` is unauthenticated**, consistent with the other read-only `/-/`
  status routes (`/-/audits`, `/-/approvals`) under ADR-0013's trusted single-tenant
  posture. It exposes claimed globs + the private inventory to any local caller; gating
  it (and those routes) behind auth is part of the deferred multi-tenant work.
- **Concurrent same-version publish is last-write-wins** (the `getVersion` duplicate
  check and `put` are not atomic) — acceptable for the MVP; concurrent-publish locking
  is in the deferred list above.
- The publish token is compared in constant time (`crypto.timingSafeEqual` over
  digests), and `parsePublishBody` rejects path-traversal versions and a manifest whose
  `name`/`version` disagree with the publish target.
