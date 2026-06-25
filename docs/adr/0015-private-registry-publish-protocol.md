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
