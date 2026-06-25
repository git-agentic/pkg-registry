# Sentinel Phase 2.3 — Private-Namespace Registry (design)

**Date:** 2026-06-25
**Status:** Approved (brainstorming) — ready for implementation planning
**Implements:** ADR-0010 (private-namespace override), Option A (full hosting)
**Sequence context:** Final Phase 2 pillar. 0011 (permission manifest & approval) and
0012 (signed per-enterprise policy) are built and merged. This adds the
private-namespace registry that structurally eliminates dependency confusion.

---

## 1. Goal & driver

Dependency confusion (Birsan 2021) exploits resolution ambiguity: an internal name
(`@acme/payments`) that also exists on public npm can resolve to the **attacker's**
public package. Configuration-based mitigations (`.npmrc` precedence, scoped
registries) fail because they require flawless per-repo setup forever. Sentinel sits
on the resolution path already, so it can remove the ambiguity **structurally**: for
names an enterprise **claims** as private, the proxy is the authoritative source and
**never consults public npm** — the claimed name cannot resolve to an attacker's
package, whether or not a private version has been published.

Success criteria:
1. A claimed name is served **only** from the private store; a claimed-but-unpublished
   name returns `404` and the public upstream is **never** consulted for it.
2. Packages can be **published** to Sentinel (`npm publish`) with bearer-token auth;
   each publish is **audited and policy-gated** (a `block` verdict is refused).
3. Private installs flow through the **same** serve-time gate as public ones (score
   under the active policy + the 0011 capability/approval gate).
4. Non-claimed names pass through **transparently and unchanged** (the ADR-0005
   invariant holds for everything not claimed). Empty claims ⇒ zero behavior change.

## 2. Decisions locked during brainstorming

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Full hosting** — Sentinel stores + serves private packages (publish/upload) | The user chose the complete registry slice over local-dir/federation. |
| D2 | **Claim defines the namespace; publish populates it.** Claimed + unpublished ⇒ `404`, never public | The structural guarantee — a claimed name can never resolve to a public attacker package. |
| D3 | **Audit + policy-gate on publish** — reject a `block` verdict | Internal packages get the same scrutiny as public; reuses `score()`+policy from 0012. |
| D4 | **Bearer-token publish auth** (`SENTINEL_PUBLISH_TOKENS`) | A write that controls the authoritative namespace must be authenticated; multi-user roles deferred. |
| D5 | **Claims in the signed `EnterprisePolicy`** (`privateNamespaces`) | Tamper-evident, versioned; reuses `matchPackage` + signed loading. A tampered claim can't un-protect a namespace. |
| D6 | **Same serve-time gate for private installs** as public | No security blind spot; re-scored under the *current* policy even though publish already gated it. |
| D7 | **Integration = Approach A** (claim-routing in the server) | One transparent registry URL; fail-closed/authoritative logic explicit; reuses `Upstream` for reads + a new write route. |

## 3. Empirical npm publish protocol (captured, not recalled)

Captured from `npm publish` (npm 11.10.1) against a logging server — the spec is
built from these observations, and the captured `PUT` body is saved as a test fixture.

- **Pre-flight:** npm issues `GET /:pkg` (twice) before publishing. A **`404` → npm
  proceeds to `PUT`** (treats the package as new). So `404` is the correct response
  for an unpublished claimed name.
- **`PUT /:pkg`** (scoped: `PUT /@scope%2fname` — note `%2f` encoding),
  `Authorization: Bearer <token>`, `content-type: application/json`. Body:
  ```jsonc
  { "_id","name","description","access",
    "dist-tags": { "latest": "1.0.0" },
    "versions":  { "1.0.0": { …manifest…, "dist": { "integrity","shasum","tarball" } } },
    "_attachments": { "<name>-1.0.0.tgz": { "content_type","data": "<base64 tarball>","length" } } }
  ```
- **Each publish sends exactly ONE new version** in `versions` + one `_attachments`
  entry — even a 2nd-version publish after a `200` GET sends only the new version,
  **no merged map, no `_rev`/`If-Match`.** The *registry* accumulates versions; the
  packument `GET` must return all of them.
- A `201 { ok: true, ... }` response is accepted.

## 4. Architecture (Approach A)

One transparent registry URL; the proxy routes internally by claim.

### 4.1 Components

- **`PrivatePackageStore`** (`@sentinel/proxy`, new — the only genuinely new
  infrastructure: it stores tarball *bytes*). Filesystem-backed
  (`SENTINEL_PRIVATE_STORE`, layout `<name>/<version>/{package.tgz, meta.json}`) with
  an in-memory index, mirroring `AuditStore`'s persistence style. Per published
  `(name, version)` it holds: tarball bytes, the version manifest, integrity, the
  **policy-independent `Audit`** computed at publish, publisher + `publishedAt`.
  - `has(name): boolean` · `versions(name): string[]` · `latest(name): string`
  - `put(name, version, { manifest, tarball, integrity, audit, actor }): void`
  - `getTarball(name, version): Buffer | undefined`
  - `getAudit(name, version): Audit | undefined`
  - `packument(name): PackumentDoc | undefined` — synthesizes the npm doc from stored
    versions (`name`, `dist-tags.latest`, the `versions` map).
- **`isClaimed(name, policy): boolean`** = `policy.privateNamespaces.some(p => matchPackage(p, name))` (reuses 0012's anchored glob).
- **Publish route `PUT /:pkg`** (new write route — *not* an `Upstream` method).

### 4.2 Policy & config

- `EnterprisePolicy` gains `privateNamespaces: string[]` (default `[]`), validated by
  `parsePolicy` (array of strings; present-but-malformed ⇒ fail closed at boot, per 0014).
- Env: `SENTINEL_PRIVATE_STORE` (store dir), `SENTINEL_PUBLISH_TOKENS`
  (comma-separated valid bearer tokens), `SENTINEL_SHADOW_PROBE` (opt-in, §7). All
  default to inert: no claims / no tokens ⇒ today's pure-passthrough behavior.

### 4.3 Routing (the only branch added)

| Route | Claimed name | Not claimed |
|---|---|---|
| `GET /:pkg` (packument) | published ? synthesize+rewrite tarball URLs+serve : **`404`** | existing public passthrough |
| `GET /:pkg/-/:tgz` (tarball) | published ? score+gate+serve : **`404`** | existing public path |
| `PUT /:pkg` (publish) | auth → parse → audit-gate → store | **`403` "not a private namespace"** |

**Fail-closed guarantee:** for a claimed name the proxy **never** calls the public
upstream — not on a missing package/version, not on error. This is the deliberate,
scoped exception to ADR-0005; everything not claimed still passes through verbatim.

## 5. Publish handler (`PUT /:pkg`)

**Middleware ordering matters** (the global `express.json({limit:"1mb"})` added in
2.1 must NOT apply to publishes — a base64 tarball exceeds 1MB and the global parser
runs *before* the handler, defeating auth-before-work):

1. The global `express.json` parser is **scoped to skip `PUT`** (or the publish path);
   the publish route gets its own chain.
2. **Auth middleware (header-only, before any body parsing):** require
   `Authorization: Bearer <token>` matching a `SENTINEL_PUBLISH_TOKENS` entry. Absent/
   mismatch, or no tokens configured ⇒ **`401`**, before the body is read/parsed (no
   pre-auth parse/DoS surface).
3. **Body parser** scoped to the publish route: `express.json({ limit: "64mb" })`
   (stated max package size; larger ⇒ `413`).
4. **Handler:**
   - Decode the name (`decodeURIComponent`, handles `@scope%2fname`). Not
     `isClaimed` ⇒ **`403` "not a private namespace"** (Sentinel is not a public-publish proxy).
   - Identify the published version from the single `_attachments` key
     (`<name>-<version>.tgz`); take its manifest from `versions[version]`; base64-decode
     `_attachments[...].data` → tarball `Buffer`. (Robust to a merged map: always key
     off `_attachments`.)
   - **Integrity:** `integrityOf(tarball)` must match `versions[version].dist.integrity`
     ⇒ else `400`. Duplicate `(name, version)` already stored ⇒ `409` (immutable).
   - **Audit + policy-gate:** `runAudit({meta, tarball})` → `score(audit, activePolicy)`.
     `verdict === "block"` ⇒ **`403`**, do not store, return the findings.
   - **Store** the policy-independent `Audit` + bytes + manifest via `privateStore.put`.
   - Respond **`201 { ok: true, id, rev }`**.

Express 5 `%2f` footgun: register the `PUT` route with a **regex + `decodeURIComponent`**
(matching the existing tarball/manifest routes), and cover it with a scoped-publish test.

## 6. Serving private packages

- **Packument `GET /:pkg`** (claimed, published): `privateStore.packument(name)` →
  rewrite each `dist.tarball` to a proxy URL (exactly as the public path) so every
  tarball fetch is still intercepted. Unpublished ⇒ `404`.
- **Tarball `GET`** (claimed): get bytes + `Audit` from the store →
  `score(audit, activePolicy)` (re-scored under the **current** policy) → the **0011
  capability/approval gate** → headers identical to public (`x-sentinel-score/verdict/
  findings/capabilities/approval/policy`) **plus `x-sentinel-private: true`** → serve
  or `403`. So a private install is held to the same standard as a public one.

**Publish ↔ approval interaction (explicit):** the two controls are **orthogonal**.
Publishing audits + stores; it does **not** auto-record a 0011 approval. A
just-published private package whose capabilities are unapproved still returns
`403 approval required` on first install under `block` policy (defense in depth — the
installer's approval is a separate control from the publisher's act). Clear via the
existing `sentinel approve`/`preflight` flow.

## 7. Collision telemetry (ADR-0010 action item 4)

- **Default (privacy-preserving):** log local structured events only — claimed
  publishes and first claimed serves — with **no public-npm calls**. Because claimed
  names never hit the public upstream, the default path leaks nothing about the
  private namespace.
- **Opt-in public-shadow probe (`SENTINEL_SHADOW_PROBE=1`):** best-effort, non-blocking
  check whether a claimed name also exists on public npm; logs a `shadow` warning if
  so. **Off by default** because probing sends claimed names (`@acme/payments`) to
  registry.npmjs.org — a privacy regression for a product protecting that namespace.
  The tradeoff is documented; failures are swallowed and never affect resolution;
  disabled for the hermetic `LocalFixtureUpstream`.
- A small `GET /-/private` status endpoint surfaces claims, published packages, and
  recent telemetry for the dashboard/agent.

## 8. Scope fence (full-hosting CORE only)

**Deferred** (so the plan doesn't balloon): unpublish/deprecate (`DELETE`,
`npm unpublish`); dist-tags beyond `latest` (`npm dist-tag add`); `npm view`/search
niceties; storage GC / durability / replication; concurrent-publish locking
(immutable `(name,version)` + `409` on duplicate; last-write-loses; no transactions);
publish access levels (`access` field ignored); multi-user roles (single shared token
set). **MVP = `PUT` publish + authoritative packument/tarball `GET` + fail-closed
claim routing + audit-gate + token auth + best-effort local telemetry.**

## 9. Invariants & determinism
- Public passthrough is unchanged for non-claimed names (ADR-0005 holds outside
  claims). The claimed-name fail-closed override is the documented exception.
- Scoring stays deterministic-given-a-policy (private packages scored by the same
  `score`). The malicious public fixture stays blocked (public path untouched).
- `privateNamespaces` is part of the signed, versioned policy; a tampered claim or
  malformed policy fails closed at boot (0014).

## 10. Testing
(Heeding prior test-infra lessons: per-test temp `SENTINEL_PRIVATE_STORE` dirs — never
the fixtures tree; close every `app.listen` in `after`.)
- **Captured-payload fixture:** the real `PUT` body (normal + scoped) saved as a
  fixture. **Unit:** payload parse + `_attachments` base64 decode (normal + scoped
  `%2f`); integrity check; duplicate `409`; audit-gate rejects a `block` publish;
  `isClaimed` glob routing; `PrivatePackageStore` put/get/packument-synthesis;
  **fail-closed (claimed+unpublished → 404, public upstream never called)**;
  publisher-auth `401` (absent/wrong token, no tokens configured); `parsePolicy`
  accepts/validates `privateNamespaces`.
- **One real `npm publish` e2e:** publish a claimed package with a token → packument +
  tarball resolve privately (`x-sentinel-private: true`); a non-claimed name still
  passes through to fixtures; unauthenticated publish → `401`; a `block`-auditing
  publish → rejected; publish to a non-claimed name → `403`.
- Regression: malicious public fixture still blocked; existing suites green.

## 11. Docs
- ADR-0010 → **Accepted**.
- New **ADR-0015** recording: the captured publish protocol (single-version PUT,
  `404`-then-PUT), auth-before-parse + body-limit, claim-defines-namespace fail-closed,
  publish↔approval orthogonality, shadow-probe-off-by-default.
- ARCHITECTURE.md: a private-namespace section + the transparency-boundary exception.
  CLAUDE.md: test count + a note that claimed names are authoritative (not passthrough).

## 12. Out of scope (recap)
Everything in §8; plus per-request multi-tenant routing, federation to an external
internal registry (a forward-compatible alternative backing for `PrivatePackageStore`
via the same read interface), and key rotation for publish tokens.
