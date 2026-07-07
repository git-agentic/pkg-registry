# ADR-0025: Control-plane auth — signed role tokens (operator/agent/publisher)

**Status:** Accepted (Phase 12)
**Date:** 2026-07-07

## Context

Every mutating endpoint on the proxy's control plane has been unauthenticated
since it was introduced: `POST /-/approvals` and `DELETE /-/approvals/:integrity`
(ADR-0011/0013), `POST /-/violations` and `DELETE /-/violations/:integrity`
(ADR-0023), and — as of Phase 11 — `POST /-/approval-requests` (ADR-0024).
ADR-0024 was explicit that this was deliberately narrower risk than it looked,
because the one write path it added could only *request*, never grant — but it
also named the gap plainly: "there is still no per-tenant identity model to
authenticate against anywhere in the proxy," and called out authenticating the
MCP↔proxy hop as "the follow-on with the broader API-auth phase." Phase 11's
central privilege boundary — *the agent can request, only a human can grant* —
was therefore enforced by ADR-0024's Decision text and the shape of the tool
surface (no `sentinel_approve` tool exists), but nothing stopped a caller from
skipping the MCP layer entirely and hitting `POST /-/approvals` directly with
any HTTP client. The boundary was real in the API design; it was honor-system
at the transport.

Phase 12 closes that gap: every caller of a gate-mutating endpoint now proves
*which kind of caller it is* before the proxy acts on the request.

## Decision

- **Signed, stateless Ed25519 role tokens, reusing ADR-0014's machinery.**
  ADR-0014 already established Ed25519-signed, offline-verifiable artifacts
  (the enterprise policy) as this codebase's pattern for authenticated
  configuration with no server-side state. `packages/core/src/auth.ts` applies
  the same pattern to short-lived identity: `signToken({ role, sub, ttlSeconds
  }, privateKeyPem)` produces `base64url(payload).base64url(sig)`, where
  `payload` is `{ role, sub, iat, exp }` (unix seconds) and `sig` is an Ed25519
  signature over the payload segment. `verifyToken(token, publicKeyPem)` is
  pure and total — it never throws — and checks, in order: **signature**
  (malformed base64/missing segments and a bad signature both fail before
  anything is parsed, so a tampered payload can never reach role/expiry logic)
  → **parse** (payload must be valid JSON and a non-array object) → **role**
  (must be one of the three known roles) → **expiry** (`now >= exp` fails
  closed). A verified token yields `{ ok: true, role, sub, exp }`; anything
  else yields `{ ok: false, reason }` with `reason` one of `malformed |
  bad-signature | bad-role | expired`.
- **Three roles, one per class of control-plane caller:** `operator` (a human
  or their tooling, who can approve/revoke and clear quarantines), `agent`
  (an autonomous caller — MCP tools, `sentinel-script-shell` — who can *ask*
  for approval and report violations, never grant them), and `publisher` (who
  can push a tarball into the private namespace store). The roles map
  directly onto the privilege boundaries ADR-0013 and ADR-0024 already drew in
  prose; Phase 12 is what makes them load-bearing at the HTTP layer instead of
  just in the tool surface's shape.
- **Opt-in via `SENTINEL_AUTH_PUBKEY`.** `makeAuthz(publicKeyPem)`
  (`packages/proxy/src/authz.ts`) returns `{ enabled, requireRole(roles) }`.
  With no configured public key, `enabled` is `false` and `requireRole`
  returns a pass-through middleware — the control plane behaves exactly as it
  always has. `packages/proxy/src/index.ts` reads `SENTINEL_AUTH_PUBKEY` (a
  path to a PEM public key) at startup and fails fast with a clear error if
  the path is set but unreadable, rather than silently falling back to open
  mode. This mirrors the opt-in postures of policy signing (ADR-0014) and
  private namespaces (ADR-0015): the feature exists, but a deployment that
  hasn't configured it sees no change in behavior.
- **`requireRole([...roles])` gates six routes:**

  | Route | Required role |
  |---|---|
  | `POST /-/approvals` | `operator` |
  | `DELETE /-/approvals/:integrity` | `operator` |
  | `DELETE /-/violations/:integrity` | `operator` |
  | `POST /-/approval-requests` | `agent` |
  | `POST /-/violations` | `agent` |
  | `PUT /:pkg` (publish) | `publisher` (when auth enabled; legacy `requirePublishAuth` token otherwise) |

  Every `GET`, tarball fetch, packument fetch, and `POST /-/audit-tree` stays
  **open** regardless of auth mode — Phase 12 authenticates *mutations to the
  gate*, not reads. `POST /-/audit-tree` is a read-shaped fan-out audit (it
  computes an aggregate verdict over already-audited packages), not a gate
  mutation, so it is deliberately excluded from the gated set. This preserves
  ADR-0005's transparent-proxy invariant unchanged: nothing about what a
  reader sees is gated behind identity.
- **`sentinel token` CLI** (`packages/cli/src/index.ts`): `token keygen --out
  <prefix>` writes `<prefix>.pub.pem` / `<prefix>.key.pem` (private key mode
  `0600`), following the existing `policy keygen` naming convention rather
  than inventing a new one; `token mint --role --sub --ttl --key` prints a
  signed token to stdout; `token verify <token> --pubkey` prints
  `role`/`sub`/`exp` or the rejection reason and exits non-zero on failure —
  the same shape as `sentinel verify` for registry signatures.
  `sentinel-mcp`/`ProxyClient` and `sentinel-script-shell` both read
  `SENTINEL_AUTH_TOKEN` and attach it as `Authorization: Bearer <token>` on
  their POST calls (agent role); reads never attach a token. The dashboard
  gained an "operator token" field (persisted to `localStorage`) that attaches
  the same header to its Approve/Deny/Revoke actions.
- **Publish migrates to the `publisher` role only when auth is enabled.**
  `server.ts` picks `authz.requireRole(["publisher"])` when
  `authz.enabled`, and falls back to the pre-existing `requirePublishAuth`
  token check otherwise — an existing deployment that never sets
  `SENTINEL_AUTH_PUBKEY` sees no change to how publish is gated.

## Enforcement of the Phase 11 boundary

ADR-0024's central claim — the agent can request, only a human can grant —
is now a runtime guarantee, not just an absent tool. With auth enabled, an
`agent`-role token presented to `POST /-/approvals` is rejected with `403`
(role mismatch); only an `operator`-role token is accepted. There is still no
`sentinel_approve` MCP tool and no auto-approve path — Phase 12 adds the
enforcement layer underneath a boundary Phase 11 already drew, it does not
change what any tool can ask the proxy to do.

## 401 vs 403

`requireRole` distinguishes two failure modes: **401** — no `Authorization`
header, a header that isn't `Bearer <token>`, or a token that fails
`verifyToken` (bad signature, malformed, expired, unrecognized role) — the
caller has not proven *any* valid identity. **403** — the token verifies fine
(good signature, well-formed, unexpired, a real role) but that role isn't in
the route's allowed set — the caller has proven an identity that is not
permitted here. This distinction matters operationally: 401 tells an operator
"your token is missing or bad," 403 tells them "your token is fine, but this
isn't your job" (e.g., an agent token hitting an operator-only route).

## Expiry is enforced, not just surfaced

Unlike the enterprise-policy expiry field (surfaced in policy metadata but not
independently enforced — see ADR-0014), a role token's `exp` is enforced by
`verifyToken` on every request: `now >= exp` is a token-verification failure,
not a warning. This is **request-time authentication, not scoring** — it has
nothing to do with `runAudit`'s deterministic verdict computation.
Invariant #1 (scoring is deterministic given a policy) is untouched by this
phase; a token never enters the score/policy machinery, and a missing or
expired token affects only whether an HTTP request is allowed to reach a
mutating handler, never what score or verdict any package receives.

## Consequences

- **Backward compatible by construction.** With `SENTINEL_AUTH_PUBKEY` unset,
  `makeAuthz` returns disabled, every `requireRole` middleware is a no-op, and
  the entire existing test suite and every existing deployment behaves
  identically to before this phase. An explicit test locks this in.
- **Stateless — no token store.** Verification is a pure function of the
  token and the configured public key; the proxy holds no session table, no
  revocation list, and no per-token database row. This mirrors the
  signed-artifact pattern of ADR-0014 rather than introducing the mutable,
  stateful session-store pattern this codebase has avoided everywhere else.
- **Revocation is coarse: short expiry plus key rotation.** There is no way
  to invalidate one already-issued token before its `exp` without rotating
  the signing key (which invalidates every token signed by it). Operators
  mint short-TTL tokens for exactly this reason — a compromised token is
  self-limiting.
- **The Phase 11 request-not-grant boundary is now enforced at the transport,
  not just implied by the tool surface.** An agent token can never reach
  `POST /-/approvals`, `DELETE /-/approvals/:integrity`, or `DELETE
  /-/violations/:integrity`, regardless of which client sends the request.

## Deferred

- **Revocation lists** — a compromised-but-unexpired token cannot be
  individually invalidated; only full key rotation revokes everything at
  once.
- **Multi-key rotation with overlap** — `SENTINEL_AUTH_PUBKEY` is a single
  key; there is no accept-old-and-new-key overlap window for zero-downtime
  rotation.
- **Per-endpoint scopes finer than role** — today's unit of authorization is
  the three roles; there's no per-package or per-namespace scoping within a
  role.
- **Authenticating reads or tarball serves** — deliberately out of scope;
  ADR-0005's transparent-proxy posture keeps every read open in every mode.
- **mTLS** — token-based bearer auth only; no client-certificate layer.
- **A real dashboard login flow** — the operator-token field is a
  paste-and-persist `localStorage` value, not a session with its own
  authentication.
- **Rate limiting** on token verification or gated endpoints.

## Rejected

- **Opaque tokens in a server-side store** (issue a random ID, look it up on
  every request) — rejected: this reintroduces exactly the mutable
  server-side state this codebase has deliberately avoided for every other
  trust artifact (policy, provenance, registry signatures are all
  signed-and-verified-offline, never a lookup table), and adds an operational
  dependency (the store) that a stateless signed token doesn't need.
- **HMAC-signed tokens with a shared secret** — rejected: a single shared
  secret that both mints and verifies tokens can't distinguish "this party is
  allowed to mint operator tokens" from "this party can only mint agent
  tokens" — anyone holding the secret can mint any role, collapsing the
  operator/agent/publisher separation that is the entire point of this ADR.
  Asymmetric signing keeps minting (private key) and verification (public
  key) separate, so the proxy can verify tokens without ever holding a secret
  that could mint an operator token.

Extends ADR-0014 (Ed25519-signed offline-verifiable artifacts — the signing
pattern this ADR reuses for identity instead of policy), ADR-0013 (the
approval-gate fail-closed contract — now enforced by role, not just by
endpoint shape), ADR-0024 (the agent-native MCP surface and its
request-not-grant boundary — now enforced at the transport), ADR-0015
(private-namespace publish — publish gains a `publisher` role check when auth
is enabled), and ADR-0005 (transparent-proxy reads-open posture — unchanged;
only gate-mutating routes are gated). Supersedes nothing.
