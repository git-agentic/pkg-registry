# Phase 12 — Control-Plane Authentication & Authorization (signed role tokens on gate-mutating endpoints)

**Date:** 2026-07-07
**Status:** Approved design, pre-implementation
**Extends:** ADR-0014 (Ed25519 signing machinery — reused for tokens), ADR-0013
(approval gate fail-closed — this makes the boundary enforceable), ADR-0024
(agent-native MCP surface — named authenticating the hop as the follow-on),
ADR-0015 (private-registry publish — publish auth unified), ADR-0005 (proxy
transparency — reads stay open). Supersedes nothing.

## Problem

Sentinel's control plane is unauthenticated. Only the publish `PUT` path has auth
(a bearer-token list); every gate-*mutating* endpoint — `POST /-/approvals` (grant),
`DELETE /-/approvals/:integrity` (revoke), `DELETE /-/violations/:integrity` (clear a
quarantine), `POST /-/violations` (report), `POST /-/approval-requests` — is open to
anyone who can reach the proxy. A network-adjacent attacker or a compromised agent can
approve a blocked package, clear a quarantine, or spoof a violation.

Phase 11 sharpened this into a concrete, now-visible gap: the MCP privilege boundary
("an agent may *request* but not *grant*") is **honor-system only** — anyone can
`POST /-/approvals` directly and grant. The boundary is unenforceable at the HTTP
layer. Phase 12 makes it real: signed role tokens authorize the mutating endpoints, so
an `agent` token literally cannot call the grant endpoint.

## Decisions (brainstorm outcomes)

1. **Signed stateless tokens**, not opaque-in-store and not HMAC. A bearer token =
   `base64url(payload).base64url(Ed25519-sig)` verified offline against a configured
   operator public key; no server-side token store. Reuses the exact `edSign`/`edVerify`
   machinery from ADR-0014 policy signing (already in `core/src/policy.ts`, exported).
   Rejected: opaque-in-store (adds mutable server state; diverges from the
   signed-artifact pattern) and HMAC (a shared secret means anyone who can verify can
   also mint — collapses the operator/agent separation this phase exists to create).
2. **Three roles: `operator` / `agent` / `publisher`**, mapped 1:1 to the real callers.
   `operator` = grant/deny/revoke approvals + clear quarantine; `agent` = request
   approval + report violation; `publisher` = publish. This is exactly Phase 11's
   boundary at the HTTP layer. Rejected: operator/agent-only (conflates publish with
   approval-granting — a publish credential could approve arbitrary packages) and
   per-endpoint scopes (YAGNI until a caller needs a non-standard slice).
3. **Opt-in via config** (`SENTINEL_AUTH_PUBKEY`): unset ⇒ today's open mode
   (all existing tests + demo unchanged); set ⇒ mutations require a valid role token.
   Mirrors the signed-policy pattern (ADR-0014: no policy file ⇒ default open).
4. **Reads stay open always** — tarball/packument is npm-facing (ADR-0005 transparency);
   npm clients don't carry Sentinel tokens. Only control-plane *mutations* are gated.

## Section 1 — Architecture & data flow

- **New core module `packages/core/src/auth.ts`** — pure token mint + verify on
  `edSign`/`edVerify`. Exported from core so cli (mint) and proxy (verify) share it.
- **New proxy middleware `packages/proxy/src/authz.ts`** — `requireRole(roles: Role[])`
  Express middleware. Auth enabled (a pubkey configured): parse
  `Authorization: Bearer <token>`, verify against the pubkey, enforce expiry, check the
  token's role ∈ the allowed set → else **401** (missing / malformed / bad-signature /
  expired) or **403** (valid token, wrong role). Auth disabled: pass-through.
- **Role → endpoint map** (the whole point of the phase):
  - `operator` → `POST /-/approvals`, `DELETE /-/approvals/:integrity`,
    `DELETE /-/violations/:integrity`
  - `agent` → `POST /-/approval-requests`, `POST /-/violations`
  - `publisher` → `PUT /:pkg`
  - all `GET` + tarball + packument → **open**
- When auth is enabled, publish moves to the `publisher` role (the legacy
  `SENTINEL_PUBLISH_TOKENS` list remains the mechanism only in open mode).

The proxy resolves auth config once at startup (like the signed policy): read
`SENTINEL_AUTH_PUBKEY` (a PEM path); if present, `authEnabled = true` and the pubkey is
held for `requireRole`. `ServerOptions` gains an optional `authPublicKey?: string`
(PEM); when absent, open mode.

## Section 2 — Token format, signing, verification

Minimal, zero-dep, mirrors policy signing:

```
token   = base64url(payloadJson) "." base64url(ed25519Sig)
payload = { role: "operator"|"agent"|"publisher", sub: string, iat: number, exp: number }  // unix seconds
sig     = edSign(payloadSegmentBytes, privateKeyPem)   // Ed25519, algorithm null
```

- `signToken(input: { role: Role; sub: string; ttlSeconds: number }, privateKeyPem: string, now?: number): string`
  — builds `{ role, sub, iat: now, exp: now + ttlSeconds }`, signs the payload segment,
  returns `payloadB64url.sigB64url`.
- `verifyToken(token: string, publicKeyPem: string, now?: number): { ok: true; role: Role; sub: string; exp: number } | { ok: false; reason: "malformed" | "bad-signature" | "expired" | "bad-role" }`
  — splits on `.` (exactly two segments, else `malformed`); verifies the signature over
  the payload segment (`bad-signature` on failure); parses JSON (`malformed` on failure);
  validates `role` (`bad-role`); checks `now < exp` (`expired`). Expiry **is** enforced
  (request-time auth is clock-dependent by nature; `now` is an explicit input for test
  determinism — this is not scoring, so invariant #1 does not apply).
- `type Role = "operator" | "agent" | "publisher"`.

All crypto is `node:crypto` Ed25519 (`edSign`/`edVerify` already imported by `policy.ts`);
no new dependency. `base64url` is `Buffer.toString("base64url")` / `Buffer.from(s, "base64url")`.

**CLI `sentinel token`** (mirrors `sentinel policy keygen/sign/verify`):
- `sentinel token keygen --out auth` → writes `auth.key` (PKCS8 PEM private) + `auth.pub`
  (SPKI PEM public), reusing `generateKeypair()`.
- `sentinel token mint --role <role> --sub <id> --ttl <seconds> --key auth.key` → prints
  the token.
- `sentinel token verify <token> --pubkey auth.pub` → prints decoded `role`/`sub`/`exp`
  or the rejection reason (operator debugging aid).

## Section 3 — Endpoint enforcement + client updates

- **Enforcement:** each mapped route gains `requireRole([...])` before its handler.
  `POST /-/approvals`, `DELETE /-/approvals/:integrity`, `DELETE /-/violations/:integrity`
  → `["operator"]`; `POST /-/approval-requests`, `POST /-/violations` → `["agent"]`;
  `PUT /:pkg` → `["publisher"]` when auth is enabled (else the legacy `requirePublishAuth`).
  An `agent` token on `POST /-/approvals` → **403** (Phase 11's boundary enforced).
- **MCP `ProxyClient`:** reads `SENTINEL_AUTH_TOKEN` and attaches
  `Authorization: Bearer <token>` to its POST calls (`approvalRequest`). If auth is on and
  the token is missing/wrong-role, the proxy 401/403s and the tool surfaces it explicitly
  (fail-closed — never a fabricated success, invariant #6). The MCP host is configured with
  an `agent`-role token.
- **`sentinel-script-shell`:** the violation-report POST attaches the same
  `SENTINEL_AUTH_TOKEN` (agent role), set in the enforce env beside `SENTINEL_PROXY`. Best-
  effort reporting still never changes the install exit code — an auth failure is swallowed
  like any other report failure (ADR-0023 best-effort).
- **Dashboard:** a small "operator token" field in the header, stored in `localStorage`;
  the Approve/Deny and clear-quarantine fetches attach it as the `Authorization` header.
  When auth is disabled the field is unused. Honest MVP — the operator pastes a minted
  `operator` token once. All interpolation stays `esc()`'d (no token is ever rendered back).

## Section 4 — Testing, backward compat, DoD

*Backward compatibility (load-bearing):* auth is off unless `SENTINEL_AUTH_PUBKEY` is
configured, so every existing test and the demo run unchanged — `requireRole` is a
pass-through with no key. No edits to the ~300 existing tests.

*Testing (hermetic):*
- **Core `auth.test.ts`** (pure): in-test Ed25519 keypair; `signToken`/`verifyToken`
  round-trip per role; tampered payload → `bad-signature`; expired (via `now`) →
  `expired`; wrong-key → `bad-signature`; garbage → `malformed`; unknown role → `bad-role`.
- **Proxy `authz-e2e.test.ts`**: boot an in-process proxy **with** a configured pubkey;
  assert the role matrix — no token → 401; `operator` → `POST /-/approvals` 200; **`agent`
  → `POST /-/approvals` 403**; `agent` → `POST /-/approval-requests` 200 and
  `POST /-/violations` 200; `publisher` → publish 200; expired `operator` → 401;
  `GET /-/audit` with no token → 200 (reads open). Plus an **open-mode** test: no pubkey →
  mutations succeed without a token (backward-compat proof).
- **CLI `token.test.ts`**: `keygen` → `mint` → `verify` round-trip; `verify` of an
  expired/tampered token prints the rejection.
- **MCP**: `request_approval` attaches `SENTINEL_AUTH_TOKEN`; against an auth-enabled proxy
  with an agent token it records the request; with no token it surfaces the 401 as a tool
  error (not a fabricated success).

*Definition of done:* `npm run build` clean; `npm test` green (existing suite unchanged by
the open-mode default + new auth suites; new count recorded in CLAUDE.md, darwin-skip
caveats preserved); the malicious fixture still blocks; ADR-0025 recorded; ARCHITECTURE
(a control-plane-auth section + the role→endpoint table; §5 store/security posture if
present), CLAUDE (phase summary + count), README (the `sentinel token` workflow,
`SENTINEL_AUTH_PUBKEY` / `SENTINEL_AUTH_TOKEN` env vars, the role→endpoint table) updated.

## Out of scope (deferred beyond Phase 12)

- Token revocation lists / instant revocation (stateless tokens revoke via short expiry +
  key rotation; a revocation store is deferred until a caller needs it).
- Multi-key / key-rotation-with-overlap verification (single configured pubkey this phase).
- Per-endpoint fine-grained scopes (roles suffice; scopes are the YAGNI escalation).
- Authenticating the READ endpoints or the tarball path (reads stay open — ADR-0005).
- mTLS / transport-layer auth (bearer tokens over the operator's existing transport).
- A session/login flow for the dashboard (the paste-a-token MVP; a real console-login is
  a productization follow-on).
- Rate limiting / anti-DoS on the auth failure path (orthogonal; deferred).

## Invariants preserved

1. **Deterministic score** — auth is request-time access control; it does no scoring and
   never touches a verdict. The determinism test is unaffected.
2. **LLM never scores** — untouched.
3. **Sync gate cheap** — `verifyToken` is one Ed25519 verify over a small payload, only on
   the (rare) mutation path; reads and the tarball gate are untouched.
4. **Cache key = integrity** — unchanged; auth gates mutations, not the integrity-keyed
   stores' shape.
5. **Proxy transparency** — reads, packument passthrough, and the npm-facing tarball path
   stay open and unauthenticated (ADR-0005).
6. **Fail-open rules / never crash** — a malformed token yields a clean 401, never a crash;
   the MCP/script-shell clients fail explicitly (or swallow, for best-effort reporting),
   never fabricating success.
7. **Private namespaces authoritative** — unchanged; publish gains a `publisher` role gate
   when auth is enabled.
8. **Approval gate fail-closed (ADR-0013)** — now *enforced* at the HTTP layer: only an
   `operator` token can grant; an `agent` token is refused. Phase 11's boundary is real.
