# ADR-0036: Network trust boundary — tarball origin pinning + configured public base URL

Date: 2026-07-09
Status: Accepted

## Context

An external security audit surfaced two ways the proxy trusts a value an
attacker can influence at its network boundary:

1. **Outbound (SSRF).** `NpmUpstream.getTarball` fetched whatever URL the
   packument's `dist.tarball` claimed. A poisoned packument — or a
   compromised/custom upstream registry — could make the proxy request
   internal services or cloud metadata endpoints from the proxy host.
2. **Inbound (Host-header trust).** The packument rewrite built tarball URLs
   from `req.protocol` + `req.get("host")`. Behind a reverse proxy, or
   reachable by a client with a spoofed Host, the rewritten `dist.tarball`
   could point npm at an attacker-controlled origin.

The design target is a network-deployed enterprise proxy, so both get
first-class fixes, not documentation.

## Decision

**Outbound: deterministic origin pinning, enforced before any request.**
A tarball URL is fetched only if its protocol is http(s) AND its origin is
the configured registry origin (`SENTINEL_REGISTRY`, default
`https://registry.npmjs.org`) or appears in the optional
`SENTINEL_TARBALL_ORIGINS` allowlist (comma-separated bare origins, for
mirror/CDN-backed private registries). Anything else ⇒ `HttpError(502)` and
the request is **never issued** — there is no DNS or IP surface to reason
about. Parsing is fail-closed at startup: a set-but-invalid allowlist is
FATAL (parity with `SENTINEL_AUTH_PUBKEY`).

**Inbound: `SENTINEL_PUBLIC_BASE_URL`.** When set (validated at startup,
malformed ⇒ FATAL), all packument `dist.tarball` rewrites use it and the
request's Host is ignored. When unset, the base is derived from the request
only for a loopback Host (`localhost`, `127.0.0.0/8`, `[::1]`) — the
zero-config dev case; a non-loopback Host is refused with **421** and an
actionable error. A network deployment cannot silently run in the spoofable
mode.

All parsing/validation lives in a pure module
(`packages/proxy/src/net-config.ts`); enforcement lives at the two boundary
sites (`upstream.ts`, `server.ts`).

## Alternatives considered

- **DNS-resolution / private-IP-range filtering** (the audit's suggested
  direction): rejected — non-deterministic, DNS-rebinding-prone, and
  needless once no packument-controlled origin is ever fetched at all.
- **Always requiring `SENTINEL_PUBLIC_BASE_URL`**: rejected — breaks
  zero-config `npm install --registry http://localhost:4873` local dev for
  no security gain (loopback Host is not attacker-controlled in that
  scenario).
- **Trusting `X-Forwarded-*` headers**: rejected — spoofable without a
  trusted-proxy configuration; may be revisited alongside rate limiting
  (ADR-0037).

## Consequences

- A poisoned packument can no longer steer the proxy's outbound fetches;
  scoring and caching are untouched (invariants #1–#4), and the packument
  passthrough still rewrites only `dist.tarball` (invariant #5).
- Deployments serving non-loopback clients must set
  `SENTINEL_PUBLIC_BASE_URL` (breaking for anyone who relied on
  Host-derived URLs over the network — that reliance was the vulnerability).
- Custom registries that serve tarballs from a different origin than their
  packument API need `SENTINEL_TARBALL_ORIGINS`.
