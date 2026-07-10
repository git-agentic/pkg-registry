# Security hardening phases 23–25 — design

**Date:** 2026-07-09
**Status:** Approved for planning
**Source:** External security audit (GPT-5.5), six findings — all six verified
against source before this design was written.

## Context

An external source audit of Sentinel surfaced six findings. Its own summary is
accurate: the deterministic-scoring / signed-policy / authz / quarantine core is
strong, and the gaps sit at the **operational boundary** — outbound fetch trust,
inbound host trust, sandbox filesystem breadth, and resource limits.

The design target is a **network-deployed enterprise proxy** (the product's
stated audience), not just a localhost dev tool: the network-boundary findings
get first-class fixes, not documentation.

Findings → phases:

| # | Finding | Location (verified) | Phase |
|---|---------|---------------------|-------|
| 1 | Sandbox allow-default only denies a fixed sensitive-path list | `sandbox/src/profile.ts:14`, `sandbox/src/bwrap.ts:21` | 25 |
| 2 | `dist.tarball` fetched with no origin check (SSRF) | `proxy/src/upstream.ts:101` | 23 |
| 3 | Packument rewrite trusts inbound `Host` header | `proxy/src/server.ts:613` | 23 |
| 4 | Descendant approval lifts an entire ancestor `subpath` deny | `sandbox/src/path-cover.ts:13–19` (acknowledged in a code NOTE) | 25 |
| 5 | `/-/audit-tree` unbounded fan-out; tarballs fully buffered, no size cap | `proxy/src/server.ts:365`, `upstream.ts:101`, `core/src/extract.ts` | 24 |
| 6 | Cache stampede — cache checked only after fetch+hash | `proxy/src/server.ts:147–152` | 24 |

Each phase is one brainstorm→plan→SDD→merge cycle with its own ADR, per the
established cadence. Order: 23 → 24 → 25 (small correlated changes ship first;
the risky sandbox rework is isolated last).

---

## Phase 23 — Trust boundary (ADR-0036)

Fixes the two places the proxy trusts a value an attacker can influence.

### Outbound: tarball origin pinning (SSRF)

`NpmUpstream.getTarball` currently `fetch()`es whatever URL the packument's
`dist.tarball` claims. A poisoned packument (or compromised custom upstream)
can point the proxy at internal services or cloud metadata.

**Fix — deterministic origin pinning, no IP/DNS filtering.** A tarball URL is
fetched only if:

- its protocol is `http:` or `https:`, **and**
- its origin is the configured registry origin (`https://registry.npmjs.org`
  by default), **or** appears in the optional `SENTINEL_TARBALL_ORIGINS`
  allowlist.

Anything else ⇒ a 502-class `HttpError` naming the offending URL; the request
is **never issued**, so there is no DNS-rebinding or private-IP surface to
reason about. Real npm serves tarballs from the registry origin itself, so the
default posture breaks nothing; for a custom registry the operator-configured
origin is the trust anchor.

`SENTINEL_TARBALL_ORIGINS` is a comma-separated list of extra allowed origins
(e.g. `https://cdn.artifactory.corp`) for mirror/CDN-backed private registries.
Parsed once at startup, fail-closed: each entry must be a valid `http(s)`
origin with no path, malformed ⇒ FATAL (same posture as `SENTINEL_AUTH_PUBKEY`).
Unset ⇒ same-origin-only.

The attestations fetch already builds its URL from the registry origin — no
change needed there.

### Inbound: public base URL (Host-header trust)

The packument rewrite builds tarball URLs from `req.protocol` +
`req.get("host")` (`server.ts:613`). Behind a reverse proxy, or with an
attacker-controlled `Host`, the rewritten `dist.tarball` can point npm at an
attacker origin.

**Fix — `SENTINEL_PUBLIC_BASE_URL`.**

- Set ⇒ all packument `dist.tarball` rewrites use it; the request's `Host` is
  ignored entirely. Validated at startup, malformed ⇒ FATAL.
- Unset ⇒ derive from the request **only when `Host` is loopback**
  (`localhost`, `127.0.0.1`, `[::1]`, any port) — the safe zero-config dev
  case. A non-loopback `Host` with no configured base URL ⇒ **421** with an
  actionable "set SENTINEL_PUBLIC_BASE_URL" error. A network deployment cannot
  silently run in the spoofable mode.

### Tests (hermetic)

- Fixture upstream whose packument points `dist.tarball` at an attacker origin
  ⇒ audit fails with the origin error, and no request is issued (no listener
  exists at the evil origin, so success proves non-fetch).
- `SENTINEL_TARBALL_ORIGINS` admits a listed origin; malformed entry ⇒ FATAL.
- Packument request with spoofed `Host`: base-URL-set mode uses the configured
  URL; unset + non-loopback ⇒ 421; unset + loopback works unchanged.

### Invariants

No scoring change. Transparency (#5) preserved — still rewriting only
`dist.tarball`. Static-input rule (#3) strengthened: outbound destinations are
now startup-configured, never request-derived.

---

## Phase 24 — Resource robustness (ADR-0037)

Fixes the ways an open endpoint can be made to do unbounded expensive work.

### Audit-tree caps + dedupe

`POST /-/audit-tree` accepts as many coordinates as fit in 1 MB and fans out
8-wide; each uncached audit may fetch a packument, two tarballs, and
attestations.

- **Dedupe** coordinates by `name@version` before fan-out; results re-join to
  rows afterward (the audit is deterministic, so this is behavior-neutral).
- **Cap** coordinate count at `SENTINEL_MAX_TREE_PACKAGES` (default **5000**,
  above real-world monorepo lockfiles at ~3–4k). Exceeded ⇒ **413** stating the
  count and the limit. `mapPool(8)` concurrency unchanged.

### Tarball size limit

`getTarball` buffers `res.arrayBuffer()` unbounded. New
`SENTINEL_MAX_TARBALL_BYTES` (default **256 MB**):

- reject early when a declared `content-length` exceeds the cap;
- content-length can lie or be absent, so also stream the body counting bytes
  and abort past the cap.

Over-limit ⇒ `HttpError`: an `error` row in a tree audit (ADR-0020's fail-open
aggregation unchanged) and a 502-class error on the gate path — never an OOM.

### Request coalescing (stampede)

`auditVersion` checks the integrity cache only after fetching + hashing the
tarball, so concurrent uncached requests all run the full pipeline.

**Fix:** an in-flight `Map<string, Promise<{report, tarball}>>` keyed
`name@version` inside `createServer`, wrapping the uncached path. Concurrent
requests share one pipeline; the entry is removed on settle, and a rejection is
never cached (next request retries). The integrity-keyed immutable cache
(invariant #4) remains the durable cache; the map is transient dedupe only.

### Rate limiting (opt-in)

A small token-bucket middleware in `@sentinel/proxy`:

- **Keyed by the socket remote address** — not `X-Forwarded-For`, which is
  spoofable; an XFF-trusting mode behind a known LB can come later.
- **Injectable clock** for deterministic tests; no wall-clock near scoring.
- Applied to the expensive endpoints only: `POST /-/audit-tree`,
  `GET /-/explain/*`, `POST /-/policy/preview`.
- Opt-in: `SENTINEL_RATE_LIMIT_RPM=<n>`. Unset ⇒ off (zero behavior change);
  malformed ⇒ FATAL. Over-limit ⇒ **429** with `Retry-After`.
- The install-gate paths (packument/tarball) are **never** rate-limited:
  coalescing + the integrity cache already make them cheap, and throttling
  installs would break the transparent-proxy promise.

### Tests (hermetic)

- N duplicate coordinates ⇒ 1 upstream fetch (instrumented fixture upstream),
  N rows.
- Over-cap tree ⇒ 413.
- Oversized tarball via fixture upstream ⇒ error row / 502, no crash.
- k parallel requests for one uncached version ⇒ 1 `getTarball` call; a
  rejected in-flight audit is retried by the next request.
- Rate limit: n+1th request within the window ⇒ 429 (injected clock); unset
  env ⇒ unlimited.

### Invariants

Reads-stay-open (ADR-0025) unchanged — rate limiting is opt-in throttling, not
auth. ADR-0037 will note that shared deployments should additionally front the
proxy with ordinary infra rate limiting.

---

## Phase 25 — Sandbox default-deny + directional path-cover (ADR-0038)

**Supersedes the allow-default + targeted-deny stance** of ADR-0016
(Seatbelt runner), ADR-0017 (write confinement), and ADR-0018 (cross-platform
backends). Today `(allow default)` / `--bind / /` plus a fixed
`SENSITIVE_PATHS` deny list means install scripts can read/write anything not
on the list — which conflicts with the "approved capability manifest" model.

> **Refined by a grilling session (2026-07-09).** The subsections below
> supersede the original one-paragraph sketch; they close the open questions
> that sketch left — most importantly the node-runtime-under-`$HOME` wrinkle,
> the read/write risk asymmetry, and the cross-backend telemetry gap. Domain
> vocabulary sharpened here (Install directory vs Project root, Grant, Carve-out)
> is captured in the root `CONTEXT.md`.

### Sequencing — two ordered slices, one phase / one ADR

Writes and reads are inverted as **two separately-landed slices** under a single
ADR-0038, because their risk profiles differ sharply:

- **Slice 1 — write-deny-by-default.** Low probe-risk (node barely writes
  outside its own dirs), high value (kills persistence/tamper). Lands first,
  fully probed and green.
- **Slice 2 — `$HOME`-read-deny-by-default.** High probe-risk (node/npm read
  config + caches scattered across `$HOME`), high value (kills credential theft
  beyond the enumerated list). Lands second, gated on its own probes.

A nasty read-probe surprise cannot sink the safe write-deny win: worst case,
slice 1 ships and slice 2 becomes a follow-up.

### Slice 1 — writes: deny by default

- **Fixed write-allow floor (not operator-configurable — a widenable floor is a
  footgun that silently reopens the persistence class):** the Install directory
  (`cwd`) subtree, the OS temp dir, `~/.node-gyp` + `~/.cache/node-gyp` (native
  build header cache), and `~/.npm/_logs`. Everything else denied.
- **Approvals extend the floor per-package** — no new config knob; an approved
  `filesystem:<path>` becomes a positive write Grant.
- `SENSITIVE_PATHS` write entries (shell rc, LaunchAgents, systemd units) now
  fall under the blanket write-deny — redundant for *enforcement*, retained for
  *attribution* + `secret-exfil` detection.

### Slice 2 — reads: full `$HOME`-read-deny + allow-list

Chosen over a merely-expanded deny-list because only default-deny actually
closes the audit finding (a bigger fixed list still leaks a novel credential
path). The allow-list must handle the wrinkle the original sketch missed —
**the node runtime often lives under `$HOME`** (nvm `~/.nvm/...`, fnm, volta,
asdf), so a blanket `$HOME`-read-deny would stop node loading its own stdlib.

Read-allow:

- **system roots** — `/usr`, `/lib`, `/System`, `/Library`, `/opt`, `/etc`,
  `/bin`, `/sbin`;
- **the node install prefix**, derived from `process.execPath` at
  sandbox-build time (a **new sandbox input**) — so node-under-`$HOME` works;
- **the Project root** subtree (a **new sandbox input**, distinct from the
  Install directory `cwd` — the script's `require()` resolves against the whole
  project tree, not just its own dir);
- `~/.node-gyp` + `~/.cache` (header/build caches are *read* too).

Deny the rest of `$HOME` — SSH, cloud creds, browser profiles, wallets,
keychains.

### Approvals as Grants + directional coverage

- An approved `filesystem:<path>` emits an explicit SBPL allow / `bwrap` bind
  for that subtree (a positive **Grant**), instead of "skip a matching deny".
- **Directional `pathCovers`:** a Grant covers targets **at or below** the
  approved path (ancestor-or-equal, one direction only). A descendant approval
  grants *exactly* its own subtree and never widens up to an ancestor — the
  `.ssh/config`-cancels-`~/.ssh` example in the `path-cover.ts` NOTE stops being
  true. (`computeDenySet` consumes `pathCovers`, so Phase 10's non-drift test
  moves in lockstep.)

### `SENSITIVE_PATHS` — data unchanged, two roles

The table stays exactly as-is; under default-deny it plays two roles:

1. **Required Carve-out enforcement** for entries inside a read-allowed region —
   `/etc/passwd`, `/etc/shadow` sit in the read-allowed `/etc`, so home-read-deny
   does *not* cover them. The profile read-allows `/etc` broadly, then punches an
   explicit deny back (SBPL last-match-wins; bwrap `--ro-bind /dev/null`). These
   are **not** redundant — miss them and `/etc/passwd` is readable again.
2. **Defense-in-depth + attribution** for the `$HOME` entries, now also covered
   by the blanket deny, retained because they still drive Phase 10 attribution
   (`computeDenySet` names *which* path) and the `secret-exfil` `detectRe`.

### Platform mechanics

- **Seatbelt:** keep `(allow default)` for non-file ops; add `(deny file-write*)`
  with subpath allows for the write floor, and `(deny file-read* (subpath $HOME))`
  with subpath allows for the read allow-list + Carve-out denies for the in-`/etc`
  sensitive files.
- **bwrap:** replace `--bind / /` with `--ro-bind` for system dirs, `--bind`
  (rw) for the write floor, and a `--tmpfs` mask over `$HOME` with the read
  allow-list re-bound inside it.

### Backend telemetry asymmetry (accepted)

The two backends enforce read-deny with different primitives, producing a
sensor-layer gap: **Seatbelt** yields **EPERM** (path present, read denied) →
Phase 10 `classifyViolation` reports a **confirmed** credential-read violation;
**bwrap** masks via tmpfs → **ENOENT** (path absent) → `classifyViolation`
returns `null`, so the attempt is **contained but not reported**. bwrap has no
present-but-unreadable primitive without owning the paths as another uid
(privilege we deliberately lack). **Accepted and documented as a direct
extension of ADR-0023's containment-≥-telemetry principle** — both backends
*contain*; only the telemetry differs.

### Probe strategy

- **Probe gate before the SDD locks.** Must pass: a real `node-gyp` native
  build (proves the write floor + header/node-prefix reads are complete), a
  benign multi-package `postinstall` that `require()`s across `node_modules`
  (proves the Project-root read Grant). Must deny: a credential read + a
  persistence write. If the gyp/require probes can't go green without unsafely
  widening the allow-list, that is the trigger to demote slice 2 to a follow-up.
- **Exploratory (throwaway, dev machines, off-CI):** run the inverted profile
  across nvm/fnm/volta/asdf/homebrew/system node layouts to discover the real
  allow-list — the CI runners only have system/homebrew node.
- **Committed effect-tests (CI):** a benign build-probe package (builds still
  work), credential-read-denied + persistence-write-denied assertions
  (containment), and a **pure generator test** for the `execPath`-derived
  node-prefix logic (fake node path under a temp "home" → assert the emitted
  profile read-allows it — verifies node-under-`$HOME` hermetically, no real
  nvm needed).

### Unchanged contracts

Profile/argv generation stays pure (same inputs ⇒ same output);
`computeDenySet`/`classifyViolation` (Phase 10) update to the new deny semantics
without drift (the non-drift test carries over); synthetic malware fixtures are
never executed; enforcement is tested with benign probes only; fail-closed
selection in `createSandbox()` unchanged. The definition-of-done "malicious
fixture still blocked" extends to "a credential read is denied under the new
default-deny."

---

## ADR / documentation impact

- **ADR-0036** — outbound tarball origin pinning + `SENTINEL_PUBLIC_BASE_URL`
  (rejected alternative: DNS-resolution/private-IP filtering — non-deterministic,
  rebinding-prone).
- **ADR-0037** — tree caps, tarball byte cap, request coalescing, opt-in rate
  limiting (rejected alternative: auth on reads — contradicts ADR-0025).
- **ADR-0038** — sandbox default-deny; **supersedes** the allow-default stance
  of ADR-0016/0017/0018 (never edits them — supersede, per the repo rule).
  Includes the directional path-cover decision.
- `ARCHITECTURE.md`, `CLAUDE.md` phase paragraphs, and `README.md` env-var
  table (`SENTINEL_PUBLIC_BASE_URL`, `SENTINEL_TARBALL_ORIGINS`,
  `SENTINEL_MAX_TREE_PACKAGES`, `SENTINEL_MAX_TARBALL_BYTES`,
  `SENTINEL_RATE_LIMIT_RPM`) updated per phase, as usual.

## Explicitly out of scope

- Auth or rate limits on cheap read endpoints (`/-/metrics`, `/-/history`, …).
- XFF-aware rate-limit keying (needs a trusted-proxy config; later if asked).
- Full read-deny of system paths in the sandbox (breaks dyld/node startup).
- Disk-spooled tarball processing (the byte cap bounds memory; streaming
  extraction is a separate perf project).
