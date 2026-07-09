# Sentinel — Architecture

> An agent-auditable security layer for the npm ecosystem.
> Phase 1 ships as a **transparent auditing proxy** in front of `registry.npmjs.org`
> (the Socket/Chainguard wedge). Phase 2 adds policy, private-namespace override,
> and an install-time permission manifest.

This document covers the Phase 1 design that is implemented in this repo, and the
Phase 2 design that the data model and proxy are built to accommodate.

> The decisions below are recorded individually, with options and trade-offs, in the
> **[Architecture Decision Records](./docs/adr/)** (`docs/adr/`). Where this document
> says "we chose X," the corresponding ADR says *why* and *what we rejected*.

---

## 1. Design goals & threat model

AI agents (and humans) now `npm install` and **execute** untrusted code with zero
risk signaling. The concrete attack surface we target:

| Threat | Real-world example | How Sentinel addresses it |
|---|---|---|
| Malicious release of a trusted package | `event-stream` → `flatmap-stream` (2018), `ua-parser-js` (2021) | Diff-audit every version; flag obfuscation, egress, secret access in install scripts |
| Install-time code execution | `pre/post-install` exfil scripts | Static detection of lifecycle scripts + dangerous patterns; Phase 2 permission prompt |
| Secret / token exfiltration | `~/.npmrc`, `AWS_SECRET_*`, `.aws/credentials`, env enumeration | `secret-exfil` rule correlates secret reads with network egress |
| Dependency confusion / name-squatting | Alex Birsan 2021 | Phase 2 private-namespace override (private always wins) |
| Unsigned / tampered artifacts | — | Surface signature/provenance status pre-install |

**Non-goals (Phase 1):** we do not replace npm, we do not rewrite tarballs, we do
not sandbox execution. We resolve and serve real packages transparently and attach
a verdict. An agent or human decides what to do with the verdict.

---

## 2. System overview

```
        ┌────────────┐    npm install / npx        ┌──────────────────────────┐
        │  npm / npx │ ───────────────────────────▶│   Sentinel Proxy         │
        │  (client)  │   registry = sentinel        │  (Express)               │
        └────────────┘                              │                          │
              ▲                                      │  1. resolve packument    │
              │  packument + tarball (transparent)   │  2. intercept tarball    │
              │                                      │  3. audit (sync gate /   │
              │                                      │     async enrich)        │
              │                                      │  4. attach verdict header│
              │                                      └───────┬───────────┬──────┘
        ┌─────┴──────┐                                       │           │
        │ Sentinel   │  pre-install verdict (size, author,   │ upstream  │ store
        │ CLI        │  signature, score, findings)          ▼           ▼
        └────────────┘                            registry.npmjs.org   audit DB
                                                  (or local fixtures)   + verdict cache
        ┌────────────┐
        │ Dashboard  │  ◀── reads audit store (recent audits, scores, findings)
        └────────────┘
```

Four packages (npm workspaces monorepo):

- **`@sentinel/core`** — the audit engine. Pure, dependency-light, deterministic.
  Tarball extraction, the rules, scoring, the data model, and the LLM adapter
  interface. No HTTP, no Express — so it is trivially unit-testable and reusable
  (CLI, proxy, CI all import it).
- **`@sentinel/proxy`** — Express server implementing the npm registry HTTP API
  surface we need (`GET /:pkg`, `GET /:pkg/-/:tarball`). Pluggable upstream
  (`NpmUpstream` for the real registry, `LocalFixtureUpstream` for hermetic tests).
  Owns the verdict cache + audit store and serves the dashboard.
- **`@sentinel/cli`** — `sentinel audit <pkg>` (one-shot) and `sentinel install …`
  (sets `registry` to the proxy and runs npm, showing the pre-install verdict).
- **dashboard** — a single self-contained HTML page served by the proxy at `/`.

---

## 3. Proxy design

The proxy implements only the parts of the [npm registry API](https://github.com/npm/registry)
a client touches during install:

- `GET /:package` → the **packument** (all versions + metadata). We pass the
  upstream document through largely untouched so resolution/semver stays npm's job,
  but we **rewrite each version's `dist.tarball` URL** to point back at the proxy.
  That is what guarantees every tarball fetch is intercepted — we never have to
  parse the client's resolution logic.
- `GET /:package/-/:tarball` → the **tarball**. This is the interception point.
  The proxy fetches the upstream tarball, runs the audit, records the verdict, sets
  `x-sentinel-score` / `x-sentinel-verdict` response headers, and (under a `block`
  policy) can refuse with `403` instead of streaming bytes.

Transparency: because we only rewrite tarball URLs and otherwise proxy the document
verbatim, any npm/yarn/pnpm/npx client works with zero changes beyond pointing
`registry` at Sentinel.

### 3.1 Where the audit runs — sync vs async

This is the key latency decision. We split it:

| Mode | What runs | When | Blocking? |
|---|---|---|---|
| **Sync gate** | Heuristic rules engine (static analysis only — no LLM, no network beyond the tarball we already fetched) | On the tarball request, before bytes are served | Yes — but only on a **cold** package@version. Result is cached by integrity hash, so steady-state is a cache hit (sub-ms). |
| **Async enrich** | LLM adapter pass + cross-version diff trend + provenance lookups | Queued after the response is served | No — enrichment updates the stored report and dashboard; never on the request path |

Rationale: the heuristic engine is fast (regex/AST over a tarball that's already in
memory) and **deterministic**, so it can gate inline without a meaningful latency
hit, and the verdict is reproducible in CI. Anything slow or non-deterministic
(LLM calls, network provenance checks) is pushed off the request path so a model
hiccup can never stall an install. The score a client sees inline never depends on
a live LLM.

Caching key = `sha512` integrity from the packument `dist.integrity`. Audits are
immutable per `(package, version, integrity)` — npm can't mutate a published
tarball without changing the hash, so a cached verdict is always valid.

### 3.2 Diff-audit

"Score every release diff" is implemented as version-to-version comparison: when
auditing `pkg@X`, the engine can take the previous version's file set as a
`baseline`. Files that are **added or changed** in the new release carry a weight
multiplier — a `postinstall` that exfiltrates secrets is far more alarming when it
**appears in a patch release** of a previously-clean package (the event-stream
pattern) than when it was there from day one. Full-content audit is the default;
diff mode is layered on top.

### 3.3 Approval gate (Phase 2.1, ADR-0011/0013)

Under the `block` policy the proxy also gates on capability approval: a tarball
with unapproved new capability atoms returns `403 approval required`. Approval is
recorded per `(name, version, integrity)` in `ApprovalStore` and inherited across
versions whose capability set is unchanged. Endpoints: `GET /-/manifest/:pkg/:ver`,
`POST /-/approvals` (single or batch), `GET /-/approvals`, `DELETE /-/approvals/:integrity`.
A dependency tree is cleared via `sentinel preflight` (resolve → preflight → batch
approve → install), because npm aborts on the first `403`.

### 3.4 Policy loading (Phase 2.2, ADR-0012/0014)

The proxy loads one Ed25519-signed policy at startup from `SENTINEL_POLICY_FILE`
(+ `SENTINEL_POLICY_SIG`, `SENTINEL_POLICY_PUBKEY`), verifying the raw bytes. An
invalid policy fails closed (non-zero exit); no policy configured uses the built-in
default. Every report carries `policy: { version, hash }` and the tarball response
sets `x-sentinel-policy`. (Distinct from the `SENTINEL_POLICY` env var, which selects
the `observe`/`block` proxy mode.)

### 3.5 Private namespace (Phase 2.3, ADR-0010/0015)

Names matching the signed policy's `privateNamespaces` globs are served
authoritatively from a `PrivatePackageStore` and NEVER from public npm (fail-closed:
unpublished claimed name ⇒ 404). `npm publish` (`PUT /:pkg`, bearer-token auth before
body parse, 64MB limit) is audited + policy-gated (a `block` verdict is rejected).
Private installs use the same score + approval gate as public, with `x-sentinel-private`.
Non-claimed names pass through transparently (the scoped exception to ADR-0005).
`GET /-/private` reports claims + published packages.

### 3.6 Sandbox enforcement (Phases 3–5, ADR-0011/0016/0017/0018)

`@sentinel/sandbox` turns an *approved* capability set into *enforced* runtime
least-privilege on macOS and Linux: `generateProfile(approved, {homeDir})` emits an allow-default +
deny-sensitive Seatbelt (SBPL) profile, each deny relaxed by an approved capability; the
`SeatbeltSandbox` runs each lifecycle script under it via `sandbox-exec` (failing closed
off-darwin). `sentinel run-scripts <dir>` ties it together and, on a loud failure, reports
the detected-but-unapproved capabilities (inferred, best-effort). Children/native inherit
the sandbox. Full `npm install --enforce` orchestration is deferred.

**Enforced surface (Phase 3):** sensitive file reads + network egress. `SENSITIVE_PATHS`
are deny-listed for reads; network is all-or-nothing (Seatbelt can't host-filter; per-host
fidelity lives on the proxy). Each deny is relaxed by an approved `filesystem` or `network`
capability. Path-segment-anchored coverage and firmlink canonicalization
(`/etc` → `/private/etc`) are applied to all deny paths.

**Env-var scrubbing (Phase 4, ADR-0017):** `scrubEnv(sourceEnv, approvedEnv)` strips the
spawned process env down to a fail-closed `ENV_ALLOWLIST` (vars npm lifecycle scripts
genuinely need: `PATH`, `HOME`, `LANG`, `NODE`, `NODE_ENV`, etc.) plus any var explicitly
named by an approved `env` capability (`--approve env:NAME`). The load-bearing goal is
dropping operator-shell secrets (`SSH_AUTH_SOCK`, `AWS_*`, `*_TOKEN`, etc.); `npm_*`
allowlist entries are forward-looking for the deferred `install --enforce` path where npm
will inject those vars. `NODE` vars are enumerated exactly (not a `NODE*` prefix) to
prevent passing `NODE_AUTH_TOKEN`. `scrubEnv` is pure and deterministic.

**Write-confinement (Phase 4, ADR-0017):** `SensitivePath` gained `modes: ("read"|"write")[]`.
Credential paths are `["read","write"]` (block exfil and tamper). New persistence-only
entries (`~/Library/LaunchAgents`, `LaunchDaemons`, crontab spool, shell rc files,
`~/.config/autostart`) are `["write"]` only — no `detectRe`, so `secret-exfil` ignores
them. `generateProfile` emits `(deny file-write* ...)` for each write-mode entry not
covered by an approved `filesystem` capability, firmlink-canonicalized. A `filesystem`
approval relaxes both the read and write deny for its target; read/write sub-kinds are
deferred (YAGNI). Firmlink canonicalization is required for write denies too (probed:
a `/tmp` deny does not match `/private/tmp`).

**Cross-platform backends (Phase 5, ADR-0018).** Enforcement runs on macOS *and* Linux behind
`createSandbox()`: darwin → `SeatbeltSandbox` (SBPL), linux → `BubblewrapSandbox` (`bwrap`
argv), any other platform → fail-closed throw. `Sandbox.run` takes the *approved capabilities*
+ `homeDir`; each backend compiles its own profile, so the runner/CLI are backend-agnostic.
The Linux deny model mirrors Seatbelt via bind/overlay: credential **dirs** → `--tmpfs`,
credential/persistence **files** → `--ro-bind /dev/null`, all-or-nothing network → `--unshare-net`;
each relaxed by an approved `filesystem`/`network` capability through the shared `pathCovers`
matcher. Persistence paths are platform-tagged in `SENSITIVE_PATHS` (`sensitivePathsFor`):
darwin gets LaunchAgents/LaunchDaemons/cron spool; linux gets XDG autostart
(`~/.config/autostart`) and systemd-user units (`~/.config/systemd/user`,
`~/.local/share/systemd/user`) — all HOME-based (the system cron spool is OS-protected
against unprivileged writes and cannot be used as a bwrap mountpoint unprivileged).
On Ubuntu 24.04, unprivileged user namespaces are AppArmor-restricted by default; CI relaxes
`kernel.apparmor_restrict_unprivileged_userns`, and the backend fails closed if the kernel
still refuses.

### 3.7 Enforced install (Phase 6, ADR-0019)

`sentinel install --enforce` runs a normal `npm install --registry <proxy>` with
`npm_config_script_shell` set to the shipped `sentinel-script-shell` wrapper. npm invokes it as
`<wrapper> -c "<cmd>"` for every lifecycle script in the tree — in dependency order, with the
full npm env, cwd, and `.bin` PATH — and the wrapper runs each command under `createSandbox()`
with the package's approved capabilities and a credential-screened env. Approvals come from the
proxy manifest for dependencies (`required`/`denied` ⇒ fail closed) and from operator `--approve`
for the root project. This is the difference from plain `sentinel install`, which redirects the
registry but runs scripts unsandboxed. `scrubEnv` now narrows the `npm_` allowlist to safe
sub-groups and drops any credential-shaped var (ADR-0017's pre-condition, met). Fail-closed:
sandbox unavailable / unapproved dependency ⇒ the wrapper exits non-zero and npm aborts.

### 3.8 Whole-tree audit (Phase 7, ADR-0020; ecosystem breadth + SBOM, Phase 14, ADR-0027)

`sentinel audit-tree [lockfile]` audits an entire resolved dependency graph in one pass.
The CLI parses the lockfile through `parseAnyLockfile(raw, {filename, omitDev})`
(`packages/core/src/lockfile.ts`), which dispatches by filename suffix (falling back to a
content sniff) across three formats — npm `package-lock.json`/`npm-shrinkwrap.json` (v2/v3
`packages` map), `yarn.lock` (a bespoke v1 text parser plus a YAML parse for berry, chosen
by sniffing for `__metadata:`), and `pnpm-lock.yaml` (YAML across lockfile versions v5's
`/name/version` and v6/v9's `name@version` keys, peer-dep suffix `(a@1)(b@2)` stripped) —
into the same deduped, sorted `{name, version, integrity?}` `Coordinate[]` regardless of
format (skipping the root entry and `link:`/`file:` deps). Berry checksums are not
SRI-shaped, so berry-parsed coordinates carry no `integrity`. The `yaml` package
(`^2.9.0`) backing the pnpm/berry parsers is a dependency of `@sentinel/core` only. The CLI
POSTs the coordinates (plus an optional `failOnError` flag) to `POST /-/audit-tree`. The
proxy fans out with bounded concurrency over the same integrity-cached `auditVersion()`
path used by the tarball route, then rolls the per-package verdicts into a worst-case-wins
aggregate and a gate decision — both computed server-side under the loaded policy. The gate
trips at the policy's `treeGate` level (default `block`); a gated tree makes the CLI exit
non-zero (the CI contract). Unresolvable packages become surfaced `error` rows and never
trip the gate (invariant #6) unless the caller opts into `--fail-on-error`, which threads
through to `aggregateTree(rows, treeGate, {failOnError})` and also gates on any `error` row.
When a coordinate carries an `integrity` (from the lockfile) that disagrees with
`report.meta.integrity` — the hash Sentinel actually recomputed from the served bytes
(ADR-0022's `actualIntegrity`), not a claimed value — the route forces that row to `block`,
sets `TreePackageRow.integrityMismatch: true`, and injects a `lockfile-integrity-mismatch`
top finding; `TreeAggregate.integrityMismatch` counts these across the tree. The check only
fires when both sides are present and disagree — an absent lockfile integrity (e.g. a
berry-parsed row) never false-flags. `audit-tree --sbom <file>` writes the audited tree as a
CycloneDX 1.6 JSON BOM via `toCycloneDX(tree, {now})` (`packages/core/src/sbom.ts`) — pure,
with `now` injected rather than read from the clock — one `library` component per package
(`purl: pkg:npm/<name>@<version>`, scoped names `%40`-encoded) carrying Sentinel's
verdict/score/top-finding/integrity-mismatch as `sentinel:*` custom properties. The SBOM is
written even when the tree is gated (it's informational output, not the gate itself). This
is a `/-/` batch endpoint, never on the inline tarball request path (invariant #3).

### 3.9 Signature & provenance verification (Phase 8, ADR-0021)

`PackageMeta` carries `signature: verified|invalid|unsigned|unknown` and
`provenance: present|absent` instead of the flattened `signatureStatus` field it replaces.
`verifyRegistrySignature` checks the npm registry signature offline against a configured
key set (`NPM_SIGNING_KEYS`, matched by `keyid`) — ECDSA P-256, SHA-256, DER-encoded,
over the payload `${name}@${version}:${integrity}`. The key set is a static input baked
into the audit, never fetched at request time (invariant #3); the check runs inline,
alongside the other sync rules. A pure `provenance` rule turns the two fields into findings
(`invalid` is `critical` and hard-blocks); it cannot see policy, so an optional
`requireSignature`/`requireProvenance` pattern-list gate lives beside `deny` in `score.ts`,
letting a policy require a verified signature or present provenance for matching package
names without changing the rule itself.

### 3.10 Provenance deep-verify (Phase 9, ADR-0022)

Phase 8's `provenance` field only recorded whether the packument *claimed* an
attestation existed; Phase 9 actually verifies it. When a packument's version
metadata claims provenance, the acquisition path calls `Upstream.getAttestations`
(a fetch failure yields `null`, never a crash) and `runAudit` recomputes the
tarball's integrity from the bytes it actually holds (`actualIntegrity`) rather
than trusting the claimed `dist.integrity` — a mismatch is a critical
`integrity-mismatch` finding, and the proxy caches/reports by the actual hash,
closing the cache-poisoning-by-claim gap ADR-0021 left open. `verifyProvenance`
(pure, offline, never throws) then runs a single `@sigstore/verify` `Verifier`
against pinned trust material in `packages/core/trust/` (`trusted-root.json` +
a `keyFinder` over `npm-attestation-keys.json`), producing
`verified | invalid | absent | unknown`: every present bundle must verify AND
every subject's sha512 digest must bind to the *actual* integrity, or the
result is `invalid` — including bundles that throw partway through verification
(a crash over a present bundle is `invalid`, never `unknown`, so a crafted
crash-bundle can't fail open past the identity gate). `unknown` is reserved for
missing inputs (unfetchable bundle, empty list, no trust material configured).
Identity (workflow SAN, issuer, source repository, ref, builder, commit) is
extracted only from the verifier's authenticated result and the signed DSSE
statement, never from unauthenticated packument fields, and attached as
`provenanceIdentity`. Status and identity flow three ways: the `provenance` rule
turns status into findings; `score.ts`'s `provenanceIdentities` gate enforces
per-pattern identity requirements with fail-closed AND across matching entries
(`unknown` is exempt from this gate but not from the upgraded
`requireProvenance`, which now demands `verified`); and the status/identity
surface on the `x-sentinel-provenance` header, the dashboard, and
`audit-tree`'s per-row + aggregate provenance counts. Trust-root staleness is
informational only — a zero-weight `trust-root-stale` finding via an injectable
clock, conservative by design (stale only when *every* pinned CA's `validFor.end`
has passed; the real Fulcio CA is open-ended, so it never reports stale today).

### 3.11 Runtime violation telemetry (Phase 10, ADR-0023)

Phases 3–6 made the sandbox *contain* a denied capability; Phase 10 makes it a
*sensor* too. `computeDenySet(approved, { homeDir, platform })`
(`packages/sandbox/src/deny-set.ts`) derives the same `deniedPaths`/
`networkDenied` the profile/`bwrap` generators already enforce, so attribution
can never drift from what's actually denied (locked by a non-drift test).
`classifyViolation(result, denySet)` (`packages/sandbox/src/violation.ts`) is
pure and total (never throws): given a failed sandboxed child, it matches
`stderr` against a permission-error signature and attributes it —
`confirmed` when a filesystem target falls inside `deniedPaths` or a
`host:port` is parseable under a network deny, `suspected` for a class-level
network deny with no parseable host, `null` otherwise (including a
permission error on a path *not* in the deny set — the false-positive
filter — and the swallowed case, `exitCode === 0`). Both `SeatbeltSandbox`
and `BubblewrapSandbox` attach the result to `SandboxResult.violation`.
`sentinel-script-shell` (the Phase 6 enforcement point) best-effort POSTs a
detected violation to `POST /-/violations` — a reporting failure never
changes the install's exit code — resolving the served integrity via the
`/-/manifest` fetch it already makes; root-install scripts are never
reported. The proxy's `ViolationStore` (`packages/proxy/src/violations.ts`)
records by `integrity`: `confirmed` quarantines (and revokes any standing
approval); `suspected` is record-only. **The quarantine is a serve-time
overlay, not a score mutation**: `applyQuarantine` (`server.ts`) runs at the
tarball serve gate (`gateAndSend`) and in `audit-tree`'s per-row audit — the
enforcement points where a gated verdict blocks the install — and, for a
quarantined integrity, returns a shallow copy with `verdict` forced to
`block` and a `weight: 0` critical `runtime-violation` finding prepended.
`/-/audit` and `/-/manifest` return the un-overlaid static report; they're
read-only, so the tarball route's 403 remains the actual gate. The cached `AuditReport` in
`AuditStore` is never written to, so invariant #1 (deterministic scoring)
holds exactly as before; only the served *verdict* reflects runtime history,
freshly on every request. `x-sentinel-violations` surfaces the flag as a
header; `sentinel violations`, the dashboard's runtime-violations panel, and
`audit-tree`'s per-row/aggregate output all read the same store. Best-effort
limitation: the sensor only detects violations that surface as process
failure — a swallowed denial (exit `0`) is invisible to telemetry but still
contained by the sandbox, unchanged from Phase 6. `POST /-/violations` is
unauthenticated (like `/-/approvals`); a spoofed report can only quarantine
an *already-audited* integrity (the endpoint 400s otherwise) and can only
force `block`, never relax a verdict — a fail-closed DoS, not a bypass.

### 3.12 Control-plane auth (Phase 12, ADR-0025)

Phases 2–11 left every mutating control-plane endpoint unauthenticated;
ADR-0024 named the gap and deferred it. Phase 12 closes it with **signed,
stateless Ed25519 role tokens**, reusing the same offline-signed-artifact
pattern ADR-0014 established for policy: `signToken`/`verifyToken`
(`packages/core/src/auth.ts`) mint and check `base64url(payload).base64url(sig)`,
where `payload` is `{ role, sub, iat, exp }`. `verifyToken` is pure and total
(never throws) and checks, in order, signature → parse → role → expiry, so a
tampered payload fails at the signature check before anything downstream sees
it. Three roles: `operator`, `agent`, `publisher`.

**Opt-in, not on by default.** `makeAuthz(publicKeyPem)`
(`packages/proxy/src/authz.ts`) is disabled (`enabled: false`, every
`requireRole` a pass-through) unless `SENTINEL_AUTH_PUBKEY` (a path to a PEM
public key) is set at proxy startup, in which case a bad path *or* content
that doesn't parse as a public-key PEM (empty, whitespace-only, or garbage)
is a fatal startup error rather than a silent fall-back to open mode. With auth
disabled — the default — every existing test and deployment behaves exactly
as before this phase.

**Role → endpoint map** (gated only when auth is enabled):

| Route | Required role |
|---|---|
| `POST /-/approvals` | `operator` |
| `DELETE /-/approvals/:integrity` | `operator` |
| `DELETE /-/violations/:integrity` | `operator` |
| `POST /-/approval-requests` | `agent` |
| `POST /-/violations` | `agent` |
| `PUT /:pkg` (publish) | `publisher` (auth enabled) / legacy `requirePublishAuth` token (auth disabled) |

**Reads stay open in every mode**: every `GET`, the tarball serve, packument
resolution, and `POST /-/audit-tree` (a read-shaped fan-out audit, not a gate
mutation) are never gated by role — Phase 12 authenticates mutations to the
gate, not visibility into it, preserving §3.5/ADR-0005's transparent-proxy
posture unchanged.

**This makes ADR-0013/0024's boundary real at the HTTP layer.** ADR-0024's
"the agent can request, only a human can grant" was, before this phase,
enforced only by the *shape* of the MCP tool surface (no `sentinel_approve`
tool exists) — nothing stopped a caller from bypassing MCP and hitting `POST
/-/approvals` directly. With auth enabled, an `agent`-role token presented to
that route now gets a `403` (valid identity, wrong role); only an
`operator`-role token is accepted. `401` vs `403` is a deliberate distinction:
401 means no valid identity was proven at all (missing/malformed/expired/bad
signature); 403 means a valid identity was proven but it isn't permitted on
this route.

Clients: `sentinel-mcp`'s `ProxyClient` and `sentinel-script-shell` both read
`SENTINEL_AUTH_TOKEN` and attach `Authorization: Bearer <token>` on POSTs only
(agent role); the dashboard has an operator-token field (persisted to
`localStorage`) that attaches the same header to its Approve/Deny/Revoke
actions. `sentinel token keygen/mint/verify` (CLI) is the minting/inspection
workflow.

Expiry is enforced at request time (`verifyToken` rejects `now >= exp`) — this
is authentication, not scoring, and touches nothing in `runAudit`/`score.ts`;
invariant #1 is untouched. There is no token store or revocation list: a
compromised token is bounded by its TTL, and full revocation is key rotation.

### 3.13 Supply-chain identity heuristics (Phase 13, ADR-0026)

The rules through Phase 12 detect behavior or verify cryptographic identity;
none of them detect the naming-based social-engineering class — typosquat,
dependency confusion. Phase 13 adds two checks, sharing one distance library
(`packages/core/src/name-distance.ts`): `canonical` (lowercase, strip
separators, fold a small homoglyph set — `rn`→`m`, `0`→`o`, `1|`→`l`, `5`→`s`),
`normalizeName` (flatten `@acme/utils`/`@acme/*` → `acme`, for comparing a
name against a namespace *claim* rather than another package name), and
`damerauLevenshtein` (optimal-string-alignment; insertion/deletion/
substitution/adjacent-transposition all cost 1). `typosquatMatch(name,
target)` is true when the names differ and either their canonical forms
collide or their edit distance sits within a length-scaled threshold (`≤2`
once the target's canonical form is 7+ characters, else `≤1`).

- **`typosquat` — a pure rule** (`packages/core/src/rules/typosquat.ts`,
  registered in `RULES`). It scans a bundled, static, dated corpus of ~150
  popular npm names (`packages/core/src/typosquat-corpus.ts` — never fetched
  at audit time, invariant #3), bucketed by canonical length for a bounded
  lookup, and flags the first corpus name the package's name is a likely
  typosquat of. `metadata` category, `medium` severity. FP controls: never
  flags a name already in the corpus, skips names under 4 characters, and
  `typosquatMatch` requires distinct names.
- **`dependency-confusion` — a score-time check**, not a rule, because it
  needs `policy.privateNamespaces` (ADR-0010/0015) and a pure rule can't see
  policy — the same pure-rule/score-time-gate split ADR-0014/0021 established
  for `requireSignature`/`requireProvenance`. `dependencyConfusion(name,
  privateNamespaces)` in `score.ts` normalizes each claimed namespace and
  flags a *public* package name whose canonical form equals, prefixes, or is
  a `typosquatMatch` of the normalized claim — `metadata` category, `high`
  severity. It never flags the legitimate claimed package itself: a name
  that already matches one of its own claims (`matchPackage`) short-circuits
  before any distance comparison runs. The finding is spliced into
  `rawFindings` before the normal weight/waiver pipeline (`score()`), so it
  gets ordinary `allow`/`disabled` treatment, but it is **not** added to the
  hard-block condition.

Both findings use the existing `metadata` `Category` (no new category). Both
are weighted, not hard-blocking, and both are deterministic and inert by
default: the default policy ships no `privateNamespaces`, so
`dependencyConfusion` returns `null` for every package until an operator
opts in, and the corpus is a static committed input, so `typosquat` never
changes behavior between runs. Under the default policy (`medium: 12, high:
25`, `thresholds: { allow: 80, warn: 50 }`), a lone typosquat finding drops a
clean package 100→88 (still `allow`); a lone dependency-confusion finding
drops it 100→75 (`warn`, not `block`) — both compound with any other
findings the package trips, and an operator escalates to a hard block via
`deny`/`hardBlockSeverity` or waives a known false positive via
`policy.allow`/`policy.rules.disabled`, exactly as with any other finding.

### 3.14 Durable history + observability (Phase 15, ADR-0028)

Every audit and violation Phases 1–10 produce lives only in the in-memory
hot cache (plus an O(n)-rewrite JSON file for `AuditStore` restart
survival) — nothing durable or queryable. Phase 15 adds an **opt-in**
second write destination, `HistoryDb` (`packages/proxy/src/history-db.ts`),
over the **built-in `node:sqlite`** — zero new dependency. It is
constructed only when `SENTINEL_HISTORY_DB=<path>` is set (`index.ts`'s
`main()`); `node:sqlite` itself is loaded via `createRequire` **inside the
constructor**, so importing the module for its types never fires the
experimental warning — only `new HistoryDb(...)` does. Unset (the
default), nothing changes: no `HistoryDb`, no `node:sqlite` import, the
same in-memory + JSON-file behavior as every prior phase.

- **Two tables.** `audit_events` is keyed on `integrity` with `INSERT ...
  ON CONFLICT DO NOTHING` — one row per immutable tarball (ADR-0004),
  first-seen `audited_at`, full `report_json` plus denormalized
  verdict/score/signature/provenance columns for aggregate queries.
  `violation_events` is `AUTOINCREMENT`-keyed and strictly append-only —
  every reported violation (ADR-0023) is its own row.
- **Write-through, additive.** `AuditStore.put` and `ViolationStore.record`
  each take an optional trailing `history?: HistoryDb` param; when present,
  the same in-memory write also calls `history.recordAudit(report, now)` /
  `history.recordViolation(rec)`. The write is best-effort (invariant #6,
  try/catch swallowed) — a `HistoryDb` failure never breaks a record or the
  gate. `now` is caller-supplied (`new Date().toISOString()`), not read
  from the clock inside `HistoryDb` — the same injected-clock discipline
  as ADR-0022/ADR-0027. The in-memory hot cache the request path reads
  from is untouched.
- **Query surface:** `summary()`, `history({verdict, name, limit, offset})`,
  `trends({limit})` (chronological daily allow/warn/block buckets),
  `topFlagged({limit})`, `violationTimeline({limit})`.
- **Three open, un-role-gated read routes** (`server.ts`): `GET
  /-/metrics` (`{summary, trends, topFlagged}`), `GET /-/history`
  (`?verdict=&name=&limit=&offset=`), `GET /-/violations/timeline`. They
  join the rest of the open read surface (Phase 12's `makeAuthz` gates
  only the six mutating routes). No `HistoryDb` configured ⇒ `501
  { enabled: false }` on all three, not a silent empty body.
- **CLI:** `sentinel stats` (summary + trend + top-flagged) and `sentinel
  history [--verdict --name --limit]`; both print "history not enabled —
  set SENTINEL_HISTORY_DB on the proxy" on a `501`.
- **Dashboard:** an "Observability" section on `packages/proxy/public/
  index.html` — inline-SVG verdict trend, top-flagged list, violation
  timeline — polled alongside the rest of the dashboard, all fetched
  fields passed through the existing `esc()` helper, degrading to a note
  when disabled.

`HistoryDb` only stores and reads back events the deterministic scoring
path already produced; it never influences a verdict (invariant #1
untouched). SQLite is single-node — no multi-proxy sharing — and both
tables grow unbounded with no retention/pruning yet (ADR-0028).

### 3.15 Maintainer & release-anomaly signals (Phase 16, ADR-0029)

Every rule through Phase 13 scores a release in isolation — `AuditInput`
carries only the audited version's own files and metadata, never anything
about the versions that came before it. Phase 16 adds cross-version
context, closing the "maintainer-change anomalies" gap ADR-0026 explicitly
deferred.

- **`ReleaseContext`** (`packages/core/src/types.ts`) is a new, all-optional
  type — `previousVersion`, `previousMaintainers`, `previousPublishedAt`,
  `currentPublishedAt`, `versionCount` — carried on the new
  `AuditInput.releaseContext?`. Absent ⇒ every Phase 16 signal is inert.
- **Plumbing.** `UpstreamPackument.time?: Record<string, string>` is now
  mapped from the packument's `time` field in both `NpmUpstream` and
  `LocalFixtureUpstream`. The exported, pure `buildReleaseContext(pm,
  version)` in `packages/proxy/src/server.ts` derives a `ReleaseContext`
  from the packument `auditVersion` has already fetched — no new upstream
  call — and passes it into `runAudit`.
- **`release-anomaly` — a pure rule** (`packages/core/src/rules/
  release-anomaly.ts`, registered in `RULES`; rule count is now 7). Three
  signals, all `metadata` category:
  1. **Maintainer change** — none of `previousMaintainers` remain in the
     current set ⇒ `high` ("possible account/ownership takeover"); the set
     changed but at least one previous maintainer remains ⇒ `low`.
  2. **Dormancy resurrection** — the gap between `previousPublishedAt` and
     `currentPublishedAt` is ≥365 days ⇒ `low`.
  3. **New-package risk** — `versionCount === 1` and
     `meta.hasInstallScripts` ⇒ `medium`.
- **`capabilityNoveltyFindings` — a pure helper, not a rule**
  (`packages/core/src/rules/capability-novelty.ts`), called from
  `buildAudit` (`packages/core/src/audit.ts`) rather than added to `RULES`,
  because it needs `capabilityDelta`, which `buildAudit` computes *after*
  `runRules` returns. Signal 4: `capabilityDelta.added` contains a
  `network`/`process` capability *and* a `previousVersion` exists ⇒ `medium`
  `metadata` finding, ruleId `capability-novelty` — a dangerous capability
  the immediately-previous version didn't have.
- **Determinism.** Both the rule and the helper are pure functions of their
  inputs — no I/O, no policy, no wall-clock. `daysBetween` parses two
  *given* ISO timestamps (`Date.parse`); neither file calls `Date.now()` or
  `new Date()` with no argument, so "dormant"/"fresh" is intrinsic to the
  release pair being compared, never relative to when the audit runs
  (invariant #1 untouched). A test-suite grep guard enforces the no-clock
  constraint.
- **Weighted, inert by default.** All four signals are `metadata`
  findings, never added to the hard-block condition — power comes from
  compounding, not any single signal. No `releaseContext` (e.g. a
  private-store package, or an upstream without `time`) ⇒ both the rule and
  the helper return `[]`.

### 3.16 CI-native GitHub Action (Phase 17, ADR-0030)

Phases 1–16 gate installs and lockfiles, but only when a human or CI job
already knows to run `sentinel audit-tree` against a proxy someone started.
Phase 17 adds a self-contained on-ramp into GitHub PRs: a new
**`@sentinel/action`** workspace (`packages/action`, bin `sentinel-ci`) that
needs nothing already running.

- **`runCi(opts)`** (`packages/action/src/run.ts`) self-boots
  `createServer` in-process on port `0` with an **injected `Upstream`**
  (`NpmUpstream` in production, `LocalFixtureUpstream` in tests — the same
  seam every other package's tests already use) rather than depending on a
  separately-started proxy. It parses the lockfile with §3.8's
  `parseAnyLockfile`, `POST`s the coordinates to the same `/-/audit-tree`
  route the CLI uses, writes a CycloneDX SBOM via §3.8's `toCycloneDX`
  (injected `now`), and renders a Markdown PR report
  (`renderPrComment`, `packages/action/src/report.ts`, starting with a
  `<!-- sentinel-report -->` marker for idempotent updates). It always
  closes the self-booted server in a `finally` block.
- **GitHub-native surfacing**, all defensive (absent env ⇒ falls back to
  stdout): `$GITHUB_OUTPUT` (`verdict`/`gated`/`blocked`/`warned`/
  `errored`/`sbom-path`), `$GITHUB_STEP_SUMMARY`, a comment body written to
  `SENTINEL_COMMENT_BODY`, and `::error::`/`::warning::` annotations per
  offending package.
- **`fail-on` (`block` default, `warn`, `none`) drives the exit code**, not
  the raw verdict alone — `exitFor` also honors the server-side `gated`
  flag (the `treeGate`/`--fail-on-error` rollup), so `none` gives an
  observe-only onboarding path that never fails the check.
- **`sentinel-ci`** (`packages/action/src/index.ts`) is a thin,
  env-driven bin (`INPUT_LOCKFILE`/`INPUT_POLICY`/`INPUT_SBOM_PATH`/
  `INPUT_FAIL_ON`/`INPUT_OMIT_DEV`/`INPUT_WORKING_DIRECTORY`), loading a
  signed policy through core's existing `loadPolicy` (falling back to
  `DEFAULT_POLICY`).
- **A thin composite `action.yml`** (repo root) does only the
  GitHub-specific work: `setup-node` → install/build → run the bin →
  `upload-artifact` for the SBOM (`if: always()`) → `github-script` to
  post or update a PR comment found by the `<!-- sentinel-report -->`
  marker instead of always appending a new one.
  `.github/workflows/sentinel-example.yml` shows minimal usage.
- **The proxy entrypoint-guard root fix.** `packages/proxy/src/index.ts`'s
  `main()` is now guarded the same way `@sentinel/mcp`'s bin already is
  (`isEntrypoint()` comparing `import.meta.url` to the resolved
  `process.argv[1]`) — importing `@sentinel/proxy` for its exports no
  longer boots a listening server as a side effect. This is what makes
  `runCi`'s self-boot import-safe.

The Action only *runs* the existing `/-/audit-tree` scoring path; it adds
no rule, weight, or verdict logic, and no package code executes anywhere in
this flow (invariant #1 untouched; ADR-0030).

### 3.17 Actionable remediation (Phase 18, ADR-0031)

Phases 1–17 detect, contain, record, and gate — but stop at the verdict. A
`block` says *that* a package is dangerous; nothing said what to do about it.
Phase 18 adds an advisory guidance layer on top of the existing, unchanged
audit output.

- **`remediate(report): Remediation`** (`packages/core/src/remediation.ts`)
  is a pure, total function of an already-computed `AuditReport`. It maps
  each finding to `{ ruleId, severity, summary, action }` via a `REMEDIATIONS`
  map keyed by `ruleId`, falling back to a per-`Category` guide and then a
  generic guide (an unrecognized `ruleId` never throws), sorted
  worst-severity-first. When the verdict isn't `allow`, it also returns a
  `WaiverTemplate` — the package's `name`/`version`/`integrity`, a ready
  `sentinel approve <name> <version> --reason "..."` command, and the same
  `{ name, version, integrity, reason }` payload shape Phase 11's
  request-not-grant approval-request path (`POST /-/approval-requests`,
  ADR-0024) already accepts. `remediationHint(ruleId)` is the short
  one-line projection used by surfaces that don't want a full result.
  `remediate` is called nowhere on the scoring path — it consumes a verdict,
  it never produces or influences one (invariant #1 untouched).
- **`GET /-/explain/:pkg/:version`** (`packages/proxy/src/server.ts`) audits
  the target version, runs `remediate`, and walks back a **bounded window**
  (newest ≤10 prior versions, via the packument and `cmpSemver`) for the
  first version whose own audit is `allow` — short-circuiting on the first
  hit and reusing the same cached, integrity-keyed `auditVersion` path every
  other route uses. A packument fetch failure or a per-version audit failure
  is treated as "no last-known-good found," not an error — this is
  best-effort advisory output, not a gate. The route is deliberately off the
  inline tarball-request gate (invariant #3); it's expected to be slower.
- **Three surfaces share one `{ report, remediation, lastKnownGood }`
  shape**: `sentinel explain <package> <version>` (CLI, `formatExplain` in
  `packages/cli/src/format.ts`) prints the verdict, each finding's action, a
  "pin to" suggestion when a last-known-good exists, and the ready
  approve/waiver command; the `audit-tree` PR comment gains a "how to fix"
  column via a new `TreePackageRow.topFindingRuleId` (set by the audit-tree
  route from the worst finding) rendered through `remediationHint` — a cheap
  projection needing no extra per-package audit — plus a footer pointing at
  `sentinel explain`; and `sentinel_explain` (MCP, `packages/mcp/src/tools.ts`)
  is a sixth **read** tool whose `ProxyClient.explain` throws on a non-OK
  response rather than fabricating a result, matching ADR-0024's contract.
- **Advisory-only.** Nothing in this phase writes to a lockfile, mutates a
  dependency tree, or auto-selects a version — `remediate` and `sentinel
  explain` only ever suggest; a human (or an agent through the existing
  request-not-grant path) still decides.

### 3.18 Signed audit attestations (Phase 19, ADR-0032)

Phases 1–18 make the audit trustworthy as it happens; nothing survives a
`sentinel audit-tree` run as a portable, offline-checkable artifact past that
process's exit. Phase 19 adds a produce/verify layer over an already-computed
tree audit, entirely off the scoring path.

- **`buildAuditStatement(tree, {sbomDigest, sbomName, now})`**
  (`packages/core/src/attest.ts`, pure) projects a `TreeAuditResult` into an
  in-toto `Statement` v1: `subject` is the hex SHA-256 digest of the tree's
  CycloneDX SBOM bytes (§3.8/ADR-0027) rather than the tree JSON itself, and
  `predicate` is a VSA-style summary — `verifier`, `policyHash` (from
  `TreeAuditResult.policyHash`, now set on the `/-/audit-tree` response),
  `verdict`, `gated`, `counts`, `packageCount`, `timestamp` (`now` injected,
  never read from the clock). `predicateType` is the Sentinel-owned
  `https://sentinel.dev/attestation/audit-summary/v1`.
- **`signAttestation(statement, privPem, keyid)`** wraps the Statement in a
  DSSE envelope and Ed25519-signs the PAE (`pae(payloadType, payload)`,
  signed via `signPolicy` — ADR-0014's raw-bytes signing primitive, no new
  crypto dependency). `attestationKeyid(pubPem)` derives
  `SHA256:base64(sha256(SPKI DER))`, matching ADR-0021's keyid convention.
- **`verifyAttestation(envelope, pubPem, opts?)`** is pure, offline, total,
  and fail-closed: the whole body runs under one `try/catch` so any
  malformed input maps to `{valid: false, reason: "malformed"}` rather than
  throwing; the Ed25519 signature over the recomputed PAE is checked before
  the payload is parsed at all; a verified-but-wrong envelope is rejected
  with a typed reason (`wrong-predicate`, `subject-mismatch` against
  `opts.expectedSbomDigest`, `policy-mismatch` against
  `opts.expectedPolicyHash`, or `verdict-block`/`verdict-warn` against
  `opts.requireVerdict`). It makes no network call and reads nothing beyond
  the envelope and key it's handed.
- **Signing is operator-side, in the CLI, never on the proxy** — the proxy
  gains no signing key and no new mutating route; its only change is
  exposing the scoring-time `policyHash` it already computed
  (`opts.policyHash ?? policyHashOf(enterprisePolicy)`) on the
  `/-/audit-tree` response, so an attestation can bind to and later be
  checked against the policy that produced the verdict. Three CLI commands:
  `sentinel attest-keygen --out <prefix>` (Ed25519 keypair, private key
  `0600`); `sentinel attest <lockfile> --key <priv> --out <att> [--sbom
  <file>]` (audit the tree → write the SBOM → sign a DSSE envelope over its
  digest); `sentinel verify-attestation <att> --key <pub> [--sbom
  --policy-hash --require allow|allow-or-warn]` (offline verify, non-zero
  exit on any rejection — the deploy gate). Note: `attest-keygen` and
  `attest` are two sibling top-level commands, not `attest keygen` — a
  commander-15 parent/subcommand `requiredOption` interaction ruled out
  nesting them.
- **Determinism (invariant #1 untouched).** `buildAuditStatement` and `pae`
  are total functions of their inputs with an injected `now`; the same tree
  result, SBOM digest, and key produce a byte-identical DSSE envelope every
  time. This phase attests *over* an already-deterministic result — `runAudit`,
  `score()`, the rule set, and `aggregateTree` are untouched, and
  `verifyAttestation` consults no clock and makes no network call.

This extends enforcement past install-time and CI-time to **deploy-time**: a
release pipeline can gate on a signed, portable artifact instead of
re-running `audit-tree` or trusting an unauthenticated JSON blob handed
across a pipeline boundary. The custom `predicateType` keeps the envelope
DSSE/in-toto-compliant but bounds interop with a generic SLSA verifier
expecting a standard predicate shape — see [ADR-0032](./docs/adr/0032-signed-audit-attestations.md).

### 3.19 Policy authoring + impact preview (Phase 20, ADR-0033)

The policy governs every verdict (ADR-0002/0012/0014), but authoring one is
hand-edited JSON with no help beyond keygen/sign/verify — nothing catches an
inverted threshold or a zero critical-weight before it's signed, and nothing
shows an operator what a candidate edit *does* to real traffic before they
sign it. Phase 20 adds a lint + dry-run impact layer on top of the existing,
unchanged scoring path.

- **`lintPolicy(policy): {errors, warnings}`** (`packages/core/src/
  policy-lint.ts`, pure, total) structurally + semantically inspects an
  `EnterprisePolicy` alone — no scoring, no I/O. **Errors** (a policy an
  operator should not sign): out-of-range or inverted thresholds, an invalid
  `hardBlockSeverity`, a non-finite/negative `severityWeight`, a
  non-positive `diffMultiplier`, a malformed list entry, or a package in
  both `allow` and `deny`. **Warnings** (legal but suspicious): non-monotonic
  severity weights, an aggressively low `hardBlockSeverity`, an `allow`
  threshold a lone critical finding still clears, an `allow` threshold of
  `100`, or a `diffMultiplier` below `1`. `DEFAULT_POLICY` lints clean.
- **`HistoryDb.allReports(limit = 1000)`** (§3.14) reads back stored
  `audit_events.report_json` rows, newest-first, bounded, skipping a
  corrupt row rather than throwing (invariant #6).
- **`POST /-/policy/preview`** (`server.ts`, open read route — it mutates
  nothing) takes a candidate policy, calls `allReports()`, and re-scores
  each stored report under the candidate via the *same* pure `score()` the
  live gate calls — a stored `ScoredFinding` is structurally a `Finding`,
  so the cast-back-and-rescore needs no bespoke replay path. Response:
  `{enabled, total, transitions, changed}` — `transitions` buckets every
  report into one of six verdict-flip counts plus `unchanged`; `changed`
  lists up to 100 flipped packages, worst-first, with
  `{name, version, from, to, fromScore, toScore}`. No `HistoryDb` ⇒ `501
  {enabled: false}`; a malformed candidate ⇒ `400` via `parsePolicy`'s
  existing validation.
- **CLI:** `sentinel policy init --out <file>` (scaffold `DEFAULT_POLICY`);
  `sentinel policy validate <file>` (parse + lint; exits non-zero **iff**
  there are errors — warnings-only still exits `0`, a clean CI gate);
  `sentinel policy preview <file> [-p proxy]` (POST + render the impact;
  `501` prints a "history not enabled" hint).
- **Dry-run, always.** The candidate policy is never applied to the live
  server, stored, or signed by the preview endpoint — signing
  (`sentinel policy sign`, §3.4/ADR-0012) and loading the signed policy
  onto the proxy remain separate, deliberate, existing steps.

Invariant #1 is exercised here, not endangered: the preview replays the
*same* `score()` the live gate uses, so an identical candidate against the
same history replays to `unchanged === total`. `lintPolicy` is pure; the
live scoring path (`runAudit`, the inline gate, `AuditStore`) gains no new
branch. The preview requires the opt-in `HistoryDb` and is bounded by
`allReports`'s 1000-row cap — see [ADR-0033](./docs/adr/0033-policy-authoring-impact-preview.md).

### 3.20 Known-advisory detection (Phase 21, ADR-0034)

Every rule through Phase 16 is heuristic or behavioral — none of them
consult a known-bad list. Phase 21 adds the confirmed-malicious dimension:

- **`packages/core/src/advisory-corpus.ts`** — a bundled, static, offline
  corpus (`KNOWN_ADVISORIES: readonly Advisory[]`) of real, publicly
  documented compromised npm releases (`(name, version, id)` plus optional
  `severity`/`reference`) — metadata only, never fetched at audit time
  (invariant #3). `buildAdvisoryIndex` builds a `name → Advisory[]` lookup
  once; `parseAdvisories` is a pure, total parser for an operator-supplied
  JSON array.
- **`known-advisory` — a pure rule** (`packages/core/src/rules/
  known-advisory.ts`, registered in `RULES`; rule count is now **8**).
  Checks the bundled corpus **union** any operator-supplied
  `input.advisories` for an exact `(name, version)` match. A hit emits a
  `metadata` finding at the advisory's own `severity` (default `critical`),
  which hard-blocks under the default policy's `hardBlockSeverity`.
- **`SENTINEL_ADVISORIES` (proxy)** — an optional path to a JSON `Advisory[]`
  file, read **once at process startup** (`resolveAdvisories` in
  `packages/proxy/src/index.ts`), fail-closed like `SENTINEL_AUTH_PUBKEY`
  (a FATAL exit on an unreadable path, never a silent skip). The parsed
  advisories are threaded into the public install audit path
  (`AuditInput.advisories`) alongside the bundled corpus; unset ⇒
  bundled-only, unchanged behavior. Never re-read per audit.
- A `known-advisory` entry in `REMEDIATIONS` (§3.17/ADR-0031) is the one
  entry that tells the operator not to waive the finding.

Determinism is unchanged: the corpus is a static committed input and the
rule is a pure function of `(name, version, advisories)`, so it fits the
existing rule pipeline with no new branch in `score()` — see
[ADR-0034](./docs/adr/0034-known-advisory-detection.md).

### 3.21 Known-vulnerability (SCA) detection (Phase 22, ADR-0035)

ADR-0034 deliberately scoped `known-advisory` to exact-match known-malicious
releases, deferring version-range CVE matching. Phase 22 closes that gap:

- **`packages/core/src/vuln-corpus.ts`** — a bundled, static, offline corpus
  (`KNOWN_VULNERABILITIES: readonly VulnAdvisory[]`) of real, publicly
  documented npm CVEs (`lodash` ×2, `minimist`, `axios`, `node-fetch`, `ws`),
  each an affected semver `ranges` array plus CVSS-derived `severity`, an
  advisory `id`, and optional `fixedIn`/`reference` — metadata only, never
  fetched at audit time (invariant #3). `buildVulnIndex` builds a `name →
  VulnAdvisory[]` lookup once; `parseVulnAdvisories`/
  `parseVulnAdvisoriesStrict` mirror ADR-0034's coerce-then-total /
  coerce-then-throw parser split for operator-supplied vulnerabilities.
- **`known-vulnerability` — a pure rule** (`packages/core/src/rules/
  known-vulnerability.ts`, registered in `RULES`; rule count is now **9**).
  Checks the bundled corpus **union** any operator-supplied
  `input.vulnerabilities` for any advisory whose `ranges` the audited
  version satisfies (`semver.satisfies`, total — never throws on a
  malformed range/version, simply matches nothing). Each match emits one
  `vulnerability`-category finding at the advisory's own **faithful**
  severity — a `critical` CVE hard-blocks under the default policy exactly
  like any other critical finding, with no new field in `score.ts`.
- **A new `vulnerability` category**, alongside `metadata`/`network`/
  `secret-exfil`/`install-script`/`obfuscation`/`provenance`.
- **`SENTINEL_VULNERABILITIES` (proxy)** — an optional path to a JSON
  `VulnAdvisory[]` file, read **once at process startup**
  (`resolveVulnerabilities` in `packages/proxy/src/index.ts`), fail-closed
  like `SENTINEL_ADVISORIES` (FATAL exit on an unreadable path, and FATAL on
  a corrupt non-JSON/non-array file via the strict parser — a legitimate
  empty `[]` boots bundled-only). Threaded into the public install audit
  path (`AuditInput.vulnerabilities`) alongside the bundled corpus; unset ⇒
  bundled-only, unchanged behavior. Never re-read per audit.
- **A tree `vulnerabilities` count** — `TreeAggregate.vulnerabilities` (and
  per-row `TreePackageRow.vulnerabilities`) counts packages in an audited
  lockfile carrying at least one `known-vulnerability` finding, surfacing
  SCA exposure across `audit-tree`'s whole dependency graph.
- A `known-vulnerability` entry in `REMEDIATIONS` (§3.17/ADR-0031) plus a
  `vulnerability` `CATEGORY_FALLBACK` entry.
- Adds `semver` (^7.x) as a `@sentinel/core` runtime dependency — the first
  real semver-range parser in the corpus/rule family.

Faithful severity is a deliberate gating stance (diverges from `npm audit`'s
report-don't-block default): tunable via the existing `hardBlockSeverity`/
`allow`/rule-disable/`treeGate` levers, not a new policy field. Determinism
is unchanged: the corpus is static and `semver.satisfies` is a pure, total
function, so the rule fits the existing pipeline with no new branch in
`score()` — see [ADR-0035](./docs/adr/0035-known-vulnerability-sca.md).

---

## 4. The audit engine (`@sentinel/core`)

Deterministic heuristic core + a pluggable LLM adapter. The score is produced
**entirely by the heuristic rules** so it is reproducible and testable; the LLM
only ever *adds* human-readable context and supplementary findings.

### 4.1 Rules

Each rule is a pure function `(files, ctx) => Finding[]`. Phase 1 ships four:

1. **`install-scripts`** — parses `package.json` lifecycle scripts
   (`preinstall`/`install`/`postinstall`). Their mere presence is `info`; a script
   that also shells out, downloads, or reads env/secrets escalates to
   `high`/`critical`. This is the highest-signal rule because it gates *execution*.
2. **`secret-exfil`** — correlates reads of sensitive locations
   (`process.env`, `~/.npmrc`, `.aws/credentials`, `/etc/passwd`, `SSH`,
   `*_TOKEN`/`*_SECRET` enumeration) with an egress sink. Read-without-send is
   `low`; read-correlated-with-send is `critical`.
3. **`network-egress`** — `http`/`https`/`net`/`dns`, `fetch`, websockets,
   `child_process` invoking `curl`/`wget`, hardcoded IPs, suspicious TLDs, and
   base64-encoded URLs.
4. **`obfuscation`** — `eval`, `Function(...)` constructor, `atob`/`unescape`,
   long base64/hex blobs, `\xNN` string arrays, `charCodeAt` decode loops,
   dynamic `require` of decoded strings.

Phase 8 adds a fifth rule (§3.9, ADR-0021):

5. **`provenance`** (`metadata` category) — turns the `signature` and
   `provenance` fields on `PackageMeta` into findings; an `invalid` signature is
   `critical` and hard-blocks.

Phase 13 adds a sixth, name-only rule (§3.13, ADR-0026):

6. **`typosquat`** (`metadata` category) — flags a package name that is a
   likely typosquat (edit-distance/homoglyph match) of a name in a bundled
   static popular-package corpus. `medium` severity; never flags a name
   already in the corpus.

Phase 16 adds a seventh rule (§3.15, ADR-0029):

7. **`release-anomaly`** (`metadata` category) — inert without a
   `releaseContext`; flags a maintainer-set change relative to the previous
   version (`high` for a full turnover, `low` for an addition), a ≥365-day
   dormancy resurrection (`low`), or a first-ever version that already runs
   install scripts (`medium`). A sibling helper, `capabilityNoveltyFindings`,
   is emitted from `buildAudit` rather than `RULES` (it needs the
   post-rules `capabilityDelta`) and flags a newly-added dangerous
   capability relative to the previous version (`medium`).

Phase 21 adds an eighth rule (§3.20, ADR-0034):

8. **`known-advisory`** (`metadata` category) — flags an exact
   `(name, version)` match against a bundled static corpus of
   publicly-documented known-malicious npm releases, unioned with any
   operator-supplied `SENTINEL_ADVISORIES`. `critical` by default —
   hard-blocks under the default policy.

Phase 22 adds a ninth rule (§3.21, ADR-0035):

9. **`known-vulnerability`** (`vulnerability` category) — flags a version
   falling in a semver range from a bundled static CVE corpus, unioned with
   any operator-supplied `SENTINEL_VULNERABILITIES`, at the advisory's
   faithful severity (a `critical` CVE hard-blocks under the default
   policy).

Rules are registered in a list, so adding a rule (typosquat detection, license
risk, provenance) is additive and never touches scoring or the proxy.

### 4.2 Scoring → verdict

Deterministic and monotonic. Start at `100`; each finding deducts
`severityWeight × ruleWeight × (changedFile ? diffMultiplier : 1)`; clamp `[0,100]`.

```
severityWeight: info 0 · low 4 · medium 12 · high 25 · critical 55
verdict:  score ≥ 80 → allow   ·   50–79 → warn   ·   < 50 → block
override: any `critical` finding forces `block` regardless of score
```

Thresholds and weights live in one config object so policy is tunable per-enterprise
in Phase 2 without code changes.

Scoring is **policy-applied at score time** (ADR-0012/0014). `runAudit` produces
policy-independent findings (`severity` + `onChangedFile`); `score(audit, policy)`
applies the enterprise policy's weights, diff multiplier, rule toggles, allow/deny
waivers, thresholds, and hard-block. A waived finding is excluded from the penalty
sum and the hard-block check but stays visible.

### 4.3 LLM adapter

```ts
interface LlmAuditAdapter {
  name: string;
  enrich(input: { files: PackageFile[]; findings: Finding[]; meta: PackageMeta })
    : Promise<{ summary: string; findings: Finding[] }>;
}
```

Default is `NoopLlmAdapter` (returns nothing — engine is fully offline). An
`AnthropicLlmAdapter` stub is wired to read `ANTHROPIC_API_KEY` and runs only in the
**async enrich** phase. Because it can only add findings/context and never sets the
score, a missing key or a model outage degrades gracefully to the heuristic verdict.

---

## 5. Data model

```ts
type Verdict = 'allow' | 'warn' | 'block';
type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
type Category = 'obfuscation' | 'network' | 'secret-exfil' | 'install-script' | 'metadata';

// Findings are policy-independent (no weight); weight/waiver come from score():
interface Finding { ruleId; category; severity; message; onChangedFile: boolean; evidence }
interface ScoredFinding extends Finding { weight: number; waived: boolean; waivedBy?: string }
interface Audit { schema: 3; meta; findings: Finding[]; capabilities; capabilityDelta; engine; auditedAt; durationMs }
// AuditReport is schema 3: findings: ScoredFinding[], plus policy: { version, hash }.

interface EnterprisePolicy {           // signed, per-enterprise (ADR-0012/0014)
  schema: 1; version: string;
  scoring: { severityWeight; diffMultiplier; thresholds; hardBlockSeverity };
  rules: { disabled: string[] };
  allow: { package; rules; reason? }[];   // package: anchored glob; rules: ruleId|category
  deny:  { package; reason? }[];
  privateNamespaces: string[];            // glob patterns for claimed names (ADR-0010/0015)
}

interface PackageMeta {
  name: string; version: string;
  author: string | null; maintainers: string[];
  license: string | null;
  hasInstallScripts: boolean;
  signature: 'verified' | 'invalid' | 'unsigned' | 'unknown';   // verified npm registry-signature status
  provenance: 'verified' | 'invalid' | 'absent' | 'unknown';    // Sigstore attestation-bundle verification (Phase 9, ADR-0022)
  provenanceIdentity?: { workflow; issuer; sourceRepository; ref; builder; commit } | null; // set only when provenance is "verified"
  integrity: string | null;       // SRI of the ACTUAL served bytes (recomputed, not the claimed dist.integrity)
  unpackedSize: number; fileCount: number;
}

type CapabilityKind = 'network' | 'filesystem' | 'process' | 'native' | 'env';
interface Capability { kind: CapabilityKind; target: string; evidence: Evidence[]; }
interface CapabilityDelta { added: Capability[]; removed: Capability[]; }

// Cross-version context for the release-anomaly rule + capability-novelty helper
// (Phase 16, ADR-0029). All optional; absent ⇒ both are inert. Derived from the
// packument in buildReleaseContext(pm, version) — never the clock.
interface ReleaseContext {
  previousVersion?: string; previousMaintainers?: string[];
  previousPublishedAt?: string; currentPublishedAt?: string;
  versionCount?: number;
}

interface AuditReport {
  schema: 3;
  meta: PackageMeta;
  score: number;                  // 0–100 (100 = safe)
  verdict: Verdict;
  findings: ScoredFinding[];
  capabilities: Capability[];
  capabilityDelta: CapabilityDelta | null;
  policy: { version: string; hash: string };    // signing/verification (ADR-0012/0014)
  engine: { version: string; rules: string[]; llm: string | null; mode: 'full' | 'diff' };
  llmSummary: string | null;
  auditedAt: string;              // ISO-8601
  durationMs: number;
}
// AuditReport is schema 3: findings: ScoredFinding[], plus policy: { version, hash }.
// Approval state is NOT in the report — it is mutable proxy state in ApprovalStore,
// keyed by integrity (see ADR-0011/0013).
// Runtime-violation state is likewise NOT in the report — it is mutable proxy state
// in ViolationStore, keyed by integrity, applied as a serve-time overlay (ADR-0023).
// Pending approval requests are a third, separate store — ApprovalRequestStore,
// keyed by integrity, written by POST /-/approval-requests (an MCP/agent ask,
// never a grant) and cleared when a human's POST /-/approvals decision lands
// for that integrity (ADR-0024).
```

Storage in Phase 1 is a pluggable `AuditStore` (in-memory + JSON-file impl). The
schema maps 1:1 onto a `audits(package, version, integrity PK, report JSONB)` table
for the eventual Postgres backing — `integrity` as primary key gives free immutable
caching.

---

## 6. CLI ↔ npm integration

Five integration modes, all non-invasive:

1. **`sentinel audit <pkg>[@version]`** — calls the proxy's `/-/audit` API and
   prints the pre-install panel: unpacked size, author, signature status, score,
   verdict, and findings. No install, no execution. Ideal for an agent to call as a
   tool before deciding to install.
2. **`sentinel install <args…>` / `sentinel npx <args…>`** — runs the real
   `npm`/`npx` with `--registry http://localhost:4873` (the proxy) injected, so all
   resolution flows through Sentinel. The proxy's `x-sentinel-verdict` headers and
   the audit store give post-hoc visibility; a `block` policy makes npm fail closed
   on a `403`.
3. **`sentinel install --enforce <args…>`** — extends mode 2 by also enforcing
   approved capabilities at runtime. Sets `npm_config_script_shell` to the shipped
   `sentinel-script-shell` wrapper so every lifecycle script in the tree runs under
   `createSandbox()` (§3.7). Scripts with unapproved or undeclared capabilities are
   denied at the kernel level even when the static audit passed.
4. **`sentinel explain <package> <version>` (Phase 18, ADR-0031)** — calls
   the proxy's `GET /-/explain/:pkg/:version`, which audits the version,
   runs the pure `remediate()` guidance mapping over the resulting report,
   and walks back a bounded (≤10) window of prior versions for the newest
   one that audits `allow`. `formatExplain` (`packages/cli/src/format.ts`)
   prints per-finding actions, a "pin to" suggestion when a last-known-good
   version is found, and a ready `sentinel approve … --reason "..."` waiver
   command. Advisory only — see §3.17.
5. **`sentinel-mcp` (Phase 11, ADR-0024)** — a stdio MCP server
   (`packages/mcp`, `@modelcontextprotocol/sdk`) for agent hosts that speak
   MCP instead of shelling out to the CLI. `createMcpServer(client)` registers
   seven tools against a `ProxyClient` — a thin fetch wrapper over the proxy's
   `/-/audit`, `/-/manifest`, `/-/audit-tree`, `/-/violations`, `/-/explain`, and
   `/-/approval-requests` endpoints, resolving `latest` from the packument's
   `dist-tags` when a version is omitted. Six tools are read-only
   (`sentinel_audit`, `sentinel_audit_tree`, `sentinel_capabilities`,
   `sentinel_check_provenance`, `sentinel_list_violations`, `sentinel_explain`
   — Phase 18); the seventh, `sentinel_request_approval`, is the only write
   path and records a
   **pending** entry in the new `ApprovalRequestStore` via `POST
   /-/approval-requests` — it can never grant approval itself. This is a
   deliberate privilege boundary: the agent requests, only a human grants
   through the existing `POST /-/approvals`, and there is no auto-approve or
   clear-quarantine tool. Because every read tool calls the same
   `/-/audit`/`/-/manifest` endpoints the CLI and the tarball serve gate use,
   the verdict an agent sees is byte-identical to what a real install would
   see; a `ProxyClient` failure (unreachable proxy, non-OK response) throws
   `ProxyError` rather than ever fabricating a verdict, and the MCP layer
   performs zero scoring of its own (invariant #1 untouched). `parseLockfile`
   (used by `sentinel_audit_tree`) moved from `@sentinel/cli` to
   `@sentinel/core` this phase so both packages can share it without `mcp`
   tripping `cli`'s own entrypoint guard.

The cleanest hook is registry redirection (`.npmrc` `registry=` or `--registry`)
rather than an npm wrapper, because it works identically across npm, yarn, pnpm,
bun, and npx and survives transitive dependency resolution — every tarball in the
tree is fetched through the proxy, not just the top-level request.

---

## 7. Stack justification

- **Node + TypeScript.** The artifacts under audit are npm packages; staying in-runtime
  means we parse `package.json`, resolve semver, and read tarballs with the same
  tooling npm uses, and the CLI ships as an npm package itself. Types make the
  `AuditReport` contract (shared across four packages) the source of truth.
- **Express** for the proxy — the registry surface is a handful of GET routes;
  Express keeps it boring and readable. Streaming tarballs is first-class.
- **`tar` + built-in `zlib`/`fetch`** — no custom archive parsing, no HTTP client dep.
- **npm workspaces** over a heavier monorepo tool — zero extra tooling, native to the
  ecosystem we're securing.
- **`node:test` + `tsx`** — run TS tests directly, no build step in the loop. The
  engine's determinism is what makes the "we actually catch the malware" test a
  hard assertion rather than a vibe.
- **Single-file HTML dashboard** — no SPA build; the proxy serves one page that
  reads the audit API. Right-sized for an MVP wedge.

LLM placement is the one opinionated choice: it is an **async enrichment adapter**,
never the scorer. Enterprises buying a security gate need the verdict to be
deterministic, auditable, and offline-reproducible; an LLM in the hot path would be
none of those. The adapter interface still lets us add model-driven findings where
they add value (explaining *why* an obfuscated blob is suspicious in plain English).
