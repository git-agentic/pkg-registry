# CLAUDE.md — working agreement for the Sentinel repo

Read this before changing code. It captures the invariants that make this a
security product rather than a linter. See [ARCHITECTURE.md](./ARCHITECTURE.md)
for the full design, [docs/adr/](./docs/adr/) for the decision log (why each
invariant below exists, with the options we rejected), and [README.md](./README.md)
for how to run things.

## What this is

Sentinel is an **agent-auditable security layer for npm**. Phase 1 (built) is a
transparent **auditing proxy** in front of `registry.npmjs.org` that scores every
tarball and attaches a verdict before install-time code can run. Phase 2 (built) added
the install-time permission manifest + approval gate, signed per-enterprise policy, and
private-namespace registry (packages scoped to claimed namespaces are served only from
the private store).
Phase 3 adds **`@sentinel/sandbox`** — a macOS Seatbelt / Linux bubblewrap runner, selected
by `createSandbox()`, that enforces the **filesystem, network, and env** portions of a
package's approved capability manifest at install time (`sentinel run-scripts`). Note: as
of Phase 28 the `process` kind's exec **floor** is **enforced on macOS** (exec
deny-by-default, ADR-0042); as of Phase 29 the exfil-tool **carve-out** is enforced on
Linux too via `/dev/null` masking (ADR-0043); and as of Phase 2 (Landlock) the exec
**floor** is also **enforced on Linux where a from-source Landlock helper is available**
(fail-open, pre-checked detection — advisory otherwise, ADR-0044). `native` is
advisory-only on both platforms by decision. A cross-platform exec floor now exists;
closing #8 is left to the controller after final review.
Synthetic malware fixtures are still scored-as-text and
**never executed**; enforcement is tested with benign probe packages.
Phase 4 hardened the sandbox: fail-closed env-var scrubbing via an `env` capability
(`--approve env:NAME`) + `file-write*` denies on credential/persistence paths.
Phase 5 adds **Linux enforcement** via bubblewrap (`bwrap`): `createSandbox()` selects
the backend by platform; same approved-capability model and `SENSITIVE_PATHS` deny list,
same fail-closed contract. CI installs `bwrap` and relaxes the Ubuntu 24.04
unprivileged-userns restriction so the Linux effect-tests run on `ubuntu-latest`.
Phase 6 adds **`sentinel install --enforce`**: script-shell interposition via
`npm_config_script_shell` wraps every lifecycle script in the tree under `createSandbox()`,
with credential-screened env and approval resolution per dependency (ADR-0019).
Phase 7 adds **`sentinel audit-tree`**: a whole-tree lockfile gate. It parses an npm
`package-lock.json`, audits every resolved package through the proxy (`POST /-/audit-tree`,
fan-out over the integrity cache), rolls a worst-case aggregate gated by the policy's
`treeGate` (default `block`), and exits non-zero on a gated tree (ADR-0020).
Phase 8 adds **offline npm registry-signature verification**: `verifyRegistrySignature`
checks the ECDSA P-256/SHA-256/DER registry signature against a configured, keyid-matched
key set (`NPM_SIGNING_KEYS`) — a static input, never fetched at audit time (invariant #3).
`PackageMeta.signatureStatus` is un-flattened into `signature` (`verified|invalid|unsigned|unknown`)
and `provenance` (`present|absent`); a pure `provenance` rule surfaces the status as findings
(`invalid` is critical and hard-blocks), and an optional `requireSignature`/`requireProvenance`
policy gate lives beside `deny` in `score.ts` (ADR-0021).
Phase 9 upgrades `provenance` from presence-only to a deep verify: `verifyProvenance`
(pure, offline, never throws) checks fetched attestation bundles against pinned trust
material in `packages/core/trust/`, producing `verified|invalid|absent|unknown` with
subject-digest binding to the *actual* served bytes — `runAudit` recomputes integrity from
bytes in hand and a claimed≠actual mismatch is a critical `integrity-mismatch` finding, with
the proxy caching by the actual hash. `requireProvenance` now demands `verified`, and a new
`provenanceIdentities` policy gate in `score.ts` fail-closed-ANDs per-pattern identity
requirements (repo/workflow/builder/issuer) against the attestation's authenticated identity;
a verification error over a *present* bundle maps to `invalid`, never `unknown`, so a
crash-bundle can't fail open past the gate (ADR-0022).
Phase 10 turns the enforcing sandbox into a **sensor**: `computeDenySet` (shared with the
profile/`bwrap` generators, non-drift-tested) plus `classifyViolation` (pure, total, never
throws) infer a `confirmed`/`suspected`/`null` runtime violation from a sandboxed child's
failure — `null` on a swallowed denial (`exitCode === 0`) or a permission error outside the
deny set (the false-positive filter). `sentinel-script-shell` best-effort reports a detected
violation to `POST /-/violations`; the proxy's `ViolationStore` records it integrity-keyed,
and `confirmed` revokes any standing approval and quarantines. Quarantine is a **serve-time
overlay** (`applyQuarantine` in `server.ts`) — it forces `block` and prepends a `weight: 0`
finding on a *copy* of the served report, never mutating the cached score (invariant #1).
Best-effort/containment-unchanged: a swallowed denial evades telemetry, not containment —
the sandbox still denied the syscall exactly as it did before Phase 10 (ADR-0023).
Phase 11 adds an **agent-native MCP surface** (`packages/mcp`, `sentinel-mcp` bin):
`createMcpServer` is a thin stdio client over the running proxy — five read tools
(`sentinel_audit`, `sentinel_audit_tree`, `sentinel_capabilities`,
`sentinel_check_provenance`, `sentinel_list_violations`) plus one write tool,
`sentinel_request_approval`, that only ever records a **pending** entry in the new
`ApprovalRequestStore` (`POST /-/approval-requests`) — the agent requests, a human
still grants via the existing `POST /-/approvals`, and there is no auto-approve or
clear-quarantine tool. `parseLockfile` moved from `@sentinel/cli` to `@sentinel/core`
so `mcp` and `cli` can share it without tripping `cli`'s own entrypoint guard. The MCP
layer does zero scoring; a `ProxyClient` failure throws rather than fabricating a
verdict (invariant #1 untouched, ADR-0024).
Phase 12 adds **signed role-token control-plane auth**: `signToken`/`verifyToken`
(`packages/core/src/auth.ts`) mint/check offline-verifiable Ed25519 tokens
(`operator | agent | publisher`), opt-in via `SENTINEL_AUTH_PUBKEY` (unset ⇒
open mode, all existing behavior unchanged). `makeAuthz(...).requireRole([...])`
gates the six mutating routes — `POST/DELETE /-/approvals*`, `POST /-/violations`,
`DELETE /-/violations/:integrity`, `POST /-/approval-requests`, and publish —
with 401 (no/bad/expired token) vs 403 (valid token, wrong role); every read
(incl. `POST /-/audit-tree`) stays open. This enforces ADR-0024's request-not-grant
boundary at the HTTP layer for the first time: an `agent` token now gets a hard
403 on `POST /-/approvals`, not just an absent tool (ADR-0025).
Phase 13 adds **supply-chain identity heuristics**: a pure `typosquat` rule
(`packages/core/src/rules/typosquat.ts`) flags a package name that's a likely
edit-distance/homoglyph match against a bundled static popular-name corpus
(`typosquat-corpus.ts`), and a score-time `dependencyConfusion` check in
`score.ts` flags a public look-alike of one of the operator's claimed
`privateNamespaces` — both share `name-distance.ts`'s canonical-fold +
Damerau-Levenshtein helpers, both are `metadata`-category **weighted**
findings (never a hard block on their own), both are deterministic and
inert by default (no `privateNamespaces` ⇒ the confusion check never fires),
and the confusion check never flags the legitimate claimed package itself
(ADR-0026).
Phase 14 adds **ecosystem breadth + SBOM** to `audit-tree`: `parseAnyLockfile`
(`packages/core/src/lockfile.ts`) dispatches by filename/content sniff across
npm `package-lock.json`, `yarn.lock` (bespoke v1 text parser + YAML for
berry), and `pnpm-lock.yaml` (YAML, v5/v6/v9 key shapes, peer-suffix
stripped) into the same `Coordinate[]`; `audit-tree --sbom <file>` writes a
pure, injected-`now` CycloneDX 1.6 BOM (`toCycloneDX` in
`packages/core/src/sbom.ts`, `sentinel:*` properties carrying verdict/score/
top-finding/integrity-mismatch); the proxy route cross-checks a claimed
lockfile integrity against Phase 9's recomputed served hash and force-blocks
a mismatch (`TreePackageRow.integrityMismatch`); `--fail-on-error` opts the
tree into gating on unresolvable-package rows (`aggregateTree`'s
`failOnError`, default off — ADR-0020's fail-open stance unchanged). Parsing
and SBOM export are pure; the per-package score path is untouched
(ADR-0027).
Phase 15 adds **durable audit history + observability**: `HistoryDb`
(`packages/proxy/src/history-db.ts`) is an opt-in (`SENTINEL_HISTORY_DB=<path>`)
wrapper over the built-in `node:sqlite`, loaded lazily via `createRequire`
inside the constructor so a plain import never fires the experimental
warning. It write-throughs (best-effort, invariant #6) beside the existing
in-memory hot cache — `AuditStore.put`/`ViolationStore.record` gained an
optional trailing `history?` param — into an integrity-keyed upsert-ignore
`audit_events` table and an append-only `violation_events` table. Three
open, un-role-gated reads (`GET /-/metrics`, `GET /-/history`,
`GET /-/violations/timeline`, `501 { enabled: false }` when disabled),
`sentinel stats`/`sentinel history` in the CLI, and a dashboard
"Observability" section (verdict trend, top-flagged, violation timeline)
sit on top. Unset env var ⇒ zero behavior change and `node:sqlite` is
never imported (ADR-0028).
Phase 16 adds **maintainer & release-anomaly signals**, completing the
maintainer-anomaly gap ADR-0026 deferred: a pure `release-anomaly` rule
(`packages/core/src/rules/release-anomaly.ts`, registered — rule count now
7) reads a new optional `AuditInput.releaseContext` and flags a
maintainer-set change vs. the previous version (`high` on full turnover,
`low` on addition), a ≥365-day dormancy resurrection (`low`), and a
first-ever version that already runs install scripts (`medium`); a sibling
pure helper, `capabilityNoveltyFindings` (`rules/capability-novelty.ts`),
is emitted from `buildAudit` — not the rule pipeline, since it needs the
post-rules `capabilityDelta` — and flags a newly dangerous
network/process capability vs. the previous version (`medium`). The server
derives `releaseContext` for free from the packument it already fetched
(`buildReleaseContext` in `server.ts`, from the packument's `time` +
per-version `maintainers`) — no new network call. All four findings are
`metadata`-category **weighted**, never a standalone hard block; all read
only immutable packument data (no `Date.now()`/wall-clock — invariant #1
untouched) and are inert without a `releaseContext` (ADR-0029).

Phase 17 adds a **CI-native GitHub Action**: a new `@sentinel/action`
workspace (bin `sentinel-ci`) whose `runCi` self-boots the proxy in-process
with an injected upstream (`NpmUpstream` in production, `LocalFixtureUpstream`
in tests — never a network call in the test suite), runs the existing
`/-/audit-tree` flow against the caller's lockfile, writes a CycloneDX SBOM
and GitHub-native outputs/step-summary/annotations, and exits per `fail-on`
(`block` default, `warn`, or `none` for an observe-only onboarding path). A
thin composite `action.yml` uploads the SBOM as a build artifact and posts an
idempotent PR comment found by a `<!-- sentinel-report -->` marker. A
root-cause fix — entrypoint-guarding `packages/proxy/src/index.ts`'s `main()`
the same way `@sentinel/mcp`'s bin already is — made the self-boot
import-safe: importing `@sentinel/proxy` for its exports no longer boots a
second server as a side effect. The Action only runs the audit; scoring is
untouched (ADR-0030).
Phase 18 adds **actionable remediation**: a pure `remediate(report)`
(`packages/core/src/remediation.ts`) maps each finding to a per-`ruleId`
`{summary, action}` (category/generic fallback, never throws) ordered
worst-first, plus a waiver template reusing Phase 11's request-not-grant
`POST /-/approval-requests` payload when the verdict isn't `allow`; a new
`GET /-/explain/:pkg/:version` audits, remediates, and walks back a bounded
(≤10) prior-version window for the newest `allow`-verdict release, off the
inline gate. Surfaced via `sentinel explain <package> <version>`, a PR-comment
"how to fix" column (`TreePackageRow.topFindingRuleId` + `remediationHint`),
and an MCP `sentinel_explain` read tool. Advisory-only — nothing here writes
to a lockfile or auto-selects a version; `remediate` never feeds `score.ts`
(invariant #1, ADR-0031).
Phase 19 adds **signed audit attestations (VSA)**: a pure `attest.ts`
(`packages/core/src/attest.ts`) builds an in-toto `Statement` v1 over an
audited tree (`buildAuditStatement` — subject = SBOM sha256 digest,
predicate = a VSA-style summary of verdict/gated/counts/`policyHash`),
wraps it in a DSSE envelope, and Ed25519-signs the PAE (`signAttestation`,
reusing `signPolicy` — no new crypto dep). `verifyAttestation` is
pure/offline/total/fail-closed (never throws; tampered signature, wrong
predicate, or an SBOM/policy/verdict mismatch each reject with a distinct
reason, never a silent pass). Signing is operator-side, never on the proxy:
`sentinel attest-keygen --out <prefix>` (Ed25519 keypair — note the
sibling-command name, not `attest keygen`, a commander-15
`requiredOption` interaction), `sentinel attest <lockfile> --key --out
[--sbom]` (audit → SBOM → signed attestation), and `sentinel
verify-attestation <att> --key [--sbom --policy-hash --require]` (offline
deploy gate, non-zero exit on rejection). The proxy's only change is
setting `TreeAuditResult.policyHash` on the `/-/audit-tree` response so an
attestation can bind to the scoring-time policy hash. Determinism:
injected `now` + Ed25519 ⇒ byte-identical envelope; scoring is untouched
(invariant #1, ADR-0032).
Phase 20 adds **policy authoring + impact preview**: a pure `lintPolicy`
(`packages/core/src/policy-lint.ts`) structurally + semantically inspects
an `EnterprisePolicy` — errors (inverted thresholds, invalid severities,
a deny/allow conflict) an operator shouldn't sign vs. warnings
(non-monotonic weights, an aggressive `hardBlockSeverity`) that are legal
but suspicious; `HistoryDb.allReports` (bounded, newest-first) feeds a new
`POST /-/policy/preview` that replays every stored audit under a candidate
policy through the *same* pure `score()` the live gate calls and reports
verdict-transition counts plus the worst flipped packages — a dry run that
never applies, stores, or signs the candidate, requiring history (`501`
when disabled). `sentinel policy init/validate/preview` round out the
authoring loop beside the existing `keygen/sign/verify`; `validate` exits
non-zero only on lint errors, making it a clean CI gate (ADR-0033).
Phase 21 adds **known-advisory (known-malicious) detection**: a bundled,
static, offline `advisory-corpus.ts` (`KNOWN_ADVISORIES` — real, verified
GHSA ids for publicly-documented compromised releases like `event-stream
3.3.6`) plus a pure `known-advisory` rule (registered — rule count is now
**8**) that critical-hard-blocks an exact `(name, version)` match against
the bundled corpus union any operator-supplied advisories. The proxy loads
an optional `SENTINEL_ADVISORIES` JSON file once at startup (fail-closed,
FATAL on an unreadable path, like `SENTINEL_AUTH_PUBKEY`) and threads it
into the public install audit path; unset ⇒ bundled-only, unchanged.
`scripts/make-advisories.ts` regenerates the corpus from a local OSV/GHSA
export — never a live fetch on the audit path (invariant #3, ADR-0034).
Phase 22 adds **known-vulnerability (semver-range CVE) detection**, closing
the gap ADR-0034 deferred: a bundled, static, offline `vuln-corpus.ts`
(`KNOWN_VULNERABILITIES` — 6 real, web-verified npm CVEs across `lodash`,
`minimist`, `axios`, `node-fetch`, `ws`, each an affected semver range +
CVSS-derived severity + `fixedIn`) plus a pure `known-vulnerability` rule
(registered — rule count is now **9**) that matches via `semver.satisfies`
and emits a finding at the advisory's own **faithful** severity — a critical
CVE hard-blocks under the default policy, riding the existing machinery with
no new policy field. A new `vulnerability` category; the proxy loads an
optional `SENTINEL_VULNERABILITIES` JSON file once at startup (fail-closed,
FATAL on an unreadable path or a corrupt non-JSON/non-array file, same
posture as `SENTINEL_ADVISORIES`) and threads it into the public install
audit path; `audit-tree` gains a `vulnerabilities` count. Adds `semver`
(^7.x) as a `@sentinel/core` dependency. `scripts/make-vulns.ts` regenerates
the corpus from a local OSV/GHSA export — never a live fetch (invariant #3,
ADR-0035).
Phase 23 closes a **network trust boundary** gap an external audit found: a
pure `packages/proxy/src/net-config.ts` adds `assertAllowedTarballUrl`,
`parseTarballOrigins`, `parsePublicBaseUrl`, and `isLoopbackHost`.
Outbound, `NpmUpstream.getTarball` now pins every tarball fetch to the
configured registry origin (`SENTINEL_REGISTRY`) or an entry in the optional
`SENTINEL_TARBALL_ORIGINS` allowlist — a disallowed origin is never fetched
at all, rejected up front as `HttpError(502)`, so a poisoned packument can't
steer the proxy at internal services (SSRF). Inbound, `createServer` takes an
optional `publicBaseUrl`; set via `SENTINEL_PUBLIC_BASE_URL` it drives every
packument `dist.tarball` rewrite regardless of the request's Host, closing
the Host-header-spoofing path — unset, the rewrite falls back to a
loopback-derived base only for a loopback Host (`localhost`, `127.0.0.0/8`,
`[::1]`), and refuses any other Host with **421**. Both env vars parse
fail-closed at proxy startup (malformed ⇒ FATAL, same posture as
`SENTINEL_AUTH_PUBKEY`). Scoring, caching, and the packument passthrough are
untouched (invariants #1–#5, ADR-0036).
Phase 24 adds **resource robustness**: `/-/audit-tree` now dedupes
coordinates by `name@version` before fan-out (auditing each distinct
coordinate once, re-expanding to per-request rows in request order —
behavior-neutral since `auditVersion` is deterministic) and returns **413**
over `SENTINEL_MAX_TREE_PACKAGES` (default 5000) instead of silently
truncating; dedupe keys on `name@version` only, so two coordinates sharing a
`name@version` but claiming different integrity would only have the first
checked (well-formed lockfiles never do this). A shared byte-counting reader,
`readBodyCapped` (`packages/proxy/src/limits.ts`), replaces `NpmUpstream`'s
unbounded `arrayBuffer()`/`json()` reads — reject-up-front on an over-cap
`content-length`, abort mid-stream on an over-cap running total —
bounding tarball fetches to `SENTINEL_MAX_TARBALL_BYTES` (default 256 MB)
and packument/attestation fetches to `SENTINEL_MAX_PACKUMENT_BYTES` (default
128 MB); over-cap is a 502, or a null attestation (fail-open unchanged). An
in-flight `name@version` map in `server.ts` coalesces concurrent uncached
public audits for the same coordinate onto one pipeline (cache-stampede
fix) — the integrity-keyed `store` stays the durable cache (invariant #4);
the map is transient and clears on settle. A pure token-bucket
`RateLimiter` (`packages/proxy/src/rate-limit.ts`, injectable clock, keyed by
`req.socket.remoteAddress` — not `X-Forwarded-For`) opt-in gates
`POST /-/audit-tree`, `GET /-/explain/*`, and `POST /-/policy/preview` when
`SENTINEL_RATE_LIMIT_RPM` is set; over-limit ⇒ 429 + `Retry-After`. The
install-gate paths are never rate-limited. (The same opt-in gate also fronts
the auth-performing control-plane mutating routes — approvals, violations,
approval-requests, publish — and the dashboard index, as brute-force defense;
added when clearing CodeQL `js/missing-rate-limiting`.) All four env vars parse
fail-closed at startup (malformed ⇒ FATAL). Scoring, caching, and the
packument passthrough are untouched (invariants #1–#6, ADR-0037).
Phase 25 Slice 1 flips the sandbox's write posture from allow-default to
**deny-by-default**: a directional `pathCovers` (`packages/sandbox/src/
path-cover.ts` — an approval now covers exactly its own subtree, never an
ancestor) plus a fixed, non-configurable `writeAllowFloor`
(`packages/sandbox/src/write-floor.ts` — cwd, tmpDir, `/tmp`, `/dev`,
`~/.node-gyp`, `~/.cache/node-gyp`, `~/.npm/_logs`) back a blanket write deny
on both backends: Seatbelt's `generateProfile` emits `(deny file-write*)` +
`(allow file-write* …floor…grants)` (SBPL last-match-wins), and bwrap's
`generateBwrapArgs` mounts root read-only (`--ro-bind / /`) and re-binds the
floor/Grants read-write via `--bind-try`. `SENSITIVE_PATHS` write entries
re-emit as a carve-out *after* the floor/Grant allow on both backends, so a
persistence path stays denied even under an allowed ancestor unless a Grant
explicitly covers it. `/dev` is deliberately asymmetric: it's in the shared
floor for Seatbelt (no isolated-device-tree primitive; not a regression from
the prior allow-default posture) but bwrap's generator excludes it from the
re-binds since `--dev /dev` already gives an isolated writable `/dev` and
re-binding the host one would overmount that isolation. A bare-relative
approved `filesystem:` target now resolves against `homeDir` (`expandHome`
widened) when emitted as a positive write Grant. Reads are unchanged this
slice — `$HOME`-read-deny is a separate, gated Slice 2 follow-up. Scoring
and the approval/manifest model are untouched (invariants #1–#6, ADR-0038).
Phase 25 Slice 2 flips `$HOME` reads to **deny-by-default** as well,
completing the ADR-0016/0017/0018 supersession: a pure `readAllowList`
(`packages/sandbox/src/read-allow.ts`, `{ nodePrefix, projectRoot }`)
re-opens exactly the node runtime's install prefix
(`nodeInstallPrefix(execPath)` — a node-under-`$HOME` runtime like
nvm/fnm/volta still loads its stdlib), the project root
(`resolveProjectRoot(cwd, INIT_CWD)` — trusts `INIT_CWD` when absolute, else
walks up to the nearest ancestor `package.json`, else `cwd` — so `require()`
resolves across the whole project tree), and `~/.node-gyp`/`~/.cache`; system
paths outside `$HOME` are unaffected. Two new sandbox inputs feed this:
`nodePrefix` (from `process.execPath`) and `projectRoot` (from `INIT_CWD`,
now an optional `Sandbox.run` parameter, default `cwd`). Seatbelt's
`generateProfile` emits three SBPL layers (last-match-wins): `(deny
file-read* (subpath $HOME))`, then `(allow file-read-metadata (subpath
$HOME))` — **load-bearing**, probe-verified: without it `require()`'s
lstat/stat traversal breaks with EPERM — then `(allow file-read*
…read-allow-list…)`; the existing SENSITIVE read carve-out
(`/etc/passwd`/`/etc/shadow`) is unchanged and still wins last. bwrap's
`generateBwrapArgs` does `--tmpfs $HOME` (empties it, denying reads), then
re-binds the read-allow list read-only (`--ro-bind-try`), then re-binds the
Slice 1 write floor read-write on top — mount order matters, the broad ro
project bind must precede the narrow rw `cwd` bind. Accepted telemetry
asymmetry (extends ADR-0023, CI-confirmed): Seatbelt's read-deny EPERMs,
which `classifyViolation` reports as `confirmed`; bwrap's tmpfs makes the
path ENOENT, which is not classified — the read is **contained** on both
backends regardless, only the *report* differs. Scoring and the
approval/manifest model are untouched (invariants #1–#6, ADR-0038).

Phase 26 Part B closes #9 (violation sensing ≠ enforcement): `ViolationStore`
no longer derives quarantine from a client-supplied `confidence` field on
`POST /-/violations`. Recording is unchanged and always allowed — every
report, confirmed or suspected, authenticated or not, is still stored and
surfaced. Quarantine — forcing the served verdict to `block` — is now a
server decision, opt-in via `SENTINEL_AUTO_QUARANTINE=1` and effective only
when `SENTINEL_AUTH_PUBKEY` is also set (auth disabled ⇒ the flag is inert;
setting the flag without auth configured is a startup FATAL, same posture as
the other fail-closed env vars). Default is unset ⇒ record-only: violations
are visible but never auto-quarantine. This closes the anonymous/forged
fleet-wide-DoS path an unauthenticated `confirmed` report previously had
against any already-audited integrity, while leaving ADR-0023's sensing,
classification, and serve-time-overlay mechanics untouched (ADR-0040,
supersedes ADR-0023's auto-quarantine default only).
Phase 26 Part A closes a **decompression-bomb** gap ADR-0037 didn't cover:
ADR-0037 bounded compressed fetch bytes, not what happens after — a small
`.tgz` within the fetch cap can still gzip-bomb into unbounded unpacked bytes
or entry count. `extractTarball` (`packages/core/src/extract.ts`) now takes
`maxUnpackedBytes`/`maxFileCount` caps (defaults 1 GiB / 100k) and counts
decompressed bytes at the gunzip boundary (an owned `node:zlib` decompression,
not per-tar-entry) — over-cap sets `truncated: true` and calls
`gunzip.destroy()` to halt decompression, catching bytes that never surface
as a tar `entry` event. `runAudit` synthesizes a critical `resource-abuse` finding
(category `resource`) on a truncated **current** tarball, hard-blocking under
the default policy; a truncated baseline (diff mode) degrades the diff
without itself blocking. Two new fail-closed, load-once-at-startup env vars,
`SENTINEL_MAX_UNPACKED_BYTES`/`SENTINEL_MAX_FILE_COUNT`, follow the exact
`resolvePositiveInt` posture of ADR-0037's four. No wall-time cap — the
byte/count caps are sufficient and a wall-clock cutoff would break
determinism (invariant #1). Extends, does not supersede, ADR-0037
(ADR-0039).

Phase 27 closes the remaining external-review gaps (#10/#11/#12) not covered
by ADR-0040: every third-party GitHub Action `uses:` (`.github/workflows/*`,
`action.yml`) is now pinned to a commit SHA with a `# vX.Y.Z` comment instead
of a mutable tag (#10, CI hygiene — CONTRIBUTING.md documents the update
path), `extractTarball` (`packages/core/src/extract.ts`) now tracks
counted-but-unscanned executable-looking files in `ExtractResult.unscanned`
— large code (>2 MB `.js`/`.ts`/etc, capped at 100 entries) and native/wasm
binaries — and `runAudit` synthesizes a `metadata`-category `low`
`unscanned-content` finding (`medium` when a native binary co-occurs with a
detected install script), making the always-existing >2 MB/non-text scan
blind spot non-silent without ever hard-blocking alone; it's synthesized
inline in `runAudit`, the same as Phase 26 Part A's `resource-abuse`, **not**
a registered `Rule` — the rule count is unchanged (#11). `verifyProvenance`
(`packages/core/src/provenance.ts`) now requires at least one attestation to
carry the SLSA v1 predicate for `status: "verified"`; a cryptographically
valid attestation list with no SLSA v1 predicate (e.g. a publish-only
attestation) maps to `"unknown"` — reusing the existing status, not a new
value — with a reason string, since real npm-provenance-published packages
already carry a SLSA v1 bundle and are unaffected. `requireProvenance` (still
demands exactly `verified`) and the `invalid`-on-verification-error mapping
are unchanged; a policy setting `provenanceIdentities` without
`requireProvenance` now lets a non-SLSA package through the identity gate
(which exempts `unknown` per ADR-0022 by design) — operators should pair the
two gates (#12). ADR-0041 extends ADR-0039 and ADR-0022; supersedes neither.

Phase 28 enforces the `process` capability on macOS: Seatbelt gains an
**exec deny-by-default** layer mirroring Phase 25's write layering —
`(deny process-exec*)`, re-allow a fixed `execAllowFloor` (`packages/sandbox/
src/exec-floor.ts`: /bin, /usr/bin, /usr/sbin, node prefix, project root,
/Library/Developer, /Applications/Xcode.app, /opt/homebrew, /usr/local) plus
approved `process:` path-Grants, then re-deny a curated `SENSITIVE_EXECUTABLES`
carve-out (`sensitive-executables.ts`: curl, wget, nc, ncat, socat, osascript,
scp, sftp — fixed literals across the floor's bin dirs, no PATH resolution)
unless a command/wildcard Grant lifts it. Grant shapes: bare word ⇒ lifts that
command's carve-out; contains `/` or starts `~` ⇒ path Grant (guarded by
`isSafeGrantTarget`); `*` ⇒ lifts the whole carve-out, opens no paths.
`process-fork` stays allowed. `computeDenySet` mirrors the exec sets
(non-drift-tested) and `classifyViolation` attributes denied execs, using the
write floor to disambiguate the shell's ambiguous "Operation not permitted"
line (writable location ⇒ confirmed; outside both floors ⇒ suspected).
Accepted residual: projectRoot is in the floor, so a package can exec a binary
written into its own tree (mitigated by `unscanned-content` + `process`
scoring). `native` is formally advisory-only on both platforms. Scoring
and the approval model are untouched (invariants #1–#7, ADR-0042).
Phase 29 adds **Linux exec hardening in pure TypeScript, floor still
advisory**: a decisive check found bwrap has no `noexec` mount mechanism
(confirmed against the `bwrap(1)` man page and the open, unimplemented
containers/bubblewrap#349), and a CAP_SYS_ADMIN inner-remount was rejected as
a security regression — so there is no Linux exec floor equivalent to
Phase 28's macOS one. What Phase 29 does ship: `generateBwrapArgs` masks each
`SENSITIVE_EXECUTABLES` literal (curl, wget, nc, ncat, socat, scp, sftp —
`osascript` is macOS-only) with `--ro-bind /dev/null <literal>` (execve on
`/dev/null` fails EACCES) unless an approved `process:` Grant covers it,
resolving merged-usr symlink ancestors (e.g. Debian/Ubuntu's `/bin` →
`/usr/bin`) first so the bind always targets a mountable node.
`computeDenySet`'s Linux branch models no floor (only the masked carve-out
literals), so `classifyViolation`'s Linux branch only ever `confirmed`s a
process violation on a masked literal — never a `suspected` floor guess. A
binary dropped into a writable location can still exec on Linux *when the
Landlock floor is inactive* (advisory fallback); it stays filesystem+network
confined (no credential read, no exfil without an approved `network` cap). The
enforced Linux exec floor that closes this gap where Landlock is available
lands in Phase 2 below (ADR-0044).
Scoring and the approval model are untouched (invariants #1–#7, ADR-0043).
Phase 2 (Landlock) closes the Linux exec-floor gap ADR-0043 left open, **where
Landlock and a compiled toolchain are available — advisory otherwise**: a
~100-line, self-contained C helper (`packages/sandbox/native/landlock-exec.c`,
inline Landlock uapi, no kernel headers) applies
`LANDLOCK_ACCESS_FS_EXECUTE` over `linuxExecFloor` (`packages/sandbox/src/
exec-floor.ts`: `execAllowFloor` plus `/lib`, `/lib64`, `/usr/lib`,
`/usr/lib64` — the dynamic linker + library `mmap` gate the spike found) and
execs the script, invoked inside bwrap as `landlock-exec --allow <floor> --
/bin/sh -c <script>`. It's **compiled from source by a `npm run build` step**
(`build-native.mjs` — Linux + `cc` only, a no-op exit-0 everywhere else),
never a `postinstall` hook or a lazy runtime compile (both would be posture
violations for a tool that guards against exactly that). Detection is
**fail-open and pre-checked**: the helper is used iff it exists AND
`landlock-exec --check` (an ABI probe) exits 0, cached per process
(`landlockActive` in `packages/sandbox/src/bubblewrap.ts`) — any negative
falls back to the Phase 29 advisory floor with a one-time notice, so a
Landlock-less kernel or a host without `cc` never regresses and never fails a
lifecycle script. `computeDenySet` gains a `linux-landlock` `execFloorMode`
and `classifyViolation` confirms a floor-outside exec denial as
`exec-floor-deny`; the Phase 29 `/dev/null` exfil-tool carve-out is unchanged
(Landlock is allow-list-only and can't deny a literal under an allowed dir).
macOS/Seatbelt is untouched; `native` stays advisory on both platforms. A
cross-platform exec floor now exists (macOS Seatbelt + Linux Landlock where
available) — #8 is closable, left to the controller after final review.
Scoring and the approval model are untouched (invariants #1–#7, ADR-0044).

We are the Socket/Chainguard wedge: **do not** try to replace npm. Resolve and
serve real packages transparently; only attach signal.

## Non-negotiable invariants

1. **Scoring is deterministic given a policy.** The 0–100 score and verdict come
   *entirely* from the heuristic rules plus the active `EnterprisePolicy`. Same input
   + same policy ⇒ same score, always. The `scoring is deterministic across runs` test
   pins the default policy — keep it green.
2. **The LLM never sets the score.** `LlmAuditAdapter` runs only in the async
   *enrich* phase and may only add `llmSummary` + supplementary findings. A missing
   `ANTHROPIC_API_KEY` or a model outage must never change a verdict. Default is
   `NoopLlmAdapter`; the engine is fully offline.
3. **The inline gate is sync + cheap; everything slow is async.** The proxy audits
   on the tarball request (static analysis over bytes already in memory) and caches
   by `dist.integrity`. Never put a network call or an LLM call on the request path.
4. **Cache key = integrity hash.** A published tarball is immutable, so
   `(name, version, integrity)` is a safe immutable key. Don't key caches on
   version alone.
5. **The proxy is transparent.** For packuments we pass the upstream document
   through and rewrite *only* `dist.tarball`. Don't synthesize or strip fields on
   the npm path — it breaks resolution (dependencies, peer deps, etc.).
6. **Rules fail open individually, the audit never crashes.** `runRules` wraps each
   rule in try/catch. A buggy rule must not take down an install.
7. **Claimed names are authoritative, not passthrough.** Names matching the signed
   policy's `privateNamespaces` are served only from the private store and never from
   public npm (fail-closed). Everything else still passes through (ADR-0010/0015).

## How to extend

- **Add a detection rule:** create `packages/core/src/rules/<id>.ts` exporting a
  `Rule` (pure `(AuditInput) => Finding[]`), register it in `rules/index.ts`. Use
  `mkFinding()` from `rules/util.ts` so the diff multiplier and policy weights apply
  consistently. Don't compute weights by hand.
- **Tune policy:** all weights, the diff multiplier, and verdict thresholds live in
  `DEFAULT_POLICY` in `packages/core/src/policy.ts`. Change them there, nowhere else. Phase 2
  makes these per-enterprise — keep them data, not code.
- **Add an upstream:** implement `Upstream` in `packages/proxy/src/upstream.ts`
  (`getPackument`, `getTarball`). Keep audit logic in the server, not the upstream.

## Fixtures — safety rules

- **Never add live malware to this repo.** Malicious fixtures must be synthetic,
  inert, marked with a `SYNTHETIC FIXTURE` header, and use RFC 5737 documentation
  IPs (`198.51.100.0/24`, `203.0.113.0/24`). They are scored as *text* and never
  executed.
- Fixtures live in `fixtures/<benign|malicious>/<name>/<version>/package/`.
  `scripts/make-fixtures.ts` packs them into real `.tgz` and writes
  `fixtures/registry.json` (the doc `LocalFixtureUpstream` serves). Re-run
  `npm run fixtures` after editing fixtures.
- Tests must stay hermetic: use `LocalFixtureUpstream`, never hit live npm in
  `npm test`.

## Stack & versions (June 2026)

Node + TypeScript, npm workspaces (`core`, `proxy`, `sandbox`, `cli`, `mcp`,
`action` — the last being Phase 17's `@sentinel/action`, bin `sentinel-ci`),
Express 5, `tar` 7, `commander` 15, `yaml` 2 (`@sentinel/core` only —
pnpm/yarn-berry lockfile parsing), `semver` 7 (Phase 22's `@sentinel/core`
`known-vulnerability` range matching), tests on `node:test` + `tsx`.
Developed against **Node 24 (Active LTS)**; Node 22 (Maintenance LTS) also
supported — `engines.node` is `>=22`. Pin to current latest; don't downgrade
majors without a reason. `node:sqlite` (Phase 15's `HistoryDb`) is a Node
built-in, not a dependency; it's opt-in via `SENTINEL_HISTORY_DB` and runs
unflagged on Node 24, but Node 22 needs `--experimental-sqlite` if you turn
it on. `SENTINEL_VULNERABILITIES` (Phase 22, like `SENTINEL_ADVISORIES`) is
an optional, fail-closed, load-once-at-startup operator vuln feed for the
public install audit path. `SENTINEL_TARBALL_ORIGINS`/`SENTINEL_PUBLIC_BASE_URL`
(Phase 23) are the same fail-closed, load-once-at-startup posture for the
outbound tarball-origin allowlist and the inbound public base URL,
respectively. `SENTINEL_MAX_TARBALL_BYTES`/`SENTINEL_MAX_PACKUMENT_BYTES`/
`SENTINEL_MAX_TREE_PACKAGES`/`SENTINEL_RATE_LIMIT_RPM` (Phase 24) round out
the same fail-closed, load-once-at-startup posture for the fetch byte caps,
the audit-tree package cap, and the opt-in token-bucket rate limiter.
`SENTINEL_AUTO_QUARANTINE` (Phase 26 Part B, ADR-0040) is `0`/unset by
default (record-only); only the exact value `1` enables it (any other value,
e.g. `true`, is treated as off — matching the `SENTINEL_ENFORCE="1"`
convention), and enabling it requires `SENTINEL_AUTH_PUBKEY` to
also be set, or the proxy FATALs at startup — the same fail-closed posture as
the rest of this list, applied to the auto-quarantine decision itself.
`SENTINEL_MAX_UNPACKED_BYTES`/`SENTINEL_MAX_FILE_COUNT` (Phase 26 Part A) are
the same fail-closed, load-once-at-startup posture for `extractTarball`'s
decompression-bomb caps (unpacked bytes / file count; defaults 1 GiB / 100k).

## Build / test / run

```bash
npm run build            # tsc --build (project references: core → proxy/cli)
npm test                 # engine + end-to-end proxy: 769 tests on this host (767 pass, 2 skipped on darwin).
                         # Skips are platform-gated enforcement: "non-darwin throws" skips on darwin
                         # (it verifies darwin-only behaviour), and the "no silent skip" CI guard skips
                         # off-CI. The BubblewrapSandbox enforcement suite and the Linux enforce-e2e tests
                         # skip as describe-level blocks on darwin ("requires Linux") and are not in the 769
                         # count. Phase 10's violation-enforce e2e and the darwin-gated runtime-violation
                         # effect test (SeatbeltSandbox: "a denied credential read surfaces a confirmed
                         # runtime violation") RUN on darwin via Seatbelt, the same way the rest of the
                         # Seatbelt effect suite does, and ARE in the 769 count. Phase 25 Slice 1's
                         # write-floor SeatbeltSandbox enforcement effect tests (positive control on
                         # the floor, persistence carve-out under a fake $HOME inside the floor's
                         # temp dir, a real /dev/null redirect) are likewise darwin-gated and RUN on
                         # darwin via Seatbelt. Phase 25 Slice 2's $HOME-read-deny SeatbeltSandbox
                         # effect test ("a $HOME read outside the read-allow list is denied; the
                         # project tree + a build stay readable") is darwin-gated and RUNs on darwin
                         # via Seatbelt, asserting containment ONLY (the sandboxed script's own
                         # try/catch observes the read as denied; the test never inspects
                         # classifyViolation's output) — the equivalent bwrap effect test ("a $HOME
                         # read outside the read-allow list is contained; the project tree stays
                         # readable") runs cross-platform and likewise asserts containment ONLY.
                         # Seatbelt's EPERM->confirmed-violation telemetry is exercised by the
                         # pre-existing Phase 10 credential-read-violation test, not by either new
                         # Slice 2 test; bwrap's --tmpfs denial surfaces as ENOENT, not a
                         # classifiable violation signature (the accepted telemetry asymmetry,
                         # ADR-0038/ADR-0023).
                         # Phase 7's audit-tree, Phase 8/9's signature/provenance, Phase 10's
                         # classifyViolation/deny-set/violations-store, Phase 11's MCP/approval-request,
                         # Phase 12's auth/authz-e2e, Phase 13's typosquat/dependency-confusion,
                         # Phase 14's lockfile/SBOM/integrity-cross-check, Phase 15's
                         # history-db/write-through/endpoints/CLI-stats-history, Phase 16's
                         # release-anomaly/capability-novelty/release-anomaly-e2e, Phase 17's
                         # action run/report/bin-e2e/action-yml, Phase 18's remediate/explain-route/
                         # CLI-explain/PR-comment-hint/MCP-explain, Phase 19's attest-core/
                         # policyHash-plumbing/CLI-attest-keygen-attest-verify-attestation, Phase 20's
                         # policy-lint/allReports/preview-route/policy-init-validate-preview-CLI,
                         # Phase 21's advisory-corpus/known-advisory-rule/SENTINEL_ADVISORIES-load,
                         # Phase 22's vuln-corpus/known-vulnerability-rule/semver-satisfies/
                         # SENTINEL_VULNERABILITIES-load/tree-vulnerabilities-count, and Phase 23's
                         # net-config parsing/validation, tarball-origin-e2e (poisoned-packument
                         # never-fetched canary + malformed-allowlist FATAL), public-base-url-e2e
                         # (configured base + loopback fallback + non-loopback 421), and net-startup
                         # (fail-closed FATAL parsing of both env vars) tests, and Phase 24's
                         # limits (parsePositiveInt/readBodyCapped early-reject + mid-stream abort),
                         # tarball-size/packument-size caps, audit-tree-limits-e2e (dedupe +
                         # 413-over-cap), coalesce (concurrent-uncached-audit stampede fix),
                         # rate-limit (token-bucket unit) + rate-limit-e2e (429 + Retry-After on
                         # audit-tree/explain/policy-preview), and limits-startup (fail-closed FATAL
                         # parsing of all four env vars) tests, and Phase 25 Slice 1's directional
                         # pathCovers unit tests, writeAllowFloor unit tests, and generateProfile/
                         # generateBwrapArgs write-deny generator tests (blanket deny, floor re-allow,
                         # Grant-as-positive-allow, SENSITIVE carve-out-after-floor, and the deny-set
                         # non-drift check), and Phase 25 Slice 2's readAllowList/nodeInstallPrefix/
                         # resolveProjectRoot unit tests, generateProfile/generateBwrapArgs
                         # $HOME-read-deny generator tests (blanket deny, file-read-metadata
                         # traversal layer, read-allow re-open, SENSITIVE read carve-out unchanged),
                         # and the runLifecycleScripts projectRoot-threading test are hermetic
                         # and platform-neutral. The Linux (bubblewrap) enforcement path — including
                         # the Phase 25 write-deny and $HOME-read-deny — is verified GREEN on ubuntu CI
                         # (Node 22 + 24) through Phase 25 via PRs #1 (write-deny) and #2 (read-deny) on
                         # git-agentic/pkg-registry; the darwin count is one lower with one more skip (the
                         # bubblewrap enforcement suite is a describe-level skip off Linux). Each
                         # platform's enforcement is verified on that platform (macOS dev host /
                         # ubuntu-latest CI). Phase 28's exec-floor/sensitive-executables/profile-exec/
                         # deny-set-exec/violation-exec unit tests are hermetic and platform-neutral;
                         # its three Seatbelt exec effect tests (floor positive control, dropped-binary
                         # denial + confirmed process violation, curl carve-out lift) are darwin-gated
                         # and RUN on darwin. Phase 29's bwrap carve-out generator tests, the
                         # computeDenySet Linux carve-out branch unit tests (plus its non-drift and
                         # live merged-usr-resolution non-drift checks against generateBwrapArgs), and
                         # the classifyViolation Linux carve-out branch unit tests are hermetic and
                         # platform-neutral; its three bwrap Linux exec effect tests (the curl
                         # carve-out denied without a Grant and lifted by process:curl, a denied curl
                         # exec surfacing a confirmed process violation, and a positive control that a
                         # node_modules/.bin shim and node still run) are CI-only (Linux/bubblewrap)
                         # and do not run on darwin. Phase 2 (Landlock)'s linuxExecFloor unit tests
                         # (exec-floor.test.ts), computeDenySet's Landlock-floor-mode unit tests
                         # (execFloorMode + populated floor, deny-set.test.ts), classifyViolation's
                         # Landlock-floor-mode unit tests ("Linux Landlock floor mode (Phase 2)":
                         # floor-outside denial confirmed exec-floor-deny, masked carve-out literal
                         # still confirmed, under-floor denial null, inert without execFloorMode,
                         # plus the same three outcomes for the node spawnSync denial shape (#24),
                         # plus the unattributable spawnSync-line fall-through (no extractable path)
                         # pinning test — violation.test.ts), and build-native.mjs's no-op-off-Linux/no-cc unit
                         # tests (build-native.test.ts) are hermetic and platform-neutral, in the
                         # 769 count. The two Landlock bwrap effect tests in bubblewrap.test.ts
                         # ("Landlock floor: a dropped /tmp binary is denied and surfaces a confirmed
                         # process violation" and "Landlock floor: a floor binary (node) and a
                         # node_modules/.bin shim still run") live inside the same
                         # describe-level-skip-on-darwin `BubblewrapSandbox enforcement` block as the
                         # rest of the Linux effect suite — CI-only (Linux/bubblewrap with a built
                         # `landlock-exec` helper), not in the darwin 769 count, same convention as
                         # the Phase 28/29 effect tests above.
npm run demo             # offline malware-detection walkthrough
node packages/proxy/dist/index.js   # run the proxy (see README for env vars)
```

## Sandbox / environment quirks

- The working tree may be on a mount where **`rm` of build artifacts fails with
  EPERM**. tsc can still overwrite in place — use `npx tsc --build --force <pkg>`
  instead of deleting `dist/` first.
- Background processes do **not** persist across separate shell invocations here;
  start the proxy and exercise it within the same command when scripting.
- ESM only (`"type": "module"`). No top-level `require` in scripts — import instead.
  Internal imports use `.js` specifiers (NodeNext) even from `.ts` sources.

## Definition of done for a change

`npm run build` clean, `npm test` green (see count above), and if you touched rules/scoring, add or
update a test that proves the new behavior — and confirm the malicious fixture is
still **blocked**. If you changed a design invariant above, update ARCHITECTURE.md
and the relevant ADR in [docs/adr/](./docs/adr/) — or add a new ADR (never edit an
Accepted one to reverse it; supersede it).

## Agent skills

### Issue tracker

Issues are tracked as **GitHub Issues** in `git-agentic/pkg-registry` via the `gh` CLI. External PRs are **not** a triage surface. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary — `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` (not yet created) + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
