# AGENTS.md — working agreement for the Sentinel repo

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
by `createSandbox()`, that enforces a package's approved capability manifest at install time
(`sentinel run-scripts`). Synthetic malware fixtures are still scored-as-text and
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
truncating. A shared byte-counting reader, `readBodyCapped`
(`packages/proxy/src/limits.ts`), replaces `NpmUpstream`'s unbounded
`arrayBuffer()`/`json()` reads (reject-up-front on an over-cap
`content-length`, abort mid-stream on an over-cap running total), bounding
tarball fetches to `SENTINEL_MAX_TARBALL_BYTES` (default 256 MB) and
packument/attestation fetches to `SENTINEL_MAX_PACKUMENT_BYTES` (default
128 MB); over-cap is a 502 (attestations ⇒ null, fail-open). An in-flight
`name@version` map in `server.ts` coalesces concurrent uncached public
audits onto one pipeline (cache-stampede fix) — the integrity-keyed `store`
stays the durable cache (invariant #4); the map is transient and clears on
settle. A pure token-bucket `RateLimiter` (`packages/proxy/src/rate-limit.ts`,
injectable clock, keyed by `req.socket.remoteAddress`, opt-in via
`SENTINEL_RATE_LIMIT_RPM`) gates `POST /-/audit-tree`, `GET /-/explain/*`, and
`POST /-/policy/preview`; over-limit ⇒ 429 + `Retry-After`; install-gate paths
are never limited. All four env vars parse fail-closed at startup
(invariants #1–#6, ADR-0037).
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
  `POLICY` in `packages/core/src/score.ts`. Change them there, nowhere else. Phase 2
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
(Phase 23) and `SENTINEL_MAX_TARBALL_BYTES`/`SENTINEL_MAX_PACKUMENT_BYTES`/
`SENTINEL_MAX_TREE_PACKAGES`/`SENTINEL_RATE_LIMIT_RPM` (Phase 24) share the same
fail-closed, load-once-at-startup posture for the fetch trust boundary, the
fetch/tree byte-and-count caps, and the opt-in token-bucket rate limiter.

## Build / test / run

```bash
npm run build            # tsc --build (project references: core → proxy/cli)
npm test                 # engine + end-to-end proxy: 661 tests on this host (659 pass, 2 skipped on darwin).
                         # Skips are platform-gated enforcement: "non-darwin throws" skips on darwin
                         # (it verifies darwin-only behaviour), and the "no silent skip" CI guard skips
                         # off-CI. The BubblewrapSandbox enforcement suite and the Linux enforce-e2e tests
                         # skip as describe-level blocks on darwin ("requires Linux") and are not in the 661
                         # count. Phase 10's violation-enforce e2e and the darwin-gated runtime-violation
                         # effect test (SeatbeltSandbox: "a denied credential read surfaces a confirmed
                         # runtime violation") RUN on darwin via Seatbelt, the same way the rest of the
                         # Seatbelt effect suite does, and ARE in the 661 count.
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
                         # Phase 21's advisory-corpus/known-advisory-rule/SENTINEL_ADVISORIES-load, and
                         # Phase 22's vuln-corpus/known-vulnerability, Phase 23's net-config/
                         # tarball-origin/public-base-url/net-startup, Phase 24's limits/tarball-size/
                         # audit-tree-limits/coalesce/rate-limit/limits-startup, and Phase 25's
                         # read-allow/directional-pathCovers/write-floor + Seatbelt & bwrap generators +
                         # $HOME-read-deny tests are hermetic and platform-neutral. The Linux
                         # (bubblewrap) enforcement path is verified GREEN on ubuntu CI (Node 22 + 24)
                         # through Phase 25 — see PRs #1 (write-deny) and #2 (read-deny) on
                         # git-agentic/pkg-registry. Each platform's enforcement is verified on that
                         # platform (macOS dev host / ubuntu-latest CI).
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

## Imported Claude Cowork project instructions
