# Sentinel

[![ci](https://github.com/git-agentic/pkg-registry/actions/workflows/ci.yml/badge.svg)](https://github.com/git-agentic/pkg-registry/actions/workflows/ci.yml)
[![codeql](https://github.com/git-agentic/pkg-registry/actions/workflows/codeql.yml/badge.svg)](https://github.com/git-agentic/pkg-registry/actions/workflows/codeql.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**An agent-auditable security layer for the npm ecosystem.** Phase 1 is a
transparent **auditing proxy** that sits in front of `registry.npmjs.org`: it
resolves and serves real packages unchanged, but intercepts every tarball,
scores its contents with a deterministic audit engine, and attaches a verdict —
so an AI agent or a human can see the risk *before install-time code runs*.

> Why: agents now `npm install` and execute untrusted code with zero risk
> signaling. npm can't retract bad releases, has no install-time permissions, and
> lets attackers squat names. Sentinel started as that audit-proxy wedge and has
> since grown the rest of the layer: signed per-enterprise policy and an
> install-time permission manifest, a **deny-by-default** capability sandbox
> (macOS Seatbelt / Linux bubblewrap) that enforces it, offline signature +
> Sigstore-provenance verification, known-malicious/known-vulnerable (GHSA/CVE)
> detection, supply-chain identity heuristics, whole-tree lockfile auditing with
> CycloneDX SBOM + signed VSA attestations, a CI-native GitHub Action, an
> agent-native MCP surface, durable history/observability, and a hardened network
> trust boundary + resource limits. See the decision log in
> [docs/adr/](./docs/adr/) (one ADR per phase).

See **[ARCHITECTURE.md](./ARCHITECTURE.md)** for the full design (proxy, sync-vs-async
audit placement, data model, npm hooks, stack justification).

## Status

**Pre-1.0.** The auditing proxy, policy gate, deny-by-default install sandbox
(macOS Seatbelt / Linux bubblewrap), CLI, MCP server, and GitHub Action work
end-to-end and are covered by the full test suite (Linux CI on Node 22 and 24;
macOS Seatbelt enforcement is exercised on maintainers' machines) — but this
has not yet been hardened by production use, and APIs may change without
notice. The complete phase-by-phase build log lives in
[docs/adr/](./docs/adr/) (one ADR per phase). **No npm packages are
published yet**: build from source (Quickstart below). Threat model:
[sentinel-threat-model.md](./sentinel-threat-model.md) · Homepage:
[git-agentic.com/sentinel](https://git-agentic.com/sentinel)

---

## Quickstart

```bash
npm install          # install workspace deps
npm run build        # compile all packages (tsc --build)
npm run fixtures     # pack the test fixtures into real .tgz tarballs
npm test             # engine + end-to-end proxy — see CLAUDE.md for the current count and skip breakdown
npm run demo         # self-contained malware-detection demo (no network)
```

`npm run demo` boots the proxy in-process against local fixtures and prints the
pre-install verdict panels for a benign package and a trojaned patch release,
ending with the `403` an installer would receive:

```
══ 3. Trojaned patch release — color-stream@1.4.1 (diff vs 1.4.0) ═
  color-stream@1.4.1
  ────────────────────────────────────────────────────────
  install    ⚠ runs lifecycle scripts
  score      ░░░░░░░░░░ 0/100
  verdict    BLOCK
  findings (7)
  critical [install-scripts] `postinstall` … reads environment variables, decodes an encoded blob.
  critical [secret-exfil]    Reads sensitive material (…~/.npmrc, AWS credentials…) and contains a network egress sink…
  high     [network-egress]  connects to a hardcoded IP address.
  high     [obfuscation]     uses eval().
  …
══ 4. What `npm install` sees when it fetches the bad tarball ════
  HTTP 403  x-sentinel-verdict: block  x-sentinel-score: 0
```

## Run the proxy against real npm

```bash
npm run build
node packages/proxy/dist/index.js          # observe policy, npm upstream, :4873
# open the dashboard:
open http://localhost:4873/
```

Audit a real package before installing (no install, no execution):

```bash
node packages/cli/dist/index.js audit is-odd 3.0.1
#   is-odd@3.0.1  → score 100/100  ALLOW  (signed, no install scripts)
```

Route a real install through the proxy (every tarball in the tree is audited):

```bash
node packages/cli/dist/index.js install lodash
# == npm install --registry http://localhost:4873 lodash
```

### Environment

| Var | Default | Meaning |
|---|---|---|
| `SENTINEL_UPSTREAM` | `npm` | `npm` (real registry) or `fixtures[:dir]` (local, hermetic) |
| `SENTINEL_POLICY` | `observe` | `observe` = audit + serve + headers; `block` = `403` on a block verdict |
| `SENTINEL_PORT` | `4873` | proxy port (verdaccio's conventional local-registry port) |
| `SENTINEL_REGISTRY` | `https://registry.npmjs.org` | upstream registry when in npm mode |
| `SENTINEL_STORE` | _(memory only)_ | path to a JSON file to persist the audit log |
| `SENTINEL_VIOLATIONS` | _(memory only)_ | path to a JSON file to persist runtime-violation records (quarantine state) |
| `SENTINEL_AUTO_QUARANTINE` | _(unset ⇒ record-only)_ | set to exactly `1` (any other value is treated as off) to let a confirmed runtime-violation report quarantine its integrity (force `block` at serve time); requires `SENTINEL_AUTH_PUBKEY` to also be set — a fatal error at startup otherwise, so auto-quarantine is only ever attributable to an authenticated caller (ADR-0040) |
| `SENTINEL_APPROVAL_REQUESTS` | _(memory only)_ | path to a JSON file to persist pending approval requests (MCP `sentinel_request_approval` and any other caller) |
| `SENTINEL_TRUSTED_ROOT` | _(bundled root)_ | path to a Sigstore `trusted_root.json` for provenance verification (fatal error on a bad path) |
| `SENTINEL_NPM_ATTESTATION_KEYS` | _(bundled keys)_ | path to an npm publish-attestation keys JSON, used alongside `SENTINEL_TRUSTED_ROOT` |
| `SENTINEL_AUTH_PUBKEY` | _(unset ⇒ open)_ | path to an Ed25519 public key PEM; when set, gates control-plane mutations behind signed role tokens (see below) |
| `SENTINEL_AUTH_TOKEN` | _(unset)_ | signed role token attached as `Authorization: Bearer` by the MCP client and `sentinel-script-shell` on their POST calls |
| `SENTINEL_HISTORY_DB` | _(unset ⇒ disabled)_ | path to a SQLite file (`node:sqlite`, built-in); enables durable audit/violation history, `/-/metrics`, `/-/history`, `/-/violations/timeline`, `sentinel stats`/`history`, and the dashboard's Observability section. Node 24 runs it unflagged; Node 22 needs `--experimental-sqlite` |
| `SENTINEL_ADVISORIES` | _(unset ⇒ bundled corpus only)_ | path to a JSON `Advisory[]` file, loaded once at startup (fatal error on an unreadable path); merged with the bundled known-malicious corpus and checked on the public install audit path |
| `SENTINEL_VULNERABILITIES` | _(unset ⇒ bundled corpus only)_ | path to a JSON `VulnAdvisory[]` file, loaded once at startup (fatal error on an unreadable path, or on a corrupt non-JSON/non-array file); merged with the bundled known-vulnerable-range corpus and checked on the public install audit path |
| `SENTINEL_TARBALL_ORIGINS` | _(registry origin only)_ | comma-separated allowlist of extra bare http(s) origins tarball fetches may target, beyond `SENTINEL_REGISTRY`'s own origin; validated once at startup (fatal error on a malformed entry), and a disallowed origin is never fetched (502) |
| `SENTINEL_PUBLIC_BASE_URL` | _(unset ⇒ loopback-derived)_ | base URL used to rewrite `dist.tarball` links; when unset, only a loopback request Host (`localhost`, `127.0.0.0/8`, `[::1]`) may derive it — any other Host is refused with 421 |
| `SENTINEL_MAX_TARBALL_BYTES` | `256 MB` | byte cap on a single tarball fetch (streamed, content-length + mid-stream enforced); over-cap ⇒ 502 |
| `SENTINEL_MAX_PACKUMENT_BYTES` | `128 MB` | byte cap on a single packument or attestation fetch; over-cap ⇒ 502 (attestations ⇒ null, fail-open) |
| `SENTINEL_MAX_TREE_PACKAGES` | `5000` | cap on distinct `name@version` coordinates in a single `/-/audit-tree` request; over-cap ⇒ 413, no silent truncation |
| `SENTINEL_RATE_LIMIT_RPM` | _(unset ⇒ disabled)_ | requests-per-minute token-bucket cap, keyed by socket remote address, applied to `POST /-/audit-tree`, `GET /-/explain/*`, and `POST /-/policy/preview`; over-limit ⇒ 429 + `Retry-After`. Install-gate paths are never limited |
| `SENTINEL_MAX_UNPACKED_BYTES` | `1 GiB` | cap on total decompressed bytes when extracting a tarball's contents; over-cap aborts extraction mid-stream and the current tarball's audit gets a critical `resource-abuse` finding (BLOCK) |
| `SENTINEL_MAX_FILE_COUNT` | `100000` | cap on the number of files unpacked from a tarball; over-cap aborts extraction mid-stream the same way as the byte cap |

## CLI

```
sentinel audit <pkg> [version]   pre-install verdict panel (exit 0 allow / 1 warn / 2 block)
sentinel explain <pkg> <version> per-finding remediation, a suggested last-known-good version, and a ready waiver
sentinel scan  <file.tgz>        audit a local tarball offline (no proxy)
sentinel audit-tree [lockfile]   audit an entire resolved tree (npm/yarn/pnpm); exit non-zero if gated
  --sbom <file>                    write a CycloneDX 1.6 SBOM of the audited tree
  --fail-on-error                  also gate when any package fails to audit (default off)
  --omit <type>                    omit a dependency group (only 'dev' is supported)
sentinel install [args…]         npm install routed through the proxy
sentinel npx     [args…]         npx routed through the proxy
sentinel violations              list runtime violations recorded by the proxy (quarantined builds)
sentinel stats                    durable audit/violation metrics (requires SENTINEL_HISTORY_DB on the proxy)
sentinel history [--verdict --name --limit]   list recorded audits (requires SENTINEL_HISTORY_DB)
sentinel policy init --out <file>                 scaffold a policy file from the built-in default
sentinel policy validate <file>                   parse + lint a policy (non-zero exit iff errors)
sentinel policy preview <file> [-p proxy]         replay audit history under a candidate policy (dry run)
sentinel policy keygen [--out <prefix>]           generate an Ed25519 keypair for signing policies
sentinel policy sign <file> --key <privkey>       write a detached signature over a policy file
sentinel policy verify <file> --pubkey <pubkey>   verify a policy's signature and print its summary
sentinel token keygen --out <prefix>              generate an Ed25519 keypair for control-plane auth
sentinel token mint --role --sub --ttl --key       mint a signed role token (prints to stdout)
sentinel token verify <token> --pubkey             verify a token, print role/sub/exp or the rejection reason
sentinel attest-keygen --out <prefix>              generate an Ed25519 keypair for attestation signing
sentinel attest [lockfile] --key --out [--sbom]    audit the tree, write an SBOM, sign a DSSE attestation over it
sentinel verify-attestation <att> --key [--sbom --policy-hash --require]   offline-verify an attestation (deploy gate)
  -p, --proxy <url>   proxy base URL (default http://localhost:4873)
  --json              raw JSON report
```

The exit codes make `sentinel audit` usable as an agent tool or a CI gate.

### Whole-tree audit (Phase 7, ADR-0020; ecosystem breadth + SBOM, Phase 14, ADR-0027)

`sentinel audit-tree [lockfile]` audits every resolved package in a lockfile in one
pass and exits non-zero if the aggregate verdict trips the policy's `treeGate`
(default `block`). It auto-detects the format — `package-lock.json`/
`npm-shrinkwrap.json` (npm v2/v3), `yarn.lock` (v1 text or berry YAML), and
`pnpm-lock.yaml` (v5/v6/v9) — by filename first, falling back to a content sniff.

- `--sbom <file>` writes the audited tree as a CycloneDX 1.6 JSON BOM: one
  `library` component per package (`purl: pkg:npm/<name>@<version>`) carrying
  Sentinel's verdict/score/top-finding as `sentinel:*` properties. Written even
  when the tree is gated — it's informational output, not the gate itself.
- The proxy cross-checks each lockfile-pinned integrity against the hash it
  actually recomputed from the served bytes (Phase 9); a mismatch force-blocks
  that row, surfaces a `lockfile-integrity-mismatch` finding, and is counted in
  the aggregate — but only when both sides are present and disagree (an absent
  integrity, e.g. yarn-berry's non-SRI checksum, never false-flags).
- `--fail-on-error` opts the tree into gating on unresolvable-package rows too
  (default: `error` rows are surfaced but never gate, per ADR-0020's fail-open
  stance).
- `--omit dev` skips dev dependencies where the lockfile format records them.

### Explain & remediation (Phase 18, ADR-0031)

`sentinel explain <package> <version>` answers "how do I get green?" for a
`warn`/`block` verdict:

```
$ sentinel explain color-stream 1.0.0

  color-stream@1.0.0  —  BLOCK  0/100

  block — 2 finding(s); see the actions below or waive with the recorded rationale.

  • secret-exfil (critical) — Reads credentials/tokens and may exfiltrate them.
      Do not install until reviewed. If this is a false positive, waive with a
      recorded rationale; otherwise remove the dependency.
  • network-egress (high) — Makes network connections.
      Confirm the egress is expected for this package's purpose; if not,
      remove it or pin to a version without it.

  ✓ suggested: pin to color-stream@0.9.0 — the most recent clean release (96/100).

  To waive after review:
      sentinel approve color-stream 1.0.0 --reason "<state your review rationale>"
```

It calls the proxy's `GET /-/explain/:pkg/:version`, which audits the
version, runs the pure `remediate()` guidance mapping over the report, and
walks back a bounded window (newest of ≤10 prior versions) for the last one
that itself audits `allow` — the "suggested safe version" line. Prior
versions come from the private store for a claimed namespace and from public
npm otherwise (same `isClaimed` split as every other route — a claimed name
never round-trips to public npm). The route is off the inline install-gate
path, since it's expected to be slower than a plain audit — up to ~11 audits
per call (integrity-cached, so repeats are cheap), so rate-limit or
authenticate it if the proxy is reachable beyond a trusted network.

Remediation surfaces in two more places without a separate `explain` call:

- The `audit-tree` PR comment gets a **how to fix** column next to each
  flagged package (`remediationHint(ruleId)`), plus a footer pointing at
  `sentinel explain` for the full detail.
- The MCP server's `sentinel_explain` tool (see below) returns the same
  `{ report, remediation, lastKnownGood }` shape for an agent host.

**Advisory only** — nothing here rewrites a lockfile, `package.json`, or
auto-selects a version. `sentinel explain` and the PR-comment hint only ever
suggest; a human (or an agent through the existing approval-request path)
still decides. See [ADR-0031](./docs/adr/0031-actionable-remediation.md).

### Signed audit attestations (Phase 19, ADR-0032)

`sentinel audit-tree` gates a CI job; nothing survives past that job as a
portable artifact a *later*, independent step can check offline. Phase 19
adds a signed, SLSA-VSA-flavored attestation over an audited tree, for a
deploy-time gate:

```bash
# once, offline: generate a signing keypair (keep sentinel-attest.key.pem secret)
sentinel attest-keygen --out sentinel-attest

# in CI, after the tree passes audit-tree: produce an SBOM + a signed attestation over it
sentinel attest package-lock.json --key sentinel-attest.key.pem --out audit.att.json --sbom sbom.json

# later, offline, in a deploy pipeline — pin the *public* key, never the private one
sentinel verify-attestation audit.att.json --key sentinel-attest.pub.pem \
  --sbom sbom.json --require allow
# ✓ valid · verdict allow · policy <hash> · 2026-07-08T...
# (or) ✗ attestation rejected: verdict-block   → exits non-zero
```

The attestation is a DSSE envelope around an in-toto `Statement` v1: its
`subject` is the SHA-256 digest of the CycloneDX SBOM written alongside it
(`--sbom`, ADR-0027), and its predicate
(`https://sentinel.dev/attestation/audit-summary/v1`) carries the verdict,
gate decision, per-verdict counts, the scoring-time policy hash, and a
timestamp — enough to gate a deploy without re-running the audit or
re-fetching the full per-package report. Signing is Ed25519, done entirely
in the CLI on whatever machine runs `sentinel attest` (typically CI); the
proxy holds no signing key and gains no new mutating route — its only
change is exposing the `policyHash` it already computed on the
`/-/audit-tree` response, so `--policy-hash` can pin an attestation to the
policy that produced it. `verify-attestation` is pure, offline, and
fail-closed: a tampered envelope, a wrong SBOM, a policy-hash mismatch, or a
verdict below `--require` all reject with a distinct reason and a non-zero
exit — never a silent pass.

This is a **VSA-style** artifact (a DSSE/in-toto envelope, in the spirit of
SLSA's Verification Summary Attestation) rather than a spec SLSA VSA: the
predicate type is Sentinel-owned, so a generic DSSE/in-toto tool can check
the signature, but a SLSA-aware verifier expecting the standard predicate
shape won't recognize it without adaptation. Note the command is
`sentinel attest-keygen`, not `sentinel attest keygen` — they're sibling
top-level commands (a commander-15 quirk with nested `requiredOption`s made
a true subcommand impractical). See
[ADR-0032](./docs/adr/0032-signed-audit-attestations.md).

### Sandbox — default-deny (Phases 3–5, 25, 28, 29, Phase 2/Landlock; macOS Seatbelt / Linux bubblewrap)

`sentinel run-scripts <package-dir> [--approve network:host …]` runs the package's lifecycle scripts under a kernel sandbox generated from its approved capabilities — `createSandbox()` selects **Seatbelt** on macOS and **bubblewrap** on Linux, same capability model and fail-closed contract. As of Phase 25 the sandbox is **deny-by-default** (ADR-0038):

- **Writes** are denied outside a fixed floor (the install dir, the OS temp dir, `/dev`, and the node build caches `~/.node-gyp` / `~/.cache/node-gyp` / `~/.npm/_logs`) plus operator-approved `filesystem:` grants — killing the persistence/tamper class, not an enumerated list.
- **`$HOME` reads** are denied by default, re-allowing only what a lifecycle script needs: system paths, the node install prefix (so a node-under-`$HOME` nvm/fnm/volta runtime still loads its stdlib), the project root (so `require()` resolves), and the build caches — closing credential theft as a whole class. `/etc/passwd`/`/etc/shadow` stay denied via the `SENSITIVE_PATHS` carve-out.
- **Network egress** is denied unless a `network` capability is approved.
- **Environment secrets** are fail-closed **scrubbed** (Phase 4): a credential-looking env var (`NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, …) never reaches the script unless approved with an `env:NAME` capability. The `secret-exfil` audit rule additionally flags env reads at scoring time.
- **Exec** (macOS, Phase 28) is denied outside a fixed floor — system dirs, the node
  prefix, the project tree, Apple/Homebrew toolchains — plus approved `process:`
  grants (`process:curl` lifts one tool's carve-out; `process:/path` opens a path;
  `process:*` lifts the carve-out only), and exfil-capable tools (`curl`, `wget`,
  `nc`, …) are re-denied inside the floor unless granted. A dropped binary in `/tmp`
  or a cache is kernel-denied; a binary the package writes into its *own* project
  tree can still exec there (the floor includes the project root), mitigated by the
  `unscanned-content` finding and `process` capability scoring, not kernel denial.
- **Exec** (Linux, Phase 29 + Phase 2/Landlock) always exec-denies the
  exfil-capable tools (`curl`, `wget`, `nc`, …) by masking each with
  `--ro-bind /dev/null <path>` unless a `process:` Grant lifts it (bwrap itself
  cannot path-gate exec — no `noexec` mount option). As of Phase 2 the exec
  **floor** is also enforced where a from-source Landlock helper is available:
  `landlock-exec`, compiled by `npm run build` (Linux + `cc` only, a no-op
  elsewhere) and invoked inside bwrap, applies `LANDLOCK_ACCESS_FS_EXECUTE`
  over the floor (`execAllowFloor` plus the library/linker dirs `/lib`,
  `/lib64`, `/usr/lib`, `/usr/lib64`) before exec'ing the script — a dropped
  binary outside that floor is kernel-denied, matching the macOS behavior.
  Detection is fail-open and pre-checked (helper present AND a `--check` ABI
  probe passes, cached); anything else falls back to the Phase 29 advisory
  floor with a one-time notice — no availability regression on hosts without
  Landlock or a `cc` toolchain, which stay filesystem+network confined as
  before. The `/dev/null` exfil-tool carve-out is unchanged either way
  (ADR-0043, ADR-0044).

A denied credential read surfaces as a confirmed runtime violation on Seatbelt (EPERM); on bubblewrap the read is *contained* (a `--tmpfs` mask yields `ENOENT`) but not classified — an accepted telemetry asymmetry (ADR-0023). Both backends contain; only the telemetry differs.

### Runtime violation telemetry (Phase 10)

The sandbox has always **contained** a denied capability; it now also reports it. When
an enforced lifecycle script's denied read or network egress *surfaces as a process
failure*, `sentinel-script-shell` best-effort reports the detected violation to the
proxy, which quarantines that exact tarball (by integrity) fleet-wide — every future
serve of the same bytes comes back `block`, on top of the deterministic score, without
ever mutating the cached audit. This is best-effort: a denial the package's own code
silently swallows (process exits `0`) leaves no signal for telemetry, but it is still
denied at the kernel level exactly as before — containment is unaffected either way.

- `sentinel violations [--json]` — list recorded violations and their quarantine state.
- `POST /-/violations` — report a violation `{ name, version, integrity, kind, target,
  confidence, deniedResource, evidence }`; `confirmed` quarantines and revokes any
  standing approval, `suspected` is record-only. Requires the integrity to already have
  an audited report.
- `GET /-/violations` — the 50 most recent violation records.
- `DELETE /-/violations/:integrity` — clear a quarantine.
- `x-sentinel-violations` response header on every served tarball (`1`/`0`).

## Durable history + observability (Phase 15)

Set `SENTINEL_HISTORY_DB=<path>` on the proxy to turn on a durable, queryable
store of every audit and violation, over the built-in `node:sqlite` — no new
dependency. It's **opt-in**: leave the var unset and nothing changes (no
`node:sqlite` import, same in-memory-only behavior as before). The store
write-throughs beside the existing in-memory cache; it's best-effort, so a
history-store failure never breaks a record or the audit gate.

```bash
SENTINEL_HISTORY_DB=./sentinel-history.db node packages/proxy/dist/index.js
```

- `GET /-/metrics` — `{ summary, trends, topFlagged }` (verdict/signature/
  provenance/violation/quarantine counts, a daily allow/warn/block trend,
  and the most-flagged package names).
- `GET /-/history?verdict=&name=&limit=&offset=` — paginated, filterable
  audit rows.
- `GET /-/violations/timeline` — the recorded violation stream, most recent
  first, with quarantine status.
- All three return `501 { enabled: false }` when `SENTINEL_HISTORY_DB` is
  unset, never a silent empty response.
- `sentinel stats` and `sentinel history [--verdict --name --limit]` render
  the same data on the CLI; both print "history not enabled — set
  SENTINEL_HISTORY_DB on the proxy" if the endpoint 501s.
- The dashboard's **Observability** section renders a verdict-trend chart,
  a top-flagged list, and a violation timeline, and degrades to a note when
  history isn't enabled.

**Node version note:** `node:sqlite` runs unflagged on Node 24. On Node 22
you need `--experimental-sqlite` if you set `SENTINEL_HISTORY_DB`; leaving it
unset keeps Node 22 fully supported with no flag. See
[ADR-0028](./docs/adr/0028-durable-history-observability.md).

## Policy authoring + impact preview (Phase 20)

Authoring an `EnterprisePolicy` is hand-edited JSON — Phase 20 adds a lint
and a dry-run impact preview so an operator can catch a broken value and see
what a candidate change *does* before signing it:

```bash
# 1. scaffold a starting point from the built-in default
sentinel policy init --out policy.json

# 2. edit weights/thresholds/namespaces, then lint it — CI-gate: non-zero exit iff there are errors
sentinel policy validate policy.json

# 3. see what the candidate would change against real audit history (requires
#    SENTINEL_HISTORY_DB on the proxy — see "Durable history" above)
sentinel policy preview policy.json -p http://localhost:4873

# 4. once it looks right, sign it as before
sentinel policy sign policy.json --key sentinel-policy.key.pem
```

- `sentinel policy validate <file>` parses and runs `lintPolicy`: **errors**
  (a policy an operator should not sign — an inverted threshold, an invalid
  severity, a package in both `allow` and `deny`, …) fail the command;
  **warnings** (legal but suspicious — non-monotonic weights, an
  aggressively low `hardBlockSeverity`, …) print but exit `0`, so `validate`
  is a clean CI gate that doesn't block on advisory noise.
- `sentinel policy preview <file> [-p proxy]` POSTs the candidate to
  `POST /-/policy/preview`, which re-scores every audit in `HistoryDb`
  under the candidate through the same deterministic `score()` the live
  gate uses, and prints the verdict-transition counts (e.g.
  "3 allow→block, 1 warn→allow") plus the worst-affected packages. It's a
  **dry run** — the candidate is never applied to the live proxy, stored, or
  signed by this command. No `SENTINEL_HISTORY_DB` on the proxy ⇒ prints
  "history not enabled" instead of an error.
- Preview is a read: it needs a running proxy but no auth token, same as
  every other read route.

See [ADR-0033](./docs/adr/0033-policy-authoring-impact-preview.md).

## Control-plane authentication (Phase 12)

The control plane's mutating endpoints — approvals, violation reports and
clears, and publish — are **unauthenticated by default (open mode)**. Setting
`SENTINEL_AUTH_PUBKEY` on the proxy turns on signed-role-token auth for those
routes; everything else (every `GET`, tarball fetches, packument resolution,
and `POST /-/audit-tree`) stays open in either mode.

Tokens are stateless, offline-verifiable Ed25519 signatures over
`{ role, sub, iat, exp }` — no server-side session store, no token database.
Generate a keypair, mint a token, and verify it:

```bash
sentinel token keygen --out ./auth              # writes auth.pub.pem, auth.key.pem (0600)
sentinel token mint --role operator --sub alice --ttl 3600 --key ./auth.key.pem
# eyJyb2xlIjoib3BlcmF0b3IiLCJzdWIiOiJhbGljZSIsImlhdCI6...  .  c2ln...
sentinel token verify <token> --pubkey ./auth.pub.pem
# valid  role=operator  sub=alice  exp=2026-07-07T15:00:00.000Z
```

Run the proxy with auth enabled:

```bash
SENTINEL_AUTH_PUBKEY=./auth.pub.pem node packages/proxy/dist/index.js
```

**Role → endpoint map** (enforced only when `SENTINEL_AUTH_PUBKEY` is set):

| Route | Required role |
|---|---|
| `POST /-/approvals` | `operator` |
| `DELETE /-/approvals/:integrity` | `operator` |
| `DELETE /-/violations/:integrity` | `operator` |
| `POST /-/approval-requests` | `agent` |
| `POST /-/violations` | `agent` |
| `PUT /:pkg` (publish) | `publisher` |

A missing/malformed/expired/badly-signed token is `401`; a well-formed token
with the wrong role for the route is `403`. Reads are never gated.

**Clients:** `sentinel-mcp` (`ProxyClient`) and `sentinel-script-shell` both
read `SENTINEL_AUTH_TOKEN` from the environment and attach it as
`Authorization: Bearer <token>` on their POST calls (agent role) — reads stay
unauthenticated even with a token set. The dashboard has an "operator token"
field (persisted to `localStorage`) that attaches the same header to its
Approve/Deny/Revoke actions, so a human operator can drive the gate when auth
is enabled.

This is what makes ADR-0024's "the agent can request, only a human can grant"
boundary a hard guarantee rather than an absent tool: with auth on, an
`agent`-role token presented to `POST /-/approvals` now gets a `403`, no
matter which client sends the request. See
[ADR-0025](./docs/adr/0025-control-plane-auth.md).

## MCP server (Phase 11)

`sentinel-mcp` is a stdio [MCP](https://modelcontextprotocol.io/) server for
agent hosts that speak MCP directly instead of shelling out to the CLI. It is
a **thin client** to the running proxy — it audits nothing itself and does
zero scoring; every tool call is a fetch to the proxy's `/-/*` endpoints, so
the verdict an agent sees is byte-identical to what a real install would see.
If the proxy is unreachable, a tool call fails explicitly — it never
fabricates a verdict.

Point an agent host at it (e.g. in an MCP client config):

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "node",
      "args": ["packages/mcp/dist/index.js"],
      "env": { "SENTINEL_PROXY": "http://localhost:4873" }
    }
  }
}
```

Tools:

- `sentinel_audit` — verdict/score/findings/capabilities/signature/provenance
  for a package version, plus whether it's quarantined by a runtime violation.
- `sentinel_audit_tree` — audits every package in a `package-lock.json` and
  returns the aggregate verdict and gate state.
- `sentinel_capabilities` — the capability manifest, delta vs. the prior
  version, and approval state.
- `sentinel_check_provenance` — provenance status and, when verified, the
  attested build identity (repo/workflow/builder/commit).
- `sentinel_list_violations` — recorded runtime violations and which builds
  are quarantined.
- `sentinel_explain` (Phase 18) — per-finding remediation actions, a
  suggested last-known-good version, and a ready approval-request payload
  for a package version. Same `{ report, remediation, lastKnownGood }` shape
  as `sentinel explain`/`GET /-/explain`; advisory only.
- `sentinel_request_approval` — records a **pending** approval request; it
  never grants approval. Only a human can approve, via the dashboard's
  "Pending approval requests" panel or `POST /-/approvals`.

The privilege boundary is deliberate: the agent can request, never grant.
There is no auto-approve or clear-quarantine tool, and none is planned — see
[ADR-0024](./docs/adr/0024-agent-native-mcp-surface.md).

- `POST /-/approval-requests` — record a pending request
  `{ name, version, integrity, reason, requestedBy? }`. Requires the integrity
  to already have an audited report.
- `GET /-/approval-requests` — the 50 most recent pending requests.
- A `POST /-/approvals` decision for an integrity auto-clears its pending
  request.

## GitHub Action (Phase 17)

`@sentinel/action` (bin `sentinel-ci`) is a self-contained on-ramp into pull
requests — it needs no separately-running proxy. `runCi` self-boots the
proxy in-process against real npm, audits your lockfile through the same
`/-/audit-tree` route the CLI uses, writes a CycloneDX SBOM, and posts the
verdict to the PR.

```yaml
# .github/workflows/sentinel.yml
name: Sentinel
on: { pull_request: {} }
permissions: { contents: read, pull-requests: write }
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./   # this action is not yet published to the Marketplace
        with:
          fail-on: block
```

**Inputs:**

| Input | Default | Description |
|---|---|---|
| `lockfile` | auto-detect | Path to `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` |
| `policy` | built-in `DEFAULT_POLICY` | Path to a signed enterprise policy file |
| `policy-pubkey` | — | Path to the policy signer's public key PEM (required with `policy`) |
| `policy-sig` | `<policy>.sig` | Path to the policy signature file |
| `omit-dev` | `false` | Omit dev dependencies from the audit |
| `sbom-path` | `sentinel-sbom.json` | Where to write the CycloneDX SBOM |
| `fail-on` | `block` | `block` \| `warn` \| `none` — the verdict level that fails the check |
| `comment` | `true` | Post/update a PR comment with the verdict |
| `working-directory` | `.` | Directory to audit |

**Outputs:** `verdict`, `gated`, `blocked`, `warned`, `errored`, `sbom-path`.

Every run uploads the SBOM as a build artifact (`if: always()`, so it's
attached even on a blocked run) and, on a `pull_request` event, posts or
updates a single PR comment — found by a hidden `<!-- sentinel-report -->`
marker so re-runs edit the same comment instead of piling up new ones — with
the verdict, per-package findings table, and provenance summary.

**Onboarding path:** start with `fail-on: none` — the audit runs, the SBOM
uploads, and the PR comment appears, but nothing blocks a merge — then move
to `fail-on: warn` and finally the `fail-on: block` default once the team is
ready to enforce. See [ADR-0030](./docs/adr/0030-ci-native-github-action.md).

Under `fail-on: block`/`warn`, a package that fails to resolve/audit (e.g. a
transient npm outage) becomes an error row that gates the tree (fail-closed)
— so a transient registry outage can fail the check; use `fail-on: none`
(observe) to avoid this during onboarding.

---

## How the malware demo works (and why it's synthetic)

The malicious fixture, `fixtures/malicious/color-stream`, reproduces the
**event-stream / ua-parser-js** pattern: a previously-clean package
(`1.4.0`) ships a patch (`1.4.1`) that adds a `postinstall` hook which harvests
environment secrets and `~/.npmrc`, decodes an obfuscated base64 blob, `eval`s
it, and exfiltrates over HTTPS to a hardcoded IP.

It is **inert test data** — never executed by the suite (the engine only reads it
as text), the egress IP is in the RFC 5737 documentation range, and it carries a
`SYNTHETIC FIXTURE` header. We use a synthetic payload on purpose: the real
historical malware (`flatmap-stream@0.1.1`) was **unpublished from npm** after the
incident (only a `0.0.1-security` placeholder remains), so it can't be fetched —
which is itself one of the problems Sentinel exists to address.

The engine was also validated against the **live npm registry**:

| Package (real npm) | Result |
|---|---|
| `is-odd@3.0.1` | `100/100` **ALLOW** — signed, no install scripts |
| `esbuild@0.19.0` | **BLOCK** — flags its network-touching `postinstall` (a real, legitimate-but-reviewable install hook) |
| `flatmap-stream@0.1.1` | unresolvable — unpublished after the event-stream incident |

`esbuild` is a deliberate example of a *true positive that needs policy*: its
postinstall is legitimate, and Phase 2's per-enterprise allowlisting is how you'd
clear it without weakening detection.

---

## Project layout

```
packages/
  core/    @sentinel/core   audit engine — rules, scoring, data model, LLM adapter (no I/O, fully unit-tested)
  proxy/   @sentinel/proxy  Express registry proxy, pluggable upstream, audit store, dashboard
  cli/     @sentinel/cli    pre-install verdicts + registry-redirected npm/npx
  mcp/     @sentinel/mcp    sentinel-mcp: stdio MCP server, thin client to the proxy (Phase 11)
  action/  @sentinel/action sentinel-ci: self-boots the proxy for GitHub Actions (Phase 17)
fixtures/  benign + synthetic-malicious packages; make-fixtures.ts packs real .tgz tarballs
scripts/   make-fixtures.ts, demo.ts
ARCHITECTURE.md   full design   ·   CLAUDE.md   working agreement for this repo
```

## Scoring

Deterministic: start at 100, subtract weighted penalties per finding, clamp
`[0,100]`. `≥80 allow · 50–79 warn · <50 block`; any `critical` finding forces
`block`. Files changed in a release are weighted `1.6×` (diff-audit). The score is
produced entirely by the heuristic rules so it is reproducible in CI; the LLM
adapter only adds human-readable context in the async-enrich phase, never the
score. Weights live in one policy object (`packages/core/src/score.ts`).

## Supply-chain identity signals (Phase 13)

Two name-only checks catch the older, non-code attack class — a malicious
package published under a name close enough to trick a human or an
automated install:

- **Typosquat detection** — a pure rule flags a package name that's an
  edit-distance/homoglyph near-match of a name in a bundled, static
  popular-package corpus (e.g. `expres` vs `express`). `medium` severity.
- **Dependency-confusion detection** — a score-time check flags a *public*
  package name that's a look-alike of one of your claimed
  `privateNamespaces` (the same field that gates private-store serving) —
  the signal only Sentinel can produce, since it's the only layer here that
  holds your namespace claims. `high` severity. Never flags the legitimate
  claimed package itself.

Both are weighted findings that raise the score, not automatic blocks — see
[ADR-0026](./docs/adr/0026-supply-chain-identity-heuristics.md).

## Maintainer & release-anomaly signals (Phase 16)

Every rule through Phase 13 scores a release in isolation. Phase 16 adds
cross-version context (a `ReleaseContext` derived from the packument's own
`time`/`maintainers` history — no new network call) and four weighted
`metadata` signals that compound with everything else:

- **Maintainer change** — none of the previous version's maintainers
  remain ⇒ `high` (possible account/ownership takeover); the set changed
  but at least one previous maintainer remains ⇒ `low`.
- **Dormancy resurrection** — the package was silent ≥365 days before this
  release ⇒ `low`.
- **New-package risk** — a first-ever published version that already runs
  install scripts ⇒ `medium`.
- **Capability novelty** — this release adds a `network`/`process`
  capability the immediately-previous version didn't have ⇒ `medium`.

All four are inert without the underlying packument history (e.g. a
private-store package) and none is a standalone hard block — see
[ADR-0029](./docs/adr/0029-release-anomaly-signals.md).

## Known-advisory (known-malicious) detection (Phase 21)

Every rule through Phase 16 infers risk from behavior, identity, or release
history. Phase 21 adds the one signal none of them provide: a check against
**already-confirmed-malicious** package versions.

- **Bundled corpus** — `packages/core/src/advisory-corpus.ts` ships a
  static, offline snapshot of real, publicly-documented compromised npm
  releases (e.g. `event-stream@3.3.6`, `ua-parser-js@0.7.29`) with their
  GHSA advisory ids. Metadata only, never fetched at audit time.
- **`known-advisory` rule** — an exact `(name, version)` match against the
  bundled corpus (or an operator-supplied advisory) emits a `critical`
  `metadata` finding by default, naming the advisory id — this **hard-blocks**
  under the default policy.
- **Bring your own advisory list** — set `SENTINEL_ADVISORIES` to a path to
  a JSON `Advisory[]` file (`{ name, version, id, severity?, reference? }[]`)
  on the proxy; it's read once at startup and merged with the bundled
  corpus, so an unreadable file fails the process closed rather than
  silently running without your entries.
- **Refreshing the bundled corpus** — the bundled snapshot goes stale as new
  malicious releases are discovered. `npm run advisories -- --in
  <export.json>` (`scripts/make-advisories.ts`) transforms a local
  OSV/GHSA "malicious-packages" export into a ready-to-paste
  `KNOWN_ADVISORIES` array; it does not fetch anything itself — see the
  script's header comment for the expected input shape and source
  pointers.

Exact-match only (no semver ranges yet); the one finding type Sentinel's own
remediation guidance tells you not to waive — see
[ADR-0034](./docs/adr/0034-known-advisory-detection.md).

## Known-vulnerability (SCA) detection (Phase 22)

`known-advisory` (above) catches confirmed-malicious releases by exact
version. Phase 22 adds the far more common case: a legitimate package with a
publicly-disclosed **CVE affecting a range of versions** — full software
composition analysis (SCA), not just malware detection.

- **Bundled corpus** — `packages/core/src/vuln-corpus.ts` ships a static,
  offline snapshot of real npm CVEs (`lodash`, `minimist`, `axios`,
  `node-fetch`, `ws`) with their affected semver ranges, CVSS-derived
  severity, advisory id, and fixed version(s). Metadata only, never fetched
  at audit time.
- **`known-vulnerability` rule** — matches the audited version against any
  range in the bundled corpus (or an operator-supplied vulnerability) via
  `semver.satisfies`. Each match emits a finding at the advisory's own
  **faithful** severity — a `critical` CVE **hard-blocks** under the default
  policy exactly like any other critical finding, tunable via the same
  `hardBlockSeverity`/`allow`/rule-disable/`treeGate` levers as everything
  else (no new policy field).
- **Bring your own vuln feed** — set `SENTINEL_VULNERABILITIES` to a path to
  a JSON `VulnAdvisory[]` file (`{ name, ranges, severity, id, fixedIn?,
  reference? }[]`) on the proxy; it's read once at startup and merged with
  the bundled corpus — an unreadable *or* corrupt file fails the process
  closed rather than silently running without your entries.
- **Refreshing the bundled corpus** — the bundled snapshot goes stale as new
  CVEs are disclosed. `npm run vulns -- --in <export.json>`
  (`scripts/make-vulns.ts`) transforms a local OSV/GHSA export into a
  ready-to-paste `KNOWN_VULNERABILITIES` array; it does not fetch anything
  itself — see the script's header comment for the expected input shape and
  source pointers.
- `audit-tree` gains a `vulnerabilities` count of packages carrying a
  known-vulnerability finding, alongside its existing verdict/provenance/
  integrity-mismatch counts.

See [ADR-0035](./docs/adr/0035-known-vulnerability-sca.md).

## Concealed native-payload detection (Phase 34)

A supply-chain incident shipped a compromised package whose loader unpacked
and launched a concealed native binary — first from an npm `preinstall`
hook, then, in a second generation, inlined directly into the package's
entry point and CLI with no lifecycle script at all. Phase 34 closes both
the classification gap and the detection gap:

- **Raw-byte magic classification** — every packaged file is classified by a
  bounded 512-byte sniff of its actual bytes (ELF/Mach-O/PE/WASM/gzip/xz/
  zstd/bzip2/ZIP), not by its declared extension or size. A binary,
  compressed, or archive signature hiding behind a text-looking extension
  (e.g. a `.js` file that's really an ELF binary) surfaces as a
  `content-mismatch` finding; a correctly-declared native/compressed/archive
  asset produces no finding at all.
- **`native-payload-loader` rule** — an AST-based (acorn) rule that flags a
  **dataflow-correlated** chain: a packaged file is read, decoded, written
  to disk, and the written file is launched. It's `critical` only when the
  values/paths are actually linked end to end (not merely present in the
  same file); a matching TypeScript/JSX file that acorn can't parse falls
  back to an independent regex scan capped below critical.

Both signals are **static and deterministic** — no lifecycle script needs to
run, no baseline/previous version is required, and no advisory feed or known
indicator list is consulted. See
[ADR-0049](./docs/adr/0049-native-payload-loader-detection.md).

## Release cooldown (Phase 35)

The same jscrambler incident published all five malicious versions within
hours of each other — a cheap, shape-independent mitigant for that pattern is
simply holding freshly-published versions for a window, giving the ecosystem
time to catch and pull a bad release before it reaches an installer. This is
signed **policy data**, not an environment variable, so it's configured in
the enterprise policy alongside weights and thresholds:

```yaml
# sentinel-policy.yaml
releaseCooldown:
  hours: 72          # hold any version published less than 72h ago
  exempt:
    - "@my-org/*"     # narrow: fast-moving internal packages only
```

- **Fail-closed by default.** A version inside the cooldown window is served
  a `block` verdict, regardless of its score — and so is any version whose
  publish time can't be resolved or parsed at all, so an attacker can't
  defeat the cooldown by omitting the timestamp.
- **`exempt` is a real hole, kept narrow on purpose.** Anything matching an
  exempt glob (`matchPackage`, the same anchored-glob matcher
  `privateNamespaces` uses) bypasses the window from the moment it's
  published — useful for a fast emergency-fix release, but a standing risk
  decision per entry. Prefer specific package names or a tight internal
  namespace over a broad wildcard.
- **`SENTINEL_POLICY=block` vs `observe`.** Under `block` (non-default), a
  cooldown-held version 403s at the tarball route exactly like any other
  blocked verdict. Under `observe` (default), the held verdict is reported
  everywhere — headers, `/-/audit`, `/-/explain`, `/-/audit-tree`,
  `/-/manifest` — but the tarball is still served, same as any other
  observe-mode block reason.
- **Serve-time overlay, like quarantine** — no wall-clock read happens
  inside the scoring engine; the cached audit score is never mutated, and a
  request past the window re-derives `allow` from the same unchanged report.

See [ADR-0050](./docs/adr/0050-release-cooldown-overlay.md).

## Phase log

The build history lives in the [ADR index](./docs/adr/README.md) — one decision
record per phase, from the auditing-proxy wedge (ADR-0001) through the
release-cooldown overlay (ADR-0050). See [ARCHITECTURE.md](./ARCHITECTURE.md) for the
current design as a whole; the old narrative phase log is archived in
[docs/archive/](./docs/archive/).

## License

Apache-2.0.
