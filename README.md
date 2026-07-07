# Sentinel

**An agent-auditable security layer for the npm ecosystem.** Phase 1 is a
transparent **auditing proxy** that sits in front of `registry.npmjs.org`: it
resolves and serves real packages unchanged, but intercepts every tarball,
scores its contents with a deterministic audit engine, and attaches a verdict —
so an AI agent or a human can see the risk *before install-time code runs*.

> Why: agents now `npm install` and execute untrusted code with zero risk
> signaling. npm can't retract bad releases, has no install-time permissions, and
> lets attackers squat names. Sentinel is the wedge — start as a security/audit
> proxy, then expand into policy and permissions (Phase 2).

See **[ARCHITECTURE.md](./ARCHITECTURE.md)** for the full design (proxy, sync-vs-async
audit placement, data model, npm hooks, stack justification).

---

## Quickstart

```bash
npm install          # install workspace deps
npm run build        # compile all packages (tsc --build)
npm run fixtures     # pack the test fixtures into real .tgz tarballs
npm test             # 308 tests: engine + end-to-end proxy (see CLAUDE.md for the exact/skip breakdown)
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
| `SENTINEL_APPROVAL_REQUESTS` | _(memory only)_ | path to a JSON file to persist pending approval requests (MCP `sentinel_request_approval` and any other caller) |
| `SENTINEL_TRUSTED_ROOT` | _(bundled root)_ | path to a Sigstore `trusted_root.json` for provenance verification (fatal error on a bad path) |
| `SENTINEL_NPM_ATTESTATION_KEYS` | _(bundled keys)_ | path to an npm publish-attestation keys JSON, used alongside `SENTINEL_TRUSTED_ROOT` |
| `SENTINEL_AUTH_PUBKEY` | _(unset ⇒ open)_ | path to an Ed25519 public key PEM; when set, gates control-plane mutations behind signed role tokens (see below) |
| `SENTINEL_AUTH_TOKEN` | _(unset)_ | signed role token attached as `Authorization: Bearer` by the MCP client and `sentinel-script-shell` on their POST calls |

## CLI

```
sentinel audit <pkg> [version]   pre-install verdict panel (exit 0 allow / 1 warn / 2 block)
sentinel scan  <file.tgz>        audit a local tarball offline (no proxy)
sentinel install [args…]         npm install routed through the proxy
sentinel npx     [args…]         npx routed through the proxy
sentinel violations              list runtime violations recorded by the proxy (quarantined builds)
sentinel token keygen --out <prefix>              generate an Ed25519 keypair for control-plane auth
sentinel token mint --role --sub --ttl --key       mint a signed role token (prints to stdout)
sentinel token verify <token> --pubkey             verify a token, print role/sub/exp or the rejection reason
  -p, --proxy <url>   proxy base URL (default http://localhost:4873)
  --json              raw JSON report
```

The exit codes make `sentinel audit` usable as an agent tool or a CI gate.

### Sandbox (Phase 3, macOS)

On macOS, `sentinel run-scripts <package-dir> [--approve network:host …]` runs the package's lifecycle scripts under a Seatbelt sandbox generated from its approved capabilities; un-approved reads of sensitive **files** (credential paths such as `~/.npmrc`, `.aws/credentials`) and network egress are denied by the kernel. Note: **environment-variable**-borne secrets (e.g. `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`) are NOT scrubbed — the process inherits `process.env`; the `secret-exfil` audit rule flags env reads at audit time.

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

## Status

Phases 1–13 are built. Phase 1 is the transparent auditing proxy. Phase 2 adds the
install-time permission manifest + approval gate, signed per-enterprise policy, and
the private-namespace registry. Phases 3–6 add cross-platform sandbox enforcement
(macOS Seatbelt, Linux bubblewrap) up through `sentinel install --enforce`, which
sandboxes every lifecycle script in the tree. Phase 7 adds `sentinel audit-tree`, a
whole-tree lockfile gate: it audits every package in a `package-lock.json` through
the proxy and exits non-zero if the aggregate verdict trips the policy's `treeGate`.
Phase 8 verifies the npm registry signature offline (ECDSA P-256/SHA-256/DER against a
configured key set) and surfaces `signature`/`provenance` status on every audit; a policy
can require a verified signature or present provenance for matching package names.
Phase 9 deep-verifies build provenance: real Sigstore attestation bundles are checked
offline against pinned trust material, `provenance` becomes `verified|invalid|absent|unknown`
with subject-digest binding to the actual served bytes, and a policy can require a verified
attestation from a specific repository, workflow, or builder for matching package names.
Phase 10 turns the enforcing sandbox into a sensor: a denied capability that surfaces as a
process failure is classified and reported to the proxy, which quarantines that exact
tarball fleet-wide (`sentinel violations`, `/-/violations`) as a serve-time overlay — the
cached, deterministic score is never touched, and a denial the package silently swallows is
still contained, just not visible to telemetry.
Phase 11 adds `sentinel-mcp`, a stdio MCP server that is a thin client to the running
proxy: five read tools plus `sentinel_request_approval`, which only ever records a pending
request (`/-/approval-requests`) for a human to approve — the agent requests, never grants.
See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design and [docs/adr/](./docs/adr/)
for the decision log.

## License

Apache-2.0.
