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
npm test             # 15 tests: engine + end-to-end proxy
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

## CLI

```
sentinel audit <pkg> [version]   pre-install verdict panel (exit 0 allow / 1 warn / 2 block)
sentinel scan  <file.tgz>        audit a local tarball offline (no proxy)
sentinel install [args…]         npm install routed through the proxy
sentinel npx     [args…]         npx routed through the proxy
  -p, --proxy <url>   proxy base URL (default http://localhost:4873)
  --json              raw JSON report
```

The exit codes make `sentinel audit` usable as an agent tool or a CI gate.

### Sandbox (Phase 3, macOS)

On macOS, `sentinel run-scripts <package-dir> [--approve network:host …]` runs the package's lifecycle scripts under a Seatbelt sandbox generated from its approved capabilities; un-approved reads of sensitive **files** (credential paths such as `~/.npmrc`, `.aws/credentials`) and network egress are denied by the kernel. Note: **environment-variable**-borne secrets (e.g. `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`) are NOT scrubbed — the process inherits `process.env`; the `secret-exfil` audit rule flags env reads at audit time.

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

## Status

Phases 1–8 are built. Phase 1 is the transparent auditing proxy. Phase 2 adds the
install-time permission manifest + approval gate, signed per-enterprise policy, and
the private-namespace registry. Phases 3–6 add cross-platform sandbox enforcement
(macOS Seatbelt, Linux bubblewrap) up through `sentinel install --enforce`, which
sandboxes every lifecycle script in the tree. Phase 7 adds `sentinel audit-tree`, a
whole-tree lockfile gate: it audits every package in a `package-lock.json` through
the proxy and exits non-zero if the aggregate verdict trips the policy's `treeGate`.
Phase 8 verifies the npm registry signature offline (ECDSA P-256/SHA-256/DER against a
configured key set) and surfaces `signature`/`provenance` status on every audit; a policy
can require a verified signature or present provenance for matching package names.
See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design and [docs/adr/](./docs/adr/)
for the decision log.

## License

Apache-2.0.
