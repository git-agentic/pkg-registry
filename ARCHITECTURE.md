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

### 3.8 Whole-tree audit (Phase 7, ADR-0020)

`sentinel audit-tree [lockfile]` audits an entire resolved dependency graph in one pass.
The CLI parses the npm `package-lock.json` (v2/v3) `packages` map into deduped, sorted
`{name, version, integrity?}` coordinates (skipping the root entry and `link:`/`file:`
deps) and POSTs them to `POST /-/audit-tree`. The proxy fans out with bounded concurrency
over the same integrity-cached `auditVersion()` path used by the tarball route, then rolls
the per-package verdicts into a worst-case-wins aggregate and a gate decision — both
computed server-side under the loaded policy. The gate trips at the policy's `treeGate`
level (default `block`); a gated tree makes the CLI exit non-zero (the CI contract).
Unresolvable packages become surfaced `error` rows and never trip the gate (invariant #6).
This is a `/-/` batch endpoint, never on the inline tarball request path (invariant #3).

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

Four integration modes, all non-invasive:

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
4. **`sentinel-mcp` (Phase 11, ADR-0024)** — a stdio MCP server
   (`packages/mcp`, `@modelcontextprotocol/sdk`) for agent hosts that speak
   MCP instead of shelling out to the CLI. `createMcpServer(client)` registers
   six tools against a `ProxyClient` — a thin fetch wrapper over the proxy's
   `/-/audit`, `/-/manifest`, `/-/audit-tree`, `/-/violations`, and
   `/-/approval-requests` endpoints, resolving `latest` from the packument's
   `dist-tags` when a version is omitted. Five tools are read-only
   (`sentinel_audit`, `sentinel_audit_tree`, `sentinel_capabilities`,
   `sentinel_check_provenance`, `sentinel_list_violations`); the sixth,
   `sentinel_request_approval`, is the only write path and records a
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
