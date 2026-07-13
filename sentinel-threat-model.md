# Sentinel — Threat Model

> Snapshot: 2026-07-13, including Phase 30 / ADR-0045. If the
> ADR log has moved past that, check newer ADRs for controls added since.

This document is for a security engineer evaluating Sentinel before adopting it.
It reframes the project's decision log for an external reader: every behavioral
claim below traces to [ARCHITECTURE.md](./ARCHITECTURE.md) or a specific ADR in
[docs/adr/](./docs/adr/), cited inline. Nothing here is aspirational — if a
control is described, it is implemented and tested on the main branch; if a gap
is accepted, the ADR that accepted it is named.

Sentinel is an agent-auditable security layer for npm: a transparent auditing
mirror plus authoritative native write path that scores every tarball before
install-time code can run (ADR-0001), a signed per-enterprise policy gate
(ADR-0012/0014), a deny-by-default install-script sandbox on macOS (Seatbelt)
and Linux (bubblewrap) (ADR-0016/0018/0038), offline signature and provenance
verification (ADR-0021/0022), and an MCP control surface for agents
(ADR-0024). Unclaimed public packages remain transparent mirrors with only
`dist.tarball` URLs rewritten; native names are isolated and authoritative
(ADR-0005/0045).

## 1. System overview & trust boundaries

```
             ┌─────────────────────────────────────────────────────┐
             │ (e) OPERATOR TRUST MATERIAL — static, never fetched │
             │     at audit time:                                  │
             │     · policy signing keypair (Ed25519,              │
             │       ADR-0012/0014)                                │
             │     · NPM_SIGNING_KEYS registry-signature keyset    │
             │       (ADR-0021)                                    │
             │     · pinned Sigstore roots, packages/core/trust/   │
             │       (ADR-0022)                                    │
             │     · attestation signing keys, operator-side only  │
             │       (ADR-0032)                                    │
             └──────────────────────────┬──────────────────────────┘
                                        │ loaded once at startup /
                                        │ committed in the repo
                                        ▼
┌──────────────────┐  (a)   ┌───────────────────────┐   (b)   ┌──────────────┐
│ npm upstream     │◀──────▶│    Sentinel proxy     │◀───────▶│ installer    │
│ registry.npmjs.  │ origin-│  audit → score →      │ verdict │ npm / yarn / │
│ org (untrusted   │ pinned │  integrity-keyed      │ headers │ pnpm / npx   │
│ content)         │ fetch, │  cache → serve gate   │ + 403   │              │
└──────────────────┘ byte-  │  (403 on block /      │ gate    └──────┬───────┘
                     capped │  unapproved caps)     │                │ (c)
                    ADR-0036│                       │                ▼
                    ADR-0037└───────────┬───────────┘        ┌──────────────────┐
                                        │ (d)                │ sandboxed        │
                            ┌───────────┴───────────┐        │ lifecycle        │
                            │ control plane         │        │ scripts          │
                            │ POST/DELETE /-/       │        │ Seatbelt / bwrap │
                            │ approvals, violations,│        │ deny-by-default  │
                            │ approval-requests,    │        │ writes + $HOME   │
                            │ publish               │        │ reads, scrubbed  │
                            │ Ed25519 role tokens:  │        │ env              │
                            │ operator/agent/       │        │ ADR-0016/0017/   │
                            │ publisher             │        │ 0018/0019/0038   │
                            │ ADR-0024/0025         │        └──────────────────┘
                            └───────────────────────┘
```

**(a) npm upstream ↔ proxy.** All upstream content — packuments, tarballs,
attestation bundles — is untrusted input, audited as bytes. Outbound tarball
fetches are origin-pinned: a URL is fetched only if its origin is the
configured registry (`SENTINEL_REGISTRY`) or an entry in the optional
`SENTINEL_TARBALL_ORIGINS` allowlist; anything else is rejected as a 502
before any request is issued, so there is no DNS or private-IP surface to
defend separately (ADR-0036). Fetches are byte-capped and abort mid-stream
over the cap (ADR-0037). The tarball's integrity is recomputed from the bytes
actually served, never trusted from the packument's claim (ADR-0022).

**(b) proxy ↔ installer.** The packument passes through verbatim except for
`dist.tarball` rewrites (ADR-0005), which guarantee every tarball fetch is
intercepted. The tarball response carries `x-sentinel-score` /
`x-sentinel-verdict` headers; under a `block` policy the proxy refuses with
403 instead of streaming bytes (ADR-0001), and also 403s on unapproved new
capability atoms (ADR-0011/0013). The audit runs synchronously on the tarball
request from static analysis only, cached by integrity hash (ADR-0003/0004).
Inbound, tarball-URL rewrites use a configured `SENTINEL_PUBLIC_BASE_URL`; a
Host-derived base is permitted only for loopback Hosts, and any other Host is
refused with 421 (ADR-0036).

**(c) installer ↔ sandboxed lifecycle scripts.** `sentinel install --enforce`
sets `npm_config_script_shell` so every lifecycle script in the tree runs
under `createSandbox()` — Seatbelt on darwin, bubblewrap on Linux, fail-closed
throw on any other platform (ADR-0016/0018/0019). The sandbox enforces the
package's *approved* capability manifest: writes are deny-by-default with a
fixed, non-configurable floor, and `$HOME` reads are deny-by-default with a
read-allow list (node prefix, project root, build caches); `SENSITIVE_PATHS`
carve-outs re-deny credential and persistence paths even under an allowed
ancestor (ADR-0038). The child's environment is scrubbed to a fail-closed
allowlist plus explicitly approved `env` capabilities, dropping
operator-shell secrets (ADR-0017/0019).

**(d) control plane ↔ roles.** The six mutating routes — approvals
(create/delete), violation report/delete, approval requests, and publish —
are gated by signed, stateless Ed25519 role tokens (`operator`, `agent`,
`publisher`) when `SENTINEL_AUTH_PUBKEY` is set: 401 for no valid identity,
403 for a valid identity with the wrong role. Every read stays open in every
mode (ADR-0025). The MCP surface for agents is request-not-grant by design:
the only write tool records a *pending* approval request; there is no
auto-approve or clear-quarantine tool, and with auth enabled an agent-role
token gets a hard 403 on the grant route (ADR-0024/0025).

**(e) operator trust material.** Everything cryptographic is a static input,
never fetched at audit time: the Ed25519 policy signing keypair — the proxy
verifies the policy's raw bytes at startup and an invalid policy fails closed
(ADR-0012/0014); the `NPM_SIGNING_KEYS` set for offline registry-signature
verification (ADR-0021); the pinned Sigstore trust roots in
`packages/core/trust/` for provenance deep-verify (ADR-0022); and attestation
signing keys, which live operator-side in the CLI — the proxy never holds a
signing key (ADR-0032).

## 2. Assets

- **Developer credentials and environment variables.** SSH keys, cloud
  credentials, `~/.npmrc`, `*_TOKEN`/`*_SECRET` env vars. Protected
  statically by the `secret-exfil` rule (read-correlated-with-egress is
  critical) and at runtime by env scrubbing (ADR-0017) plus the sandbox's
  deny-by-default `$HOME` reads and credential-path write denies (ADR-0038).
- **Verdict integrity.** The 0–100 score and verdict are the product; if an
  attacker can change what verdict a client sees, everything downstream
  fails. Defended by deterministic scoring (same input + same policy ⇒ same
  score, ADR-0002), score-time policy application over a signed policy
  (ADR-0014), and the rule that quarantine is a serve-time overlay on a
  *copy* of the report — the cached score is never mutated (ADR-0023).
- **Policy signing keys.** Whoever signs the policy controls thresholds,
  waivers, and hard-block behavior for every install (ADR-0012/0014). Key
  custody is the operator's problem (see Out of scope), but the proxy fails
  closed on an invalid signature rather than falling back to a permissive
  default.
- **The private-namespace store.** Packages under claimed namespaces are the
  enterprise's proprietary code. Claimed names are authoritative: served only
  from the private store, never from public npm, and an unpublished claimed
  name is a 404, not a passthrough (ADR-0010/0015).
- **Native publication integrity.** A version becomes visible only after strict
  parsing, deterministic audit, policy gating, and an atomic tarball+metadata
  commit. A failed, interrupted, or duplicate PUT cannot expose a partial or
  replace immutable bytes (ADR-0045).
- **Audit history.** The opt-in `HistoryDb` (ADR-0028) feeds metrics and the
  policy impact preview (ADR-0033). It is read-back only — it never
  influences a verdict — but it is an information asset (what an org
  installs) served on open read routes.
- **The integrity-keyed cache.** Cache poisoning would let one poisoned audit
  stand in for a legitimate package. The cache key is the hash of the bytes
  Sentinel actually served — recomputed, not the claimed `dist.integrity` —
  and a claimed≠actual mismatch is itself a critical finding (ADR-0004/0022).

## 3. Attacker capabilities & abuse paths

### 3.1 Malicious package author

An author publishes a package whose install scripts or code exfiltrate
secrets, download second stages, or obfuscate payloads. Every tarball is
statically scored before install-time code can run, by nine deterministic
rules — install-script analysis, secret-read/egress correlation, network
egress patterns, obfuscation signatures, and metadata rules (ADR-0001,
ARCHITECTURE §4.1). A finding on a file *added or changed* since the previous
version carries a diff multiplier, targeting the patch-release-compromise
pattern (ADR-0008). Under a `block` policy the tarball is refused with 403;
under `--enforce`, even a package that evades static detection runs its
scripts inside the deny-by-default sandbox (ADR-0019/0038).

### 3.2 Compromised maintainer / release

An attacker takes over a legitimate package (the `event-stream` pattern) and
ships a malicious release. Beyond the diff-audit multiplier (ADR-0008),
release-context signals flag a full maintainer-set turnover (high), a
maintainer addition (low), a ≥365-day dormancy resurrection (low), and a
first-ever version that already runs install scripts (medium); a sibling
check flags a newly-added network/process capability relative to the previous
version (ADR-0029). All are weighted findings derived only from immutable
packument data — deliberately compounding signal, never a standalone hard
block (ADR-0029).

### 3.3 Name squatter / dependency confusion

An attacker registers a look-alike of a popular name, or a public package
shadowing an internal one (Birsan-style dependency confusion). The
`typosquat` rule flags edit-distance/homoglyph matches against a bundled
static corpus of popular names, and a score-time `dependency-confusion` check
flags public look-alikes of the operator's claimed `privateNamespaces` —
both weighted, deterministic, and inert until an operator opts in with
claims (ADR-0026). Independently, and fail-closed rather than heuristic:
claimed private namespaces are *authoritative* — a name matching a claim is
never served from public npm at all, so the classic confusion attack (public
registry wins the race) is structurally closed for claimed names
(ADR-0010/0015).

### 3.4 Known-bad releases

Publicly documented compromised releases and vulnerable version ranges. The
`known-advisory` rule hard-blocks an exact `(name, version)` match against a
bundled static corpus of verified malicious releases (ADR-0034); the
`known-vulnerability` rule matches semver ranges from a bundled CVE corpus
and emits findings at the advisory's own faithful severity, so a critical CVE
hard-blocks under the default policy (ADR-0035). Operators extend both via
`SENTINEL_ADVISORIES` / `SENTINEL_VULNERABILITIES` files loaded once at
startup — fail-closed (FATAL on an unreadable or corrupt file), and never
fetched live on the audit path (ADR-0034/0035).

### 3.5 Malicious packument steering the proxy's fetches (SSRF) — closed

A poisoned packument (or compromised upstream) claims a `dist.tarball` URL
pointing at internal services or cloud metadata endpoints. Closed: the tarball
URL's origin must be the configured registry origin or an allowlisted entry,
checked before any request is issued; a disallowed origin is never fetched
(ADR-0036).

### 3.6 Host-header spoofing of rewritten tarball URLs — closed

A client or misconfigured reverse proxy supplies a spoofed Host, steering the
packument's rewritten `dist.tarball` links at an attacker-controlled origin.
Closed: with `SENTINEL_PUBLIC_BASE_URL` set, the request's Host is ignored;
unset, a Host-derived base is allowed only for loopback Hosts and anything
else is refused with 421 — a network deployment cannot silently run in the
spoofable mode (ADR-0036).

### 3.7 Resource exhaustion

Oversized tarballs/packuments, huge coordinate lists, cache stampedes, and
hammering of expensive read endpoints. Mitigated: streamed byte caps with
up-front content-length rejection and mid-stream abort
(`SENTINEL_MAX_TARBALL_BYTES` / `SENTINEL_MAX_PACKUMENT_BYTES`); a tree-size
cap returning 413 instead of silently truncating
(`SENTINEL_MAX_TREE_PACKAGES`); request coalescing so concurrent uncached
audits of the same coordinate share one pipeline; and an opt-in token-bucket
rate limiter (429 + `Retry-After`) on the expensive endpoints, keyed by
socket address, never `X-Forwarded-For`. Install-gate paths are never
rate-limited (ADR-0037).

### 3.8 An agent holding a control-plane token

An AI agent integrated via MCP (or any caller with an `agent`-role token)
tries to approve its own install, clear a quarantine, or grant a waiver. The
MCP tool surface has no grant tool at all — the only write records a pending
request a human must act on (ADR-0024) — and with auth enabled this boundary
is enforced at the HTTP layer: an `agent` token on `POST /-/approvals` gets a
403; only an `operator` token is accepted (ADR-0025). Tokens are stateless
and TTL-bounded; there is no revocation list — a compromised token is bounded
by its expiry, and full revocation is key rotation (ADR-0025). A spoofed
violation report can only quarantine an already-audited integrity and only
force `block`, never relax a verdict — a fail-closed denial of service, not a
bypass (ADR-0023).

### 3.9 A lifecycle script trying to escape the sandbox

A script whose static audit passed (or was approved) attempts credential
reads, persistence writes, or exfiltration at install time. Writes are
deny-by-default: a blanket deny plus a fixed, non-operator-configurable write
floor (cwd, temp dirs, `/dev`, node build caches); approved `filesystem:`
Grants are directional — a Grant covers exactly its own subtree, never an
ancestor — and pathological Grant targets (`*`, `/`, `..` segments) are
fail-closed rejected (ADR-0038). `$HOME` reads are deny-by-default behind a
read-allow list, so SSH keys, cloud credential files, and arbitrary user
documents are denied at the kernel as a class, while the node runtime and
project tree stay readable (ADR-0038). `SENSITIVE_PATHS` carve-outs re-deny
credential/persistence paths even under an allowed ancestor. Network is
all-or-nothing per approval (Seatbelt cannot host-filter; per-host fidelity
lives on the proxy) (ADR-0016/0018). The environment is scrubbed to an
allowlist, so an escaped-detection script still does not see
`SSH_AUTH_SOCK`, `AWS_*`, or `NODE_AUTH_TOKEN` (ADR-0017/0019). A confirmed
runtime violation revokes any standing approval and quarantines the integrity
at serve time (ADR-0023).

**Enforcement scope — process execution: macOS enforces the floor + carve-out;
Linux enforces the floor where Landlock + the from-source helper are available
(advisory otherwise), plus the carve-out always.** The `process` and `native`
capability kinds are detected and fed to scoring, and on macOS (Phase 28,
ADR-0042) an exec is enforced deny-by-default: a spawn is kernel-permitted only
from the fixed exec floor (system dirs, node prefix, project tree,
developer/Homebrew toolchains) or an approved `process:` Grant, with
exfil-capable tools (curl, wget, nc, …) re-denied inside the floor unless
granted. On Linux (Phase 29, ADR-0043) bwrap cannot path-gate exec at all, so
the exfil-tool carve-out is enforced independently of any floor: each
`SENSITIVE_EXECUTABLES` literal is masked with `--ro-bind /dev/null` unless a
`process:` Grant lifts it, so a denied carve-out exec is still kernel-denied and
surfaces as a confirmed violation. Phase 2 (Landlock, ADR-0044) closes the
Linux floor gap where the kernel and toolchain allow it: a first-party,
from-source `landlock-exec` helper, compiled by a `npm run build` step (Linux +
`cc` only, no-op elsewhere) and invoked inside bwrap, applies
`LANDLOCK_ACCESS_FS_EXECUTE` over the floor (`execAllowFloor` plus the
library/linker dirs `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`) before exec'ing
the lifecycle script — a dropped binary outside that floor is kernel-denied.
Detection is fail-open and pre-checked (the helper must exist AND pass a
`--check` ABI probe, cached); any negative falls back to the Phase 29 advisory
floor with a one-time notice, so a Landlock-less or no-`cc` host is unaffected
and stays filesystem+network confined as before. The Phase 29 `/dev/null`
carve-out is unchanged (Landlock is allow-list-only and can't deny a literal
under an allowed dir). `native` is advisory-only on both platforms by decision.
A spawned child inherits the filesystem/network confinement on both platforms.
A cross-platform exec floor now exists (macOS Seatbelt, Linux Landlock where
available); [issue #8](https://github.com/git-agentic/pkg-registry/issues/8)
is closed, with the Landlock-availability caveat documented here.

## 4. Accepted limitations

Stated plainly. Each is a deliberate, recorded trade-off, not an oversight.

- **Heuristics are signal, not proof.** The rules are static pattern
  detection; misses are expected, both false negatives (novel or
  well-disguised malware scores clean) and false positives (a legitimate
  build script trips `install-scripts`). Sentinel's stance is
  defense-in-depth — score, gate, sandbox — not a guarantee that a scored
  `allow` is safe (ADR-0001/0002/0008).
- **`process` exec floor is enforced on macOS, and on Linux where Landlock +
  the from-source helper are available (advisory otherwise); the exfil-tool
  carve-out is enforced on both platforms unconditionally; `native` is
  advisory everywhere.** On macOS an unapproved exec outside the floor is
  kernel-denied (ADR-0042), with a recorded residual: a package may exec a
  binary written into its own project tree (floor decision) — the same
  residual now applies on a Landlock-enforced Linux host. On Linux (Phase 29,
  ADR-0043) the exfil-capable tools (curl, wget, nc, …) are individually
  exec-denied via `/dev/null` masking regardless of floor availability; Phase 2
  (Landlock, ADR-0044) additionally kernel-denies a dropped binary outside the
  floor on hosts where Landlock + a compiled `cc` toolchain are available
  (fail-open, pre-checked detection with a one-time notice on fallback) — a
  host without either stays on the Phase 29 advisory floor, filesystem+network
  confined as before, no availability regression. `native` loading is not
  distinguishable from reading at the path level and stays a scoring signal. A
  cross-platform floor now exists; see §3.9;
  [issue #8](https://github.com/git-agentic/pkg-registry/issues/8) is closed
  with the availability caveat documented above.
- **A swallowed denial evades telemetry, not containment.** The runtime
  violation sensor only sees denials that surface as process failure. A
  script that catches the sandbox's denial and exits 0 is invisible to
  telemetry — but the sandbox still denied the syscall exactly as before;
  containment is unchanged (ADR-0023).
- **Seatbelt and bwrap report differently.** A denied `$HOME` read surfaces
  as EPERM under Seatbelt, which `classifyViolation` reports as a `confirmed`
  violation; under bwrap the tmpfs makes the path ENOENT, which is not
  classified. The read is contained on both backends — only the report
  differs (ADR-0038, extending ADR-0023). Similarly, a denied write to a
  non-sensitive, non-floor path is contained but attributes as ambient
  (`null`), since confirmed attribution covers only the finite
  `SENSITIVE_PATHS` deny set (ADR-0038).
- **LLM enrichment is advisory-only, never the verdict.** The LLM adapter
  runs only in the async enrich phase and can only add a summary and
  supplementary findings; a missing API key or a model outage never changes
  a verdict. The default adapter is a no-op and the engine is fully offline
  (ADR-0002/0003).
- **Several stances are deliberately fail-open.** Each rule is individually
  wrapped in try/catch — a buggy rule must not take down an install
  (invariant #6). An unresolvable package in an `audit-tree` run becomes a
  surfaced `error` row that does not trip the gate unless the caller opts
  into `--fail-on-error` (ADR-0020/0027). An attestation-bundle fetch
  failure — including an over-cap response — yields `null` (provenance
  `unknown`), not a crash or a block (ADR-0022/0037); note the deliberate
  counterweight: a *present* bundle that fails verification is `invalid` and
  gates fail-closed (ADR-0022).
- **Control-plane reads are open by design.** Auth gates only the six
  mutating routes; every read — audits, manifests, history, metrics,
  audit-tree — is unauthenticated in every mode, preserving the
  transparent-proxy posture. An org that considers its audit history
  sensitive must control network access to the proxy itself (ADR-0025/0028).
- **The corpora are static and dated.** The typosquat popular-name corpus and
  the bundled advisory/vulnerability corpora are committed snapshots,
  regenerated offline — never fetched at audit time. Coverage lags reality
  between regenerations; operator feeds close the gap only as well as the
  operator maintains them (ADR-0026/0034/0035).
- **Network MITM is out of scope.** Sentinel assumes TLS between the proxy
  and the upstream registry and between clients and the proxy; it does not
  defend against an attacker who can strip or forge TLS on either leg.

## 5. Out of scope

- **Runtime application security of installed packages after an `allow`.**
  Sentinel gates installation and contains install-time lifecycle scripts. A
  package that audits clean and behaves maliciously later, at application
  runtime, is outside the enforcement boundary — the sandbox covers lifecycle
  scripts under `--enforce` (ADR-0019/0038), not the application's own
  execution of the dependency.
- **npm account security.** Registry-account takeover, phished maintainer
  credentials, and npm's own infrastructure are upstream of Sentinel; the
  release-anomaly signals (ADR-0029) and signature/provenance checks
  (ADR-0021/0022) detect some *consequences* of a takeover but Sentinel
  cannot prevent one.
- **The operator's own key hygiene.** Custody of the policy signing key, the
  auth token signing key, and attestation keys is the operator's
  responsibility. Sentinel verifies signatures fail-closed
  (ADR-0012/0014/0025/0032) but cannot detect a signature made with a stolen
  key.

## 6. Registry write path and future registry controls

> Phases 30–31 / ADR-0045–0046 are implemented. Sections explicitly labeled
> Phase 32 or 33 remain proposed design and are not shipped.

Accepting writes adds attacker goals a read-only proxy never faced. The
implemented load-bearing property is a name-level
partition — `source(name)` is a pure function of the signed policy and the
claim-corpus input, ordered policy-private → verified-claim → public-mirror,
with no per-version merging (ADR-0045). Phase 31 adds signed loading and steward
semantics while retaining an explicit empty default. Most of the new surface concentrates
on the *inputs* to that function and on the write path itself.

### 6.1 Publisher-credential and trusted-publisher takeover

An attacker steals a publisher role token (ADR-0025) or compromises the CI
identity enrolled as a trusted publisher (ADR-0046) and publishes to a
claimed namespace. One shipped control and one future control bound the damage.
The shipped control is that **credentials
never bypass the audit engine**: every publish gates synchronously on
`runAudit` + `score(policy)` against the policy-data `publishGate`, with no
timeout-fallback-to-allow (ADR-0045) — a stolen credential ships malware only
if the payload also scores clean, which is the same heuristics-are-signal
residual as §4, not a new one. The proposed Phase 32 retraction window (ADR-0047)
gives the legitimate owner an operator-side recovery path that does not
require re-taking the compromised credential — retraction is an instance-side
act, deliberately unlike Go's publish-a-new-version model. Residuals: a
clean-scoring backdoor published with valid credentials (unchanged from §4),
and provenance that *validly* attests a compromised CI run — the TanStack
May-2026 pattern; the design treats OIDC as publish-auth precisely because it
cannot prove more than build origin.

### 6.2 Steward and signed claim-corpus compromise (Phase 31 — implemented)

The claim corpus is signed, versioned, distributed offline, and verified
fail-closed at boot (ADR-0046) — so *tampering* in distribution is detected,
and the meaningful attack is upstream: compromise of the steward's corpus
signing key, or a hostile/coerced steward issuing a corpus that re-routes
names (a forged claim over a popular namespace would eclipse public npm
fleet-wide, by the same partition mechanism that protects legitimate claims).
Design mitigations: the corpus key is operator-trust-material of the same
class as the policy key (§4 key-hygiene stance applies); **local policy
sovereignty** — policy-private outranks every claim, so an operator can pin
any name against a hostile corpus; **30-day timelocked corpus entries** for
transfers, dispute rulings, and Tier-2 grants make the dangerous mutations
visible in corpus diffs before they take effect; voluntary transfers must
verify against the current claimant's Ed25519 key; published versions retain
their publication-time claim attribution; and claims are
non-overlapping by construction, so a forged claim cannot silently shadow an
existing one. Residual, stated plainly: the steward is a deliberate trust
chokepoint — corpus-key compromise is in the same catastrophic class as
policy-key compromise, and the timelock is the detection window.

### 6.3 Claim forgery (Phase 31 — implemented)

An attacker attempts to acquire a claim they are not entitled to: a lookalike
domain (`tanstack-js.dev`, homograph variants) passes its own DNS TXT
challenge trivially, so **domain control alone never grants a contested
name**. The design's control is the three-tier grandfathering rule, derived
from an authoritative upstream lookup owned by the steward rather than
applicant input (ADR-0046): Tier-1 auto-grant requires the *upstream package's
own metadata* to corroborate the claimant's domain — a pure function the
attacker cannot satisfy without already controlling the upstream package; Tier-2 (an active
unlinked upstream publisher — the squatting-dispute tier) is refused by
default and requires PEP-541-grade evidence plus the 30-day timelocked entry;
brand-dispute adjudication is categorically refused, closing the
social-engineering-via-mediation channel crates.io documented. Renewal
failure freezes a claim rather than releasing it, so domain expiry is not a
takeover path (ADR-0046). Residuals: DNS takeover of the *legitimate* domain
during a challenge or renewal window defeats the mechanism by satisfying it
(upstream of Sentinel, like npm account security in §5); and Tier-2 evidence
review is a human judgment — the steward's narrow adjudication question is
the control, not a proof.

### 6.4 Retraction abuse (Phase 32 — proposed)

An attacker (hostile maintainer, compromised publisher, or coerced org)
tries to grief a dependency out of existence — the left-pad goal. The dual
window bounds this **structurally**: a version past 72 hours *or* 1,000
cumulative downloads cannot be retracted by anyone, ever (ADR-0047), so the
packages whose disappearance would cascade are exactly the ones that cannot
disappear. Inside the window: damage is bounded to young, low-adoption
versions; every retraction emits an attributed advisory (synchronously
local, corpus-cadence fleet-wide); tombstones are permanent and identifiers
spent, so retract-then-republish substitution is rejected by construction;
and history — audits, attestations, history-DB rows — survives retraction
byte-identically, so the record of what was served cannot be erased by the
mechanism (ADR-0047). Residuals: churn-griefing of young releases is an
annoyance the advisory trail makes visible but does not prevent; and the
window means Sentinel **cannot** serve as a takedown mechanism for
widely-adopted content — legal takedowns are an operator/steward process
outside this design, recorded as a boundary, not a gap.

### 6.5 Resolution-merge downgrade attacks

The classic attack — steer an installer's semver range to an
attacker-supplied higher version on the attacker-writable side — is
**inexpressible** under the partition rule: no packument ever unions native
and upstream versions, so there is no race for a resolver to lose
(ADR-0045). The attack therefore moves to changing `source(name)` itself.
The policy input is signed fail-closed (ADR-0012/0014). Phase 31's claim data
is a signature-verified trust input with the steward controls in §6.2. Another future path is
**mode-revert resurrection** (Phase 33) — disabling registry mode flips
previously-claimed names back to public-mirror, handing their resolution to
whatever squats them upstream. Phase 33 proposes making that flip loud rather than
silent: with native content present it is a startup FATAL without an
explicit acknowledgment, and the revert manifest enumerates every name whose
resolution class changes, with the safe migration path stated (ADR-0048).
Residual: an operator who acknowledges the manifest without reading it has
accepted the resurrection knowingly — the control is auditability, not
prevention. The mirrored path's behavior — packument transparency, byte
caps, SSRF pinning, never-rate-limited install gates (§1, §3.5–3.7) — is
unchanged by the write path; publish-path resource abuse rides the existing
caps and rate-limiter design (ADR-0037), with the publish gate's latency
budget enforced as a benchmark, never by fail-open (ADR-0045).
