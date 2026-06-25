# Sentinel Phase 2.2 — Signed Per-Enterprise Policy (design)

**Date:** 2026-06-25
**Status:** Approved (brainstorming) — ready for implementation planning
**Implements:** ADR-0012 (per-enterprise policy as versioned, signed data)
**Sequence context:** Phase 2 pillars build **0011 → 0012 → 0010**. 0011 (permission
manifest & approval) is built and merged. This is the second pillar. ADR-0010
(private-namespace override) remains after it.

---

## 1. Goal & driver

Promote the single global `POLICY` object into a **per-enterprise policy document**
that is **versioned and cryptographically signed**, so each customer sets its own
risk appetite and allow/deny lists under change control — without code changes —
while every verdict stays **reproducible and explainable** ("engine vX + policy
version/hash Y"). Driver: the enterprise multi-tenant story (the natural follow-on
to 0011), and taming false positives (e.g. clearing `esbuild`'s legitimate network
postinstall) as policy rather than patches.

Success criteria:
1. The proxy loads a customer's **signed** policy; an invalid/tampered policy **fails
   closed** (never serves, never silently degrades to default).
2. Verdicts are deterministic **given a policy** and every report carries
   `policy: { version, hash }`.
3. Out of the box (no policy configured) behavior is **identical to today** via a
   compiled-in default policy.
4. All Phase 1/2.1 invariants hold: same-bytes audit findings are policy-independent
   and cached by integrity; the LLM never sets a verdict; rules fail open; the
   malicious fixture stays **blocked under the default policy**.

## 2. Decisions locked during brainstorming

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **One signed policy per proxy instance** (loaded at startup) | Smallest lift; matches current deployment; still gets versioning+signing; forward-compatible to per-request multi-tenant later. |
| D2 | **Ed25519 via `node:crypto`**, detached signature over **raw file bytes** | Zero new deps, offline, fits the built-in-crypto ethos. Raw-bytes signing avoids the JSON-canonicalization-mismatch failure class. |
| D3 | Schema = **scoring knobs + per-rule enable/disable + package/namespace allow/deny lists** | Delivers the ADR's headline value (risk appetite + false-positive taming). 0011 manifest-defaults deferred. |
| D4 | Allowlist = **granular waiver, finding stays visible** | "Clear esbuild without weakening detection": waived findings are excluded from scoring **and** hard-block but remain in the report, marked. |
| D5 | Architecture = **Approach A: policy-independent audit + score-time policy** | The only split where "findings are policy-independent" is actually true; one-policy-per-process makes caching trivial. |

## 3. Architecture — the audit/score split

The load-bearing change: separate the **policy-independent audit** (cached by
integrity) from **policy-dependent scoring** (computed live against the active
policy).

### 3.1 Two phases

- **Audit (policy-independent, integrity-cached).** `runAudit(input)` produces
  `{ meta, findings: Finding[], capabilities }`. A `Finding` carries
  `{ ruleId, category, severity, message, evidence, onChangedFile }` — **no
  `weight`**. `mkFinding` stops computing weight; it records `onChangedFile` (the
  diff applicability it currently consumes to bake the multiplier in).
- **Score (policy-dependent, live).** `score(findings, meta, policy)` applies the
  policy and returns `{ score, verdict, findings: ScoredFinding[] }` where
  `ScoredFinding = Finding & { weight, waived, waivedBy? }`.

### 3.2 `auditTarball` survives (explicit blast-radius decision)

`auditTarball` is called by the proxy, the offline CLI `scan`, and most of
`core/test/audit.test.ts` (which asserts `r.score`, `f.weight`, deterministic
weights, diff-mode weight comparison). It is **kept** as a convenience:

```
auditTarball(input) = score(runAudit(input), DEFAULT_POLICY)
```

Because the default policy's knobs equal today's `POLICY`, the weights and scores it
returns are **identical to today**, so `scan` keeps a policy source and every
existing core test passes unchanged. The **proxy** does not use `auditTarball`; it
calls `runAudit` (cache by integrity) + `score(enterprisePolicy)` directly.

### 3.3 Naming (avoid collision)

The proxy already has `type ProxyPolicy = "observe" | "block"` and a `policy`
variable in `server.ts`. The new signed scoring policy is named **`EnterprisePolicy`**
(type) / **`enterprisePolicy`** (variable) everywhere, never bare `Policy`/`policy`,
to keep the two distinct.

### 3.4 Component map

- **`@sentinel/core`** — new `policy.ts` (`EnterprisePolicy` type, `DEFAULT_POLICY`,
  `loadPolicy`/verify, `policyHashOf`, glob matcher); `score.ts` refactored to
  `score(findings, meta, policy)`; `Finding`/`mkFinding`/the four rules drop baked
  weight and record `onChangedFile`; `audit.ts` splits into `runAudit` + the
  `auditTarball` convenience.
- **`@sentinel/proxy`** — loads the signed policy at startup (config + trusted
  pubkey), **fails closed** on a bad policy, threads `enterprisePolicy` into scoring,
  stamps `policy: { version, hash }` + `x-sentinel-policy` header, and scores
  recent audits live for the dashboard.
- **`@sentinel/cli`** — `sentinel policy` (verify/sign/keygen).

## 4. The policy document

### 4.1 Schema (the signed payload — `@sentinel/core`)

```jsonc
{
  "schema": 1,
  "version": "acme-2026.06.25",          // recorded on every verdict for audit
  "scoring": {
    "severityWeight": { "info":0, "low":4, "medium":12, "high":25, "critical":55 },
    "diffMultiplier": 1.6,
    "thresholds": { "allow": 80, "warn": 50 },
    "hardBlockSeverity": "critical"
  },
  "rules": { "disabled": ["obfuscation"] },         // rule IDs turned off for this tenant
  "allow": [
    { "package": "esbuild", "rules": ["network-egress","install-scripts"], "reason": "known native build" }
  ],
  "deny": [
    { "package": "evilcorp-*", "reason": "blocked vendor" }
  ]
}
```

- `version` is a free-form string recorded per verdict.
- `rules.disabled` lists rule IDs whose findings are waived at score time.
- `allow[].package` / `deny[].package` use the glob rule in §4.4. `allow[].rules`
  entries match a finding's **ruleId or category**.
- `DEFAULT_POLICY` (the compiled-in default) equals these exact values with empty
  `rules.disabled`/`allow`/`deny`, so out-of-the-box behavior == today's `POLICY`.

### 4.2 Signing & verification (Ed25519, raw bytes)

- The enterprise signs the **raw `policy.json` bytes** with an Ed25519 private key.
  The proxy is configured with the trusted Ed25519 **public key**. Verification is
  `crypto.verify(null, rawBytes, publicKey, signature)` over the file **as-is** — no
  JSON re-canonicalization.
- Artifacts: `policy.json` + detached `policy.json.sig` (base64 signature).
- `policyHashOf(rawBytes) = sha256(rawBytes)` (hex). Reports carry
  `policy: { version, hash }`.

### 4.3 Loading & failure modes

- **No policy configured** (`SENTINEL_POLICY_FILE` unset) → use `DEFAULT_POLICY`
  (compiled-in, unsigned, implicitly trusted); log it. Only externally loaded
  policies require a signature.
- **Configured but bad** — missing file, parse error, missing pubkey, invalid
  signature, or schema-invalid → **fail closed**: throw at startup, proxy exits
  non-zero, logs the reason. Never silently fall back to `DEFAULT_POLICY` (a tamperer
  must not be able to downgrade by corrupting the file).
- Config env: `SENTINEL_POLICY_FILE`, `SENTINEL_POLICY_SIG` (defaults to
  `<file>.sig`), `SENTINEL_POLICY_PUBKEY` (path to an Ed25519 public key PEM).

### 4.4 `DEFAULT_POLICY` hash & glob rule (completeness)

- `DEFAULT_POLICY` is an in-code constant with no file bytes. Its identity is pinned:
  `version: "default"`, `hash = sha256(canonical JSON of DEFAULT_POLICY)` computed
  once at module load (canonical = `JSON.stringify` with sorted keys). External
  policies use raw-bytes hashing (§4.2); the default uses canonical-JSON hashing —
  they are different sources, intentionally.
- **Glob matching is anchored and literal.** A `package` pattern matches the **full**
  package name; `*` (matching any run of characters) is the **only** metacharacter;
  every other regex metacharacter is escaped. Implementation: escape the pattern,
  replace `\*` → `.*`, wrap as `^…$`, test against `meta.name`. Not substring, not
  regex passthrough.

## 5. Scoring with policy — `score(findings, meta, policy)`

Pure: same `(findings, meta, policy)` ⇒ same result.

**Per finding, in order:**
1. **Rule disabled** (`policy.rules.disabled` includes `finding.ruleId`) → **waived**,
   `waivedBy: "rule disabled: <id>"`.
2. **Allow match** — an `allow` entry whose `package` glob matches `meta.name` **and**
   whose `rules` contains the finding's `ruleId` **or** `category` → **waived**,
   `waivedBy: "allow: <package> — <reason>"`.
3. **Weight:** waived → `0`. Else `round(severityWeight[severity] × (onChangedFile ? diffMultiplier : 1))`.

**Then:**
- `score = clamp(100 − Σ non-waived weights, 0, 100)`.
- `denied = meta.name matches any policy.deny[].package` glob.
- `hardBlock = any **non-waived** finding with severityRank(severity) ≥ severityRank(hardBlockSeverity)`.
- **Verdict order:** `denied → block` · else `hardBlock → block` · else
  `score ≥ thresholds.allow → allow` · else `score ≥ thresholds.warn → warn` · else `block`.

**Invariant points:**
- A waiver removes a finding from **both** the penalty sum **and** the hard-block
  check, while it stays in the report (`waived: true` + `waivedBy`). So an
  allowlisted package clears its *known* critical, but a *different*, un-waived
  critical still blocks.
- `deny` wins over everything; `allow` cannot rescue a denied package.
- **Regression:** under `DEFAULT_POLICY` there are no waivers and the knobs equal
  today's, so `color-stream@1.4.1` stays `block` — the existing malware test holds.

## 6. Proxy caching, report & headers

- `AuditStore` caches the **policy-independent audit** by integrity:
  `{ meta, findings: Finding[], capabilities }`. No policy dimension; integrity is
  immutable and sufficient.
- Score/verdict are computed **live** from `enterprisePolicy` on every tarball
  request and every dashboard read (`/-/audits` scores its recent ≤50 set on the fly).
  A policy change is reflected without re-running static analysis.
- `policyHash` is **not** a cache key — it is stamped on served reports for the audit
  trail. Persisted store entries from the 0011 era (full scored reports) are dropped
  on load by a shape guard (same move as the schema-2 guard shipped in 0011 — and
  the guard must be updated for the new cached shape, not left asserting the old one).
- `AuditReport.findings` → `ScoredFinding[]`; add `policy: { version, hash }`. New
  tarball header `x-sentinel-policy: <version>`. `/-/manifest` surfaces `policy` and
  the `waived`/`waivedBy` markers so an agent sees *why* something cleared.

### 6.1 `createServer` callers in scope (avoid the last-round regression)

Adding the active policy to `ServerOptions` touches **every** `createServer` caller.
All are in scope for the plan and must be updated together:
- `packages/proxy/test/proxy.test.ts` (×2 before-hooks)
- `packages/proxy/src/index.ts` (startup — also loads the policy + pubkey from env)
- `scripts/demo.ts` (offline demo — broke last round when a required option was added)

How the policy reaches the server: `createServer` takes the resolved
`enterprisePolicy` (already loaded+verified by the caller) as a `ServerOptions`
field. `index.ts` does the env-driven load/verify (fail closed); tests and the demo
pass `DEFAULT_POLICY` (or a test policy) explicitly.

## 7. CLI — `sentinel policy`

- `sentinel policy verify <file> --pubkey <key>` — parse, verify the Ed25519
  signature, validate the schema, and print version, hash, rule toggles, and
  allow/deny summary; exit non-zero on any failure. (ADR's validation tool.)
- `sentinel policy sign <file> --key <ed25519-priv-pem>` — write `<file>.sig`
  (detached base64 signature over the raw bytes). Admin/authoring + test-fixture helper.
- `sentinel policy keygen [--out <prefix>]` — generate an Ed25519 keypair (PEM) for
  authoring/testing.

## 8. Determinism, docs & testing

### 8.1 Invariant handling
The determinism invariant is **superseded, not edited** (CLAUDE.md): determinism now
means "same bytes + same policy ⇒ same verdict." The existing `scoring is
deterministic across runs` test stays green by pinning a fixed policy (it goes
through `auditTarball`/`DEFAULT_POLICY`).

### 8.2 Tests
- **core:** `score` is pure/deterministic under a fixed policy; **same bytes under
  two different policies yield different verdicts** (proves policy-dependence);
  `DEFAULT_POLICY` still blocks `color-stream@1.4.1`; an `allow` waiver clears a
  finding from the score **and** the hard-block while keeping it visible+marked; a
  disabled rule waives its findings; `deny` forces `block` on a clean package;
  `severityWeight`/`diffMultiplier`/`thresholds` overrides change the score/verdict;
  glob matching is anchored (does not over/under-match); signature verify pass/fail;
  malformed/schema-invalid policy rejected; `policyHashOf` stable.
- **proxy:** with `DEFAULT_POLICY` all existing proxy tests pass; a test policy with
  a `deny` returns `403`/block on an otherwise-allowed package; a test policy with an
  `allow` serves an otherwise-blocked package (and `x-sentinel-policy` header +
  `policy.hash` are set); startup fails closed on a tampered/invalid signed policy;
  the store drops pre-existing entries of the old shape on load.
- **cli:** `policy verify` passes a correctly-signed fixture and exits non-zero on a
  tampered one; `policy sign`/`keygen` round-trip (keygen → sign → verify).
- **fixtures:** a signed test-policy fixture (generated via `policy keygen`+`sign`,
  or inline `node:crypto` in tests) plus a tampered copy.

### 8.3 Docs
- ADR-0012 → **Accepted**.
- New **ADR-0014** recording the refinements: the score-time weight refactor
  (weight moves out of `mkFinding`), raw-bytes Ed25519 signing, and the
  fail-closed-vs-default loading rule.
- Annotate/supersede **ADR-0008** (diff multiplier is now applied at **score time**,
  not baked at finding creation).
- Update **ARCHITECTURE.md** §4.2 (scoring → `score(findings, meta, policy)`), §5
  (data model: `Finding` loses weight + gains `onChangedFile`; `ScoredFinding`;
  `EnterprisePolicy`; report `policy`), and the proxy section (policy loading +
  fail-closed). Update **CLAUDE.md** invariant #1 wording (deterministic *given a
  policy*) and the test count.

## 9. Out of scope (recap)

Per-request multi-tenant policy routing (D1 defers it); 0011 manifest-defaults in the
policy document (D3 defers it); key rotation / multiple trusted signers / KMS /
Sigstore (a single configured trust anchor for this slice); private-namespace
override (ADR-0010, the next pillar).
