# Sentinel Phase 2.1 — Permission Manifest & Approval (design)

**Date:** 2026-06-24
**Status:** Approved (brainstorming) — ready for implementation planning
**Implements:** ADR-0011 (install-time permission manifest), stage B
**Sequence context:** Phase 2 pillars build in the order **0011 → 0012 → 0010**. This
spec is the first pillar. It is scoped to ADR-0011 **stage B** (declare + approve,
no sandbox); the sandboxed runner (stage A) and deny-scripts default (stage C) are
explicitly out of scope here.

---

## 1. Goal & driver

Deepen the **agent-auditable** thesis: make a package's *capabilities* explicit and
**approvable before install**, so a human or an orchestrating agent decides what gets
to run rather than discovering it after the fact. The Phase 1 audit *scores* risk;
this phase makes capability an **explicit, recorded, gated decision**.

Success criteria:

1. An agent can ask "what is this package allowed to do?" and get a complete,
   specific capability inventory plus the current approval state — without installing.
2. Under enforcement, **nothing installs unapproved**, and an agent can clear an
   entire dependency tree in a bounded, non-retry workflow (see §6).
3. A new capability appearing in a later release re-triggers approval (the
   event-stream pattern expressed as a capability escalation).
4. All Phase 1 invariants stay intact: scoring is deterministic, the LLM never sets
   a verdict, the malicious fixture stays blocked, rules fail open.

## 2. Decisions locked during brainstorming

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Lead Phase 2 with ADR-0011, stage B; sandbox deferred | Highest leverage on the agent thesis at lowest new-infra cost; reuses existing static analysis. |
| D2 | Enforcement = **gate at the proxy**, folded into the existing `block` policy | Real teeth without a sandbox; reuses the `403` path; no new policy mode. |
| D3 | Capability inventory is **specific** — per-category with concrete targets | "Wants to reach 203.0.113.5" is far more decision-useful to an agent than "uses network". Targets are already in our evidence. |
| D4 | Re-approval trigger = **capability delta vs the prior _approved_ version** | First sight requires full approval; later versions only re-prompt on a *new* capability atom. Minimizes prompt fatigue. |
| D5 | Architecture = **Approach A**: a dedicated capability pass beside the rules, sharing matchers | Complete inventory (not risk-thresholded) while leaving findings/scoring — and their invariants — untouched. (Approach C, inverting the core, deferred as a possible 0012-era refactor.) |

## 3. Component map

Additive changes; Phase 1 scoring/findings code is not modified.

- **`@sentinel/core`** — new **capability extraction pass** run by `auditTarball`
  after the rules, over the same in-memory tarball. Produces a complete
  `RequestedCapabilities` inventory and a `capabilityDelta` vs the diff baseline.
  Deterministic (pure function of files), cached by integrity, attached to
  `AuditReport` (schema `1 → 2`). Rules and the capability pass share low-level
  matchers extracted into a new `detect/` util module (DRY without inverting the core).
- **`@sentinel/proxy`** — new `ApprovalStore` (in-memory + JSON-file, mirroring
  `AuditStore`, keyed by `integrity`); approval reconciliation + gating folded into
  the existing `block` policy path; a structured approval API under `/-/`.
- **`@sentinel/cli`** — new `sentinel manifest`, `sentinel approve`, and
  `sentinel preflight` (tree workflow, §6); `sentinel install` fails closed with a
  pointer to `sentinel approve` when gated.
- **dashboard** — an Approvals panel: gated packages with their new capability atoms
  + Approve/Deny; recent approvals.

**Separation of concerns (invariant-preserving):** `AuditReport` stays a *pure,
deterministic, immutable* artifact (now including capabilities). **Approval is
mutable proxy state**, held entirely in `ApprovalStore` — never in the audit report.
"Same bytes ⇒ same report" continues to hold; approval decisions evolve independently.

## 4. Data model

### 4.1 Core (deterministic, integrity-cached)

```ts
type CapabilityKind = 'network' | 'filesystem' | 'process' | 'native';

// One concrete thing the package can do. The (kind, target) pair is the
// "atom" diffed across versions.
interface Capability {
  kind: CapabilityKind;
  target: string;        // network: host/IP/URL · filesystem: path/glob ·
                         // process: command · native: addon file.
                         // '*' when dynamic/uncomputable, so it can't churn the delta.
  evidence: Evidence[];  // reuse the existing Evidence type (file/line/snippet)
}

interface CapabilityDelta {
  added: Capability[];     // atoms here, absent in the prior PUBLISHED version
  removed: Capability[];   // present in prior published version, gone now (informational)
}
```

`AuditReport` becomes `schema: 2` and gains:

```ts
capabilities: Capability[];                // complete inventory — NOT risk-thresholded
capabilityDelta: CapabilityDelta | null;   // null in 'full' mode (no baseline)
```

Atoms are **normalized** before comparison (lowercased host, trimmed path) so
cosmetic churn does not register as a delta.

### 4.2 Proxy (mutable, integrity-keyed)

```ts
type ApprovalDecision = 'approved' | 'denied';

interface Approval {
  name: string; version: string;
  integrity: string;                    // the gate key (immutable anchor)
  decision: ApprovalDecision;
  approvedCapabilities: Capability[];    // snapshot of what was approved
  actor: { type: 'human' | 'agent'; id: string };
  reason?: string;
  decidedAt: string;                     // ISO-8601
}

// Computed LIVE at the gate; never persisted in the audit report:
type ApprovalState =
  | 'approved'    // explicit approval recorded for this integrity
  | 'inherited'   // covered by an approved prior version's atom set (derived, not stored)
  | 'required'    // unapproved new atoms — gate
  | 'denied'      // explicit denial recorded
  | 'n-a';        // no capabilities at all
```

Only **explicit** human/agent decisions are persisted. `inherited` is **derived
live** on each request — there is **no write on the tarball serve path** (avoids a
serve-path side effect and the associated concurrency concern). `inheritedFrom`
(the version whose approval covers this one) is reported in responses/headers but not
stored as a new approval record.

### 4.3 Schema migration

`schema 1 → 2` is a breaking change to stored audit JSON. The JSON-file `AuditStore`
treats any schema-1 entry as a **cache miss** and re-audits. No migration script;
re-audit is cheap and deterministic.

## 5. Capability extraction & gate logic

### 5.1 Extraction (`@sentinel/core`)

`extractCapabilities(input: AuditInput): Capability[]`, invoked by `auditTarball`
after the rules. It maps the four kinds to detectors that share matchers with the
existing rules via the new `detect/` util module:

| Kind | Sourced from | Target captured |
|---|---|---|
| `network` | `network-egress` matchers (http/https/net/dns, fetch, ws, curl/wget, hardcoded IPs, base64 URLs) | host / IP / URL, else `*` |
| `filesystem` | `secret-exfil` + general `fs` read/write | path / glob (`~/.npmrc`, `.aws/credentials`, …), else `*` |
| `process` | `install-scripts` + `child_process` | command spawned, else `*` |
| `native` | `package.json` `gypfile`/`binding.gyp`, `.node` requires | addon file path |

This is a **superset** of what trips findings: it records the benign-but-real network
call that never escalated to a finding — exactly what an approval decision needs.
Output is neutral (no severity, no weight). Each detector is wrapped per-item in
try/catch (same fail-open discipline as `runRules`). A `capabilities are
deterministic across runs` test parallels the existing scoring determinism test.

### 5.2 Two baselines — stated explicitly (advisor item 2)

There are **two distinct diffs**, and they must not be conflated:

- **`capabilityDelta`** (core, in the report) = current vs the prior **published**
  version. Informational; part of the deterministic, cached artifact.
- **`approvalRequired`** (proxy, at the gate) = current atoms **minus the atoms of
  the most recent _approved_ version**. This is the set a user/agent must actually
  approve. These diverge whenever an intermediate version was never approved.

`GET /-/manifest` returns **both**, and the approval UX/API acts on
`approvalRequired`, not `capabilityDelta`.

### 5.3 Gate logic (proxy, `block` policy only)

On a tarball request, after audit:

```
1. explicit approval for this integrity?
     approved → serve · denied → 403 'denied'
2. else find the latest PRIOR version of this pkg with an 'approved' record
3. inheritedAtoms = that approval's approvedCapabilities  (∅ if none / prior denied)
4. approvalRequired = current.capabilities − inheritedAtoms
5. approvalRequired empty? → state 'inherited' (derived, no write) → serve
   else                    → state 'required' → 403 { error:'approval required',
                                                       approvalRequired, findings }
```

Also keep the existing rule: `verdict==='block'` → `403` regardless of approval.
Under **`observe`**, nothing gates — the proxy only sets `x-sentinel-approval`
(state) and `x-sentinel-capabilities` (count) headers alongside the existing
`x-sentinel-*` headers.

## 6. Dependency-tree workflow (advisor item 1 — the thesis in practice)

Folding approval-required into the `block` path means that under enforcement **every
first-sight package with any capability `403`s** — not just the rare malicious one.
npm aborts on the first `403`, so a naive install becomes enumerate-by-retry hundreds
deep. The agent-auditable thesis therefore requires an explicit **preflight** flow
that approves the *whole tree* before install:

1. **Resolve** the tree without executing it — `npm install --package-lock-only`
   (or `--dry-run`) against the proxy registry yields every `(name, version)` and,
   from the lockfile, each `dist.integrity`.
2. **Preflight** — for each `(name, version, integrity)`, call `GET /-/manifest`.
   Aggregate the union of `approvalRequired` atoms across the tree and the subset of
   packages whose state is `required`/`denied`.
3. **Approve** — present the aggregate to the human/agent; on acceptance, **batch
   approve** via `POST /-/approvals` (the endpoint accepts an array of decisions).
4. **Install** — re-run `npm install` against the proxy; with approvals recorded,
   every tarball now serves (or a deliberate `denied` fails closed with a clear
   reason).

`sentinel preflight <pkg>[@version]` implements steps 1–2 (and offers `--approve` to
chain 3). Acceptance check for this spec: **an agent can clear an N-package tree with
one preflight + one batch approve + one install — no per-package failed install
attempts.**

## 7. API / CLI / dashboard surface

**Proxy API** (reserved `/-/` namespace):

- `GET /-/manifest/:pkg/:version` → `{ meta, score, verdict, findings, capabilities,
  capabilityDelta, approvalRequired, approvalState, inheritedFrom? }`. Audit stays
  pure; this endpoint layers live approval state on top.
- `POST /-/approvals` → body is a single decision **or an array** (for batch/tree
  approval): `{ name, version, integrity, decision, actor, reason? }`. Records the
  `Approval`(s) keyed by `integrity` and returns them. Approval references an
  integrity directly (the immutable anchor); the gate matches by integrity — no
  coupling to a "current version" check (advisor item 5b).
- `GET /-/approvals` → recent approvals + currently-gated packages (for the dashboard).
- `DELETE /-/approvals/:integrity` → revoke (ADR-0011 requires approvals be revocable).

**CLI:**

- `sentinel manifest <pkg>[@version]` — human-readable inventory, both diffs (with
  `approvalRequired` atoms highlighted), and approval state.
- `sentinel approve <pkg>@<version> [--deny] [--reason <r>] [--actor <id>]`.
- `sentinel preflight <pkg>[@version] [--approve]` — the §6 tree workflow.
- `sentinel install …` — unchanged routing; under `block`, fails closed on
  `approval required` with a message pointing at `sentinel preflight`/`approve`.

**Dashboard:** an Approvals panel — gated packages with their `approvalRequired`
atoms and Approve/Deny buttons; recent approvals. Reads `AuditStore` + `ApprovalStore`.

## 8. Security posture & deferred non-goals

- **Approval API authentication/authorization is OUT OF SCOPE for stage B** (advisor
  item 4). Stage B assumes the proxy runs in a **trusted, single-tenant context**
  (local dev / trusted internal network). An open `POST /-/approvals` would let
  anyone reaching the proxy self-approve malware, so authN/authZ is a **named
  prerequisite for any multi-tenant or untrusted-network deployment** and is deferred
  to the per-enterprise/tenancy work (ADR-0012 era). This is called out so it is not
  shipped silently.
- **No runtime enforcement.** Approval gates *distribution* of the tarball, not what
  a script does once it runs. Real least-privilege requires the sandboxed runner
  (ADR-0011 stage A), explicitly deferred.

## 9. Invariants & documentation impact

- **Unchanged:** scoring determinism, LLM-never-scores, transparency (packument
  passthrough), rules-fail-open. Capabilities are pure; approval is out-of-band proxy
  state, so none of these are touched.
- Capability extraction is wrapped per-detector in try/catch (fail-open like
  `runRules`).
- **Docs to update on implementation:**
  - Move **ADR-0011 → Accepted**.
  - Add **ADR-0013** recording the two refinements: (a) gate via the existing `block`
    policy path rather than a new mode; (b) the capability-**delta-vs-prior-approved-
    version** trigger, with the tree-preflight workflow as its necessary complement.
  - **ARCHITECTURE.md**: §4 (capability pass), §5 (schema 2 + Approval), §6 (CLI
    preflight), proxy section (gate + approval API).
  - **CLAUDE.md**: the "must be 15/15" line becomes the new test count.

## 10. Testing

- **core:** per-kind extraction (network/filesystem/process/native); `capabilities
  are deterministic across runs`; `capabilityDelta` added/removed; schema-2 report
  shape.
- **proxy:** first-sight `403 approval required` under `block`; approve-via-API then
  serve; inheritance (approve 1.4.0 → 1.4.1 with same atoms serves without a new
  write); re-gate when 1.4.1 adds an atom; deny → `403`; revoke; batch/tree approval;
  `observe` stays advisory (headers only, never gates).
- **regression (teeth preserved — advisor item 3):** the malicious `color-stream`
  fixture stays blocked **for the right reason** — the test asserts `verdict==='block'`
  / the critical finding, *not* merely `status===403`. To isolate the verdict as the
  block source, the test **pre-approves color-stream's capabilities** so an
  approval-required `403` cannot mask a silently-broken score. Existing determinism +
  scoring tests remain untouched and green.
- **fixture validation:** confirm `color-stream` 1.4.1 (adds `lib/build.js` over
  1.4.0) exercises a real `added`/`approvalRequired` atom, so the delta path is
  covered by an existing fixture.

## 11. Out of scope (recap)

Sandboxed install runner (ADR-0011 stage A); deny-scripts-by-default allowlist
(stage C); author-declared `package.json` manifests as the baseline (near-useless in
stage B — prior-approved-version is the baseline instead); approval API authN/authZ;
per-enterprise signed policy (ADR-0012); private-namespace override (ADR-0010).
