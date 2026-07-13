# Sentinel registry roadmap — Phases 30–33

**Status:** Phases 30–33 shipped
**Date:** 2026-07-11

This is the phased plan for Sentinel's evolution from a transparent auditing
proxy into a first-class registry. It continues the existing phase log — the
[ADR index](../adr/README.md) ends at Phase 29 (ADR-0044) — and assembles the
decisions recorded in ADR-[0045](../adr/0045-registry-write-path-resolution-merge.md)/
[0046](../adr/0046-verified-namespace-claiming.md)/[0047](../adr/0047-time-locked-retraction.md)/
[0048](../adr/0048-migration-compatibility-surface.md). The decision trail
lives on the planning map, GitHub issue
[#33](https://github.com/git-agentic/pkg-registry/issues/33); the evidence
base is the three research notes in [docs/research/](../research/). The new
attack surface is analyzed in the DRAFT section of
[sentinel-threat-model.md](../../sentinel-threat-model.md).

## Why a registry

Two capabilities are structurally unavailable to a proxy, however good its
signal: **verified canonical namespace ownership** (a proxy can only observe
npm's name space, never bind a name to an organization) and **time-locked
retraction** (a proxy cannot unpublish what it does not host). Everything else
Sentinel does — deterministic scoring, policy gating, sandboxing — carries
over unchanged; the registry adds a write path under the same invariants.

Vocabulary used throughout: a **native** package is one published to (or
imported into) Sentinel's own authoritative store, as opposed to **mirrored**
from public npm — no relation to native *binaries* (the ADR-0041/0044 sense).
The **steward** is whoever operates the claim service centrally. Audit
verdicts are `allow | warn | block`.

**The thesis is preserved, verbatim:** scoring stays deterministic given a
policy (invariant 1); publishing gates **synchronously** on the existing audit
engine; the inline gate stays cheap and offline (ADR-0003); caches stay
integrity-keyed (ADR-0004); mirrored packuments stay transparent (ADR-0005).

Two load-bearing rules recur in every phase below, stated once here in full:

> **The resolution precedence rule (ADR-0045):** every package name maps to
> exactly one source class — `source(name)` is a pure function of the signed
> policy and the claim corpus, evaluated as **policy-private →
> verified-claim → public-mirror, first match wins**. A served packument
> never contains versions from two sources. Claims are non-overlapping by
> construction; publish requires a claim — where the publishable name space
> is the signed policy's `privateNamespaces` **∪** verified claims, so
> policy-private namespaces are publishable with no claim corpus at all;
> claimed-but-unpublished names 404 (fail-closed, ADR-0015 semantics).

> **The publish-gate latency budget (ADR-0045):** the gate is synchronous and
> fail-closed with **no timeout-fallback-to-allow**; budget **p50 ≤ 1 s,
> p99 ≤ 15 s** from `PUT` received to verdict returned, within the existing
> byte caps (256 MB fetch, 1 GiB / 100k-file extraction), pinned by a CI
> benchmark. Overruns are fixed by optimizing or moving work to async enrich
> — never by weakening the gate.

## Phase 30 — Registry write path & deterministic resolution merge

**Status:** Complete (2026-07-13)

**ADR:** [0045](../adr/0045-registry-write-path-resolution-merge.md) ·
**Depends on:** nothing new (generalizes ADR-0015)

Generalize the existing private-namespace publish path into the registry
write path: `source(name)` resolution, claim-gated publishing, the
policy-data `publishGate`, and the latency benchmark. This phase can ship
with an empty claim corpus — resolution degenerates to policy → mirror, which
is exactly today's behavior, and publishing works against policy-private
namespaces (they are claims for publishability purposes) — so it has no
dependency on the Phase 31 steward service.

**Entry criteria** (satisfied):
- ADR-0045 reviewed and status-checked (Accepted).
- A latency-benchmark harness exists in CI that times `PUT` → verdict on
  the fixture corpus and on a cap-adjacent synthetic package.
- The claim-corpus input is defined as data (may be the empty corpus).

**Exit criteria** (satisfied and pinned by tests):
- `source(name)` is a pure function of (signed policy, claim corpus): a
  property test evaluates the precedence order deterministically for
  generated (policy, claim-set, name) triples.
- A `PUT` on an unclaimed name is rejected 403 with no store side effects.
- No native/claimed packument ever references an upstream version (fixture
  test over the served documents).
- `publishGate` fixtures pin the publish outcome for all three verdicts
  (`allow`/`warn`/`block`), exercised against a policy-private namespace; the
  403 rejection body carries the full `AuditReport`.
- The latency benchmark is green: fixture-corpus median ≤ 1 s, cap-adjacent
  synthetic ≤ 15 s, and runs as a CI regression tripwire.
- The `scoring is deterministic across runs` test extends to publish: same
  bytes + same policy ⇒ same publish outcome.
- The malicious fixture is still blocked — on install *and* on publish.

Evidence: `packages/proxy/test/resolution.test.ts`, `publish.test.ts`,
`private-serve.test.ts`, `private-store.test.ts`, and
`npm run benchmark:publish`. The Phase 30 corpus input is deliberately
data-only and defaults empty; Phase 31 subsequently added signed loading.

## Phase 31 — Verified namespace claiming

**Status:** Complete (2026-07-13)

**ADR:** [0046](../adr/0046-verified-namespace-claiming.md) ·
**Depends on:** Phase 30 exit

Ownership binds to organizational identity, not registry accounts: DNS TXT
challenges are constitutive of a claim; Sigstore OIDC is optional trusted
publishing under one; claims ship as an offline signed corpus on the
advisory-corpus pattern; lapses freeze rather than fall through; transfers
and disputes ride 30-day timelocked corpus entries; grandfathering follows
the three-tier issuance rule (corroborated auto-grant / evidence-gated /
free).

**Entry criteria** (satisfied):
- **The steward role + claim service exist operationally**: challenge
  issuance, TXT verification, renewal tracking, and signed corpus release —
  this is a new operational dependency, named here deliberately; the engine
  and proxy remain offline consumers of its output.
- Corpus signing keys are managed under the same discipline as policy keys
  (ADR-0012-class trust material).
- Phase 30's exit criteria hold with a non-empty corpus substituted in.

**Exit criteria** (satisfied and pinned by tests):
- A tampered or malformed claim corpus is a boot-time FATAL; the corpus
  version appears in audit provenance alongside `policyHash`.
- No corpus entry exists without a passed challenge (claim-service pipeline
  test); claims with trusted-publisher entries reject unattested publishes
  (ADR-0022 machinery).
- A frozen claim rejects publishes with a distinct error; renewal failure
  alone never changes `source(name)`; frozen-claim serving is byte-identical
  for published versions.
- No transfer or dispute ruling takes effect in under 30 days; a disputed
  namespace rejects publishes while contested; a local policy override beats
  a pending transfer.
- Tier-1 (corroborated) grandfathering linkage is a pure function of
  (upstream packument, claim domain), pinned by fixtures; a Tier-2
  (evidence-gated) grant cannot land without a timelocked corpus entry; an
  unclaimed name's resolution is byte-identical to passthrough.

Evidence: `packages/core/test/claim-corpus.test.ts`,
`packages/proxy/test/claim-corpus-startup.test.ts`,
`packages/proxy/test/claim-lifecycle-e2e.test.ts`, and
`packages/steward/test/steward.test.ts`. Applicant input cannot select a
grandfather tier: the steward owns the upstream lookup, and voluntary transfers
must verify against the current claim's Ed25519 key. The proxy remains an
offline consumer; the authenticated `@sentinel/steward` service owns DNS
verification, durable renewal state, timelocked issuance changes, and signed
release output.

## Phase 32 — Time-locked retraction

**ADR:** [0047](../adr/0047-time-locked-retraction.md) ·
**Depends on:** Phase 30 exit (the native store exists); Phase 31 only for
fleet-wide propagation — retraction advisories ride the steward's bundled
advisory-corpus releases (ADR-0034), which reuse the Phase 31 release
pipeline; instance-local retraction works without it

Maintainers can pull a native release only while `age < 72 h` **and**
`cumulativeDownloads < 1,000` (both policy data); past either bound,
immutability is absolute. Tombstones kill availability, never history —
already-fetched installers keep working from their local caches (there is no
phone-home) and learn through the advisory path at their next audited
install. Identifiers are permanently spent; advisories emit synchronously
into the instance's operator feed and fleet-wide at the advisory-corpus
release cadence; propagation rides the serve-time quarantine overlay by
default, no opt-in flag.

**Entry criteria:**
- Phase 30 native store exit criteria hold.
- Download counting is implemented at the authoritative instance (distinct
  tarball serves; deduped where the history DB, ADR-0028, is enabled) and its
  semantics are documented in the retraction API.
- The operator advisory feed (ADR-0034 `input.advisories` channel) is
  writable by the retraction path.

**Exit criteria:**
- Window enforcement: retraction at 71 h/999 succeeds; at 73 h/5 and at
  2 h/1,001 it is rejected — 403 carrying the window state, with distinct
  errors per exceeded bound; both bounds read from policy.
- Range resolution never selects a retracted version; the tarball GET returns
  410 + JSON tombstone; `_sentinel.retractions` appears in the packument.
- A spent identifier (`name@version`) can never be republished.
- Stored audit reports, attestations (ADR-0032), and history rows are
  byte-identical before/after retraction.
- An `audit-tree` over a lockfile pinning the retracted version flags it
  immediately on the retracting instance; the same lockfile + same corpus
  version yields the same verdict on any instance.
- A cached retracted version serves 410 + tombstone via the overlay with no
  env flag set, while its stored `AuditReport` is unchanged.
- Window-hit telemetry is recorded (attempts outside the window), so the
  unprecedented default values can be revisited with data — in policy, not
  code.

Evidence: `packages/core/test/retraction-corpus.test.ts`,
`packages/proxy/test/retraction-e2e.test.ts`, `private-store.test.ts`,
`history-db.test.ts`, `claim-corpus-startup.test.ts`, and
`packages/steward/test/steward.test.ts`. The proxy exposes the local operator
feed and counting semantics at `GET /-/retractions`; the steward emits the
signed fleet corpus in the same atomic directory as the claim corpus.

## Phase 33 — Migration & compatibility

**Status:** Complete (2026-07-13)

**ADR:** [0048](../adr/0048-migration-compatibility-surface.md) ·
**Depends on:** Phases 30–32 exits

The compatibility contract, the escape hatch, and the coexistence data model:
native namespaces speak the small MUST-implement route set (full packuments
including `time`; negotiation of npm's abbreviated-packument Accept header
("corgi") with the Content-Type echo pnpm checks; publish PUT; npm's
revision-based delete flow (the `-rev` routes) mapped onto retraction;
dist-tags; legacy auth; trivial whoami);
everything else is proxied or documented-ignorable; reverting to pure-proxy
mode is fail-closed, acknowledged, manifested, lossless, and lock-in-free.

**Entry criteria:**
- Phases 30–32 exit criteria hold.
- A client compatibility harness can drive real npm/pnpm/yarn-Berry/bun
  binaries against a Sentinel instance in CI.

**Exit criteria:**
- The compat matrix is green: each client × {install, publish, dist-tag,
  unpublish-in-window, unpublish-past-window} against a native namespace;
  unpublish-past-window surfaces the 403 window state through the client.
- Every proxied route is byte-identical passthrough (diff test against the
  upstream response).
- Flipping registry mode off with native content and no acknowledgment is a
  startup FATAL; the revert manifest enumerates exactly the names whose
  resolution class flips; flip → flip-back round-trips byte-identical
  resolution; the export command's output is republishable to a stock
  registry.
- A lockfile written before a name was claimed still installs after the
  audit-gated history import, with unchanged integrity checks.
- No stored source-class field exists anywhere in the data model (schema
  test) — source class must remain derivable from (policy, corpus) alone, so
  no store migration or restore can ever change routing.

Evidence: `packages/proxy/test/compatibility-e2e.test.ts`,
`registry-migration.test.ts`, `private-store.test.ts`, and the
`sentinel-registry import|export` migration utility. Native packuments carry
full metadata and negotiate corgi documents; npm's revision workflow delegates
availability changes to the Phase 32 retraction decision. Registry-mode revert
retains the store and emits derived resolution flips without persisting a
source class.

## Out of scope for this roadmap

Operating a public registry service and cross-instance federation. Phases
Further public-registry operation or federation requires a new charter.
