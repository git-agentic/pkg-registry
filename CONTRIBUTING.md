# Contributing to Sentinel

Thanks for helping build an agent-auditable security layer for npm. This page
is the practical guide; the design lives in [ARCHITECTURE.md](./ARCHITECTURE.md),
the decision log in [docs/adr/](./docs/adr/), and the working agreement (the
invariants that make this a security product rather than a linter) in
[CLAUDE.md](./CLAUDE.md).

## Getting started

Node **>= 22** (developed against Node 24, Active LTS).

```bash
npm install          # workspace deps
npm run build        # tsc --build across all packages
npm test             # engine + end-to-end proxy (hermetic; never hits live npm)
npm run demo         # offline malware-detection walkthrough
```

The exact test count and platform skip breakdown are documented in
[CLAUDE.md](./CLAUDE.md) — it changes as the project grows; CLAUDE.md is the
source of truth. Tests are hermetic: they use `LocalFixtureUpstream` against
packed local fixtures (`npm run fixtures`, run automatically by `pretest`).

## Fixture safety rules

**Never add live malware to this repo.** Malicious fixtures must be:

- **synthetic and inert** — written for this repo, doing nothing when run;
- marked with a `SYNTHETIC FIXTURE` header comment;
- using **RFC 5737 documentation IPs only** (`198.51.100.0/24`,
  `203.0.113.0/24`) for any "exfil" targets.

They are scored **as text** and never executed. Fixtures live in
`fixtures/<benign|malicious>/<name>/<version>/package/`; after editing, re-run
`npm run fixtures` to re-pack the `.tgz` files and `fixtures/registry.json`.

A PR containing real-world malicious code, live C2 addresses, or anything
copied from an actual campaign will be closed. If you want Sentinel to catch a
real-world pattern, describe the *pattern* in an issue and we'll build a
synthetic fixture for it.

## Non-negotiable invariants

Summarized — the full list with rationale is in [CLAUDE.md](./CLAUDE.md):

1. Scoring is **deterministic** given a policy; the LLM never sets the score.
2. The inline gate is **sync + cheap**; nothing slow on the request path.
3. Caches key on the **integrity hash**, never on version alone.
4. The proxy is **transparent** — packuments pass through, only
   `dist.tarball` is rewritten.
5. Rules **fail open individually**; the audit never crashes an install.
6. Claimed private namespaces are **fail-closed** — served only from the
   private store.

A PR that breaks one of these will be asked to change approach, however clean
the code. If you believe an invariant itself is wrong, that's an ADR
discussion, not a code change.

## Adding a detection rule

Create `packages/core/src/rules/<id>.ts` exporting a `Rule` (a pure
`(AuditInput) => Finding[]`), register it in `packages/core/src/rules/index.ts`,
and use `mkFinding()` from `rules/util.ts` so the diff multiplier and policy
weights apply consistently — don't compute weights by hand. Policy weights and
verdict thresholds live in `DEFAULT_POLICY` in `packages/core/src/policy.ts`, nowhere
else. Every rule change needs a test proving the new behavior, and the
malicious fixtures must still be **blocked**.

## ADRs

Design decisions are recorded in [docs/adr/](./docs/adr/). Never edit an
Accepted ADR to reverse it — supersede it with a new one. If your change
alters a design invariant, update ARCHITECTURE.md and add/supersede an ADR in
the same PR.

## Issues & triage

Bug reports, feature requests, and **detection gaps** (missed detection or
false positive) each have an issue template. Maintainers triage with the
labels `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`,
and `wontfix` — see [docs/agents/triage-labels.md](./docs/agents/triage-labels.md).

Security vulnerabilities: **not** a public issue — see
[SECURITY.md](./SECURITY.md).

## Definition of done for a PR

`npm run build` clean, `npm test` green, new behavior covered by a test, and
the malicious fixtures still blocked. CI runs the suite on Linux (Node 22 +
24) including the bubblewrap sandbox enforcement path; macOS Seatbelt
enforcement is exercised on maintainers' machines.
