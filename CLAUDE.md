# CLAUDE.md — working agreement for the Sentinel repo

Read this before changing code. It captures the invariants that make this a
security product rather than a linter. See [ARCHITECTURE.md](./ARCHITECTURE.md)
for the full design, [docs/adr/](./docs/adr/) for the decision log (why each
invariant below exists, with the options we rejected), and [README.md](./README.md)
for how to run things.

## What this is

Sentinel is an **agent-auditable security layer for npm**. Phase 1 (built) is a
transparent **auditing proxy** in front of `registry.npmjs.org` that scores every
tarball and attaches a verdict before install-time code can run. Phase 2 (designed,
not built) adds private-namespace override and an install-time permission manifest.
Phase 3 adds **`@sentinel/sandbox`** — a macOS Seatbelt runner that enforces a package's
approved capability manifest at install time (`sentinel run-scripts`). Synthetic malware
fixtures are still scored-as-text and **never executed**; enforcement is tested with
benign probe packages.

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

Node + TypeScript, npm workspaces, Express 5, `tar` 7, `commander` 15, tests on
`node:test` + `tsx`. Developed against **Node 24 (Active LTS)**; Node 22
(Maintenance LTS) also supported — `engines.node` is `>=22`. Pin to current latest;
don't downgrade majors without a reason.

## Build / test / run

```bash
npm run build            # tsc --build (project references: core → proxy/cli)
npm test                 # engine + end-to-end proxy (must be 116/116)
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

`npm run build` clean, `npm test` 116/116, and if you touched rules/scoring, add or
update a test that proves the new behavior — and confirm the malicious fixture is
still **blocked**. If you changed a design invariant above, update ARCHITECTURE.md
and the relevant ADR in [docs/adr/](./docs/adr/) — or add a new ADR (never edit an
Accepted one to reverse it; supersede it).
