# ADR-0030: CI-native GitHub Action — self-booted proxy, SBOM artifact, idempotent PR comment

**Status:** Accepted (Phase 17)
**Date:** 2026-07-08

## Context

By Phase 16, Sentinel has sixteen phases of real capability — deterministic
scoring, a whole-tree lockfile gate (ADR-0020), multi-format lockfile parsing
and CycloneDX export (ADR-0027), signature/provenance verification
(ADR-0021/0022), and identity/anomaly heuristics (ADR-0026/0029) — but no
adoption on-ramp into the place most teams actually gate changes: a GitHub
pull request. Using any of it in CI today means a team hand-rolls a workflow
step that starts the proxy as a background process, waits for it to become
ready, points `sentinel audit-tree` at it, and parses the exit code — the CLI
was designed to talk to an already-running proxy, not to bring one up itself.
Nothing in the existing surface writes to a PR: no comment, no check
annotation, no artifact a reviewer can open. The result is that whole-tree
audit output lives in a terminal log, if a team wires it up at all.

## Decision

- **A new `@sentinel/action` workspace** (`packages/action`, bin
  `sentinel-ci`) depends on `@sentinel/core` and `@sentinel/proxy` directly —
  it is a runner, not a proxy client like `@sentinel/mcp` (ADR-0024), because
  its job is to *bring up* an audit, not just call one.
- **`runCi(opts)`** (`packages/action/src/run.ts`) self-boots
  `createServer` in-process on port `0` with an **injected upstream**
  (`NpmUpstream` against real npm in production, `LocalFixtureUpstream` in
  tests) rather than shelling out to a separately-started proxy process. It
  parses the lockfile with Phase 14's `parseAnyLockfile`, `POST`s the
  resulting coordinates to the same `/-/audit-tree` route the CLI already
  uses, writes a CycloneDX SBOM via Phase 14's `toCycloneDX` (an injected
  `now`, never the wall clock), renders a Markdown report
  (`renderPrComment`, `packages/action/src/report.ts`), and always closes
  the server in a `finally` block regardless of outcome. It emits
  GitHub-native surfacing: `$GITHUB_OUTPUT` (`verdict`/`gated`/`blocked`/
  `warned`/`errored`/`sbom-path`), `$GITHUB_STEP_SUMMARY`, a comment body
  written to `SENTINEL_COMMENT_BODY` when set, and `::error::`/`::warning::`
  annotations per offending package — all of it defensive: an absent env var
  falls back to `console.log` rather than throwing.
- **`fail-on` drives the exit code**, not the raw verdict. `exitFor` maps
  `none → 0` always; `warn → fail on warn-or-worse`; `block` (the default)
  `→ fail on block-or-worse`; a server-side `gated` flag (the tree-level
  `treeGate`/`--fail-on-error` rollup ADR-0020/0027 already compute) also
  forces a failing exit even when the raw verdict alone wouldn't have.
- **`sentinel-ci` (`packages/action/src/index.ts`)** is a thin, env-driven
  bin: `INPUT_LOCKFILE`/`INPUT_POLICY`/`INPUT_SBOM_PATH`/`INPUT_FAIL_ON`/
  `INPUT_OMIT_DEV`/`INPUT_WORKING_DIRECTORY` map to `RunCiOptions`; a signed
  policy is loaded through core's existing `loadPolicy` (falling back to
  `DEFAULT_POLICY` when `INPUT_POLICY` is unset — no new export needed); a
  `SENTINEL_CI_FIXTURES` env var is a test-only escape hatch that swaps in
  `LocalFixtureUpstream` so the bin's own e2e tests stay hermetic without
  touching live npm; it calls `process.exit(result.exitCode)`.
- **A thin composite `action.yml`** (repo root) does the GitHub-specific
  work `runCi` deliberately doesn't: `actions/setup-node` → install/build →
  run the bin (with the env above wired from the action's typed inputs) →
  `actions/upload-artifact` for the SBOM (`if: always()`) →
  `actions/github-script` to post or update a PR comment, found by an
  idempotency marker (`REPORT_MARKER = "<!-- sentinel-report -->"` at the
  top of every rendered report) rather than always appending a new one.
  `.github/workflows/sentinel-example.yml` shows the minimal usage
  (`pull_request` trigger, `permissions: { contents: read, pull-requests:
  write }`, `uses: ./`).
- **A root-cause fix, not a workaround, made the self-boot possible.**
  `packages/proxy/src/index.ts`'s `main()` was unconditionally invoked at
  module scope before this phase — any import of `@sentinel/proxy` for its
  exports (`createServer`, the stores) would also boot a listening server
  as a side effect. This phase entrypoint-guards it the same way
  `@sentinel/mcp` already guards its own bin (`isEntrypoint()`, comparing
  `import.meta.url` against the resolved `process.argv[1]`), so `runCi` can
  `import { createServer, ... } from "@sentinel/proxy"` and construct its
  own server without a second, unwanted one appearing.

## Determinism (invariant #1 untouched)

The Action only **runs** an audit through the exact `/-/audit-tree` route
and scoring engine every prior phase already exercises; it adds no new rule,
no new weight, and no new verdict logic. `renderPrComment` and `toCycloneDX`
both take `now` as an injected parameter rather than reading the clock, so
the report and SBOM are pure projections of an already-deterministic
`TreeAuditResult` (the same discipline ADR-0022/ADR-0027/ADR-0028 established
for every other injected-clock surface). The `scoring is deterministic
across runs` test is unaffected — nothing in this phase touches `runAudit`,
`score()`, or the rule set.

## Consequences

- Self-booting avoids the fragility of a separate background-proxy step
  (PID files, readiness polling, port collisions between concurrent CI
  jobs) while reusing every store/route/aggregate the CLI and proxy already
  have — there is no second code path to keep in sync.
- The injected-upstream design keeps `packages/action`'s own tests
  hermetic (`LocalFixtureUpstream`, per this repo's fixture-safety rules)
  without special-casing test mode inside `runCi` itself — the seam is the
  same `Upstream` interface every other package already depends on.
- `fail-on: none` gives adopting teams an observe-only onboarding path —
  the audit runs, the PR comment and SBOM appear, but nothing blocks merges
  — before a team opts into `fail-on: warn`/`block` enforcement.
- No package code executes anywhere in this flow: `audit-tree` is the same
  static, bytes-in-memory audit path every prior phase used, and the Action
  never installs the audited tree's dependencies.
- Every CI run now does a full `npm ci && npm run build` of the Action's
  own dependency tree inside `github.action_path` — slower than a
  pre-built distribution would be, at the benefit of no separate publish
  step for this phase.

## Deferred

- **SARIF / GitHub code-scanning output** — findings surface as a PR
  comment and step annotations, not a `security-events` SARIF upload.
- **GitLab or other CI platforms** — `action.yml` is GitHub Actions-specific
  composite syntax; `runCi` itself is platform-agnostic, but no other CI
  wrapper exists yet.
- **A pre-commit hook** — no local, pre-push gate; the Action only runs in
  CI.
- **GitHub Marketplace publish workflow** — the Action is usable via
  `uses: ./` (or a tag on this repo) but is not published/listed on the
  Marketplace.
- **Auto-remediation in the comment** — the PR comment reports; it never
  proposes or applies a lockfile fix, version bump, or allowlist entry.

## Rejected

- **A Docker-based action** — rejected: heavier (an image to build,
  publish, and keep patched) for no capability the Node composite action
  doesn't already have; `actions/setup-node` plus `npm ci` is fast enough
  and keeps the Action's build identical to every other workspace package's.
- **A separate background-proxy step, started and polled from a later
  step** — rejected: readiness-polling and PID-lifecycle management is
  exactly the fragility class `runCi`'s in-process self-boot exists to
  avoid; a step boundary would also force the proxy's URL to cross
  processes as plain state instead of staying a local variable.
- **Putting the CI runner in `@sentinel/cli`** — rejected: the CLI's
  `sentinel audit-tree` is deliberately a pure HTTP client against an
  already-running proxy (mirroring `@sentinel/mcp`'s `ProxyClient`
  boundary); folding proxy-boot lifecycle management into it would muddy
  that boundary for every other CLI command that assumes the proxy is
  already there.

Extends ADR-0020 (whole-tree lockfile audit — the Action drives the same
`/-/audit-tree` fan-out and aggregate gate, now from a self-booted proxy
instead of an operator-run one) and ADR-0027 (ecosystem breadth + SBOM — the
Action's SBOM output is the same `toCycloneDX` projection, now written
automatically as a CI artifact on every run). Supersedes nothing.
