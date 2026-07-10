# Phase 17 — CI-Native GitHub Action

**Date:** 2026-07-08
**Status:** Approved design, pre-implementation
**Extends:** ADR-0020 (whole-tree lockfile audit — the Action runs it), ADR-0027
(multi-format lockfiles + CycloneDX SBOM — the Action detects the lockfile and uploads
the SBOM). Reuses `createServer`, `parseAnyLockfile`, `toCycloneDX`, `aggregateTree`.
Supersedes nothing. Adds a new `packages/action` workspace; the scoring engine is untouched.

## Problem

Sixteen phases built a deep audit engine — whole-tree lockfile gating, CycloneDX SBOM,
signature/provenance verification, release-anomaly detection — but there is **no drop-in way
for a real team to run any of it**. The only entry points are a CLI that talks to a
separately-run proxy, an MCP server, and the proxy itself. A developer cannot add Sentinel to
their repo in five minutes and see a verdict on their next pull request. The wedge is built;
the on-ramp is missing. Phase 17 ships the on-ramp: a packaged GitHub Action that runs the
tree audit on every PR, uploads the SBOM, comments the verdict, and fails the check on a gated
tree — surfacing all prior work in the place developers actually live.

## Decisions (brainstorm outcomes)

1. **A new `packages/action` workspace** (`@sentinel/action`, bin `sentinel-ci`) — keeps
   `@sentinel/cli` a pure HTTP client (unchanged) and isolates the CI concern in its own
   well-bounded unit, matching the repo's `mcp`/`sandbox` workspace pattern. Depends on
   `@sentinel/core` + `@sentinel/proxy`.
2. **Self-boot the proxy in-process** (ephemeral port) rather than managing a background
   process — reuses all existing audit-tree machinery with zero refactor and no
   readiness/PID fragility. The `upstream` is **injected** (`NpmUpstream` in production,
   `LocalFixtureUpstream` in tests) so tests stay hermetic.
3. **A composite `action.yml`** (not Docker) — lighter, no image to publish, uses the runner's
   Node. GitHub API glue (PR comment) stays declarative; all logic/formatting lives in the
   tested runner.
4. **Fail-closed with graceful onboarding** — `fail-on: block` (default) fails the check on a
   gated tree; `fail-on: none` is observe-only (comment + summary, always green), mirroring the
   proxy's observe/block philosophy so teams can adopt gradually.

## Section 1 — Architecture

- **`packages/action`** (`@sentinel/action`, bin `sentinel-ci`): the CI runner. `runCi(opts)`
  constructs `createServer({ upstream, store, approvals, enterprisePolicy, privateStore,
  violations, approvalRequests })` on port 0, runs the tree audit against it, then closes it.
  All stores are constructed with in-memory defaults; `enterprisePolicy` defaults to
  `DEFAULT_POLICY`. The `upstream` is injectable (default `NpmUpstream`; tests pass
  `LocalFixtureUpstream`).
- **Produces:** a CycloneDX **SBOM** file (`toCycloneDX`), a **Markdown report** (to
  `$GITHUB_STEP_SUMMARY` + a comment-body file), **step outputs** (`verdict`, `gated`, counts,
  `sbom-path`) via `$GITHUB_OUTPUT`, `::error::`/`::warning::` **workflow-command annotations**
  for gated rows, and an **exit code** (non-zero when gated).
- **`action.yml`** (repo root): a composite action — setup-node → install/build Sentinel → run
  `sentinel-ci` → upload the SBOM artifact → post/update the PR comment via
  `actions/github-script`. No package code ever executes (tarballs are fetched and scored as
  text, consistent with the whole product).

## Section 2 — The `sentinel-ci` runner

`runCi(opts): Promise<CiResult>` — orchestration with an injected `upstream` and `env`:

- **Inputs** (action.yml → env/flags): `lockfile` (path, or auto-detect
  `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml` in the working dir), `policy` (optional
  signed policy file; default `DEFAULT_POLICY` — see note), `sbom` (output path, default
  `sentinel-sbom.json`), `fail-on` (`block`|`warn`|`none`, default `block`), `comment` (bool,
  default true), `omit-dev` (bool).
- **Flow:** detect + read the lockfile → `parseAnyLockfile(raw, { filename, omitDev })` → boot
  the in-process server on port 0 → `POST /-/audit-tree` with the coordinates (+ `failOnError`
  from `fail-on`) → `TreeAuditResult` → write the SBOM (`toCycloneDX(result, { now })`) →
  `renderPrComment(result)` → emit outputs/summary/annotations → close the server → set exit
  code.
- **Gate / `fail-on`:** `block` (default) → non-zero when the aggregate verdict is `block` or
  the tree is `gated`; `warn` → also fail on `warn`; `none` → always exit 0 (comment + summary
  still emitted). Mirrors the proxy's observe/block modes.
- **`renderPrComment(result): string`** (pure, unit-tested): a Markdown block — a headline
  verdict badge, the `allow/warn/block/error` counts, a table of the worst offenders
  (name@version, verdict, score, top finding — surfacing release-anomaly / provenance /
  integrity-mismatch), a provenance summary line, and a footer noting the SBOM artifact. Begins
  with a hidden `<!-- sentinel-report -->` marker so the Action can find-and-update its comment
  idempotently. Deterministic (injected `now`).
- **GitHub-native but local-runnable:** all `GITHUB_*` env is read defensively — absent (a local
  run) ⇒ `sentinel-ci` prints the report to stdout and still returns the correct exit code, so
  the runner is fully testable and usable outside GitHub.
- **Policy note:** signed-policy loading reuses the proxy's existing resolution (the same path
  `main()` uses). If that helper is not already exported, this phase exports it (a one-line
  change) — Phase 17 adds **no new policy logic**; default is `DEFAULT_POLICY`.

## Section 3 — The composite `action.yml`, PR commenting, example workflow

- **`action.yml`** (repo root), `runs.using: composite`:
  - `inputs`: `lockfile` (default `''` = auto-detect), `policy` (default `''`), `sbom-path`
    (default `sentinel-sbom.json`), `fail-on` (default `block`), `comment` (default `true`),
    `working-directory` (default `.`).
  - `outputs`: `verdict`, `gated`, `blocked`, `warned`, `errored`, `sbom-path` — mapped from the
    `sentinel-ci` step's `$GITHUB_OUTPUT`.
  - steps: (1) `actions/setup-node`; (2) install + build Sentinel (from this repo during dev;
    documented as an install-from-published-package step once released); (3) run `sentinel-ci`
    with inputs as flags/env (writes SBOM, comment-body, `$GITHUB_STEP_SUMMARY`, outputs; sets
    the step exit code); (4) `actions/upload-artifact` for the SBOM; (5) `actions/github-script`
    to post/update the PR comment — find an existing Sentinel comment by the hidden
    `<!-- sentinel-report -->` marker and `updateComment`, else `createComment` (idempotent),
    gated behind `comment == 'true'` && `github.event_name == 'pull_request'`.
- **Fail-closed ordering:** the upload + comment steps use `if: always()` so a *gated* (failed)
  run still uploads the SBOM and posts the report before the job goes red — the developer sees
  *why*. The runner's non-zero exit is what fails the check.
- **Permissions & secrets:** documented minimal `permissions: { contents: read, pull-requests:
  write }`; `GITHUB_TOKEN` passed only to the github-script step, never logged; no Sentinel
  secret required for the public-npm path.
- **Example workflow** (`.github/workflows/sentinel-example.yml` + README snippet): `uses: ./`
  (dev) / `uses: your-org/sentinel@v1` with `fail-on: block`, plus an observe-only variant
  (`fail-on: none`) for onboarding.

## Section 4 — Testing & Definition of Done

*Testing (hermetic, deterministic):*
- **`runCi` e2e** — inject `LocalFixtureUpstream` + a fake env (temp dir for `GITHUB_OUTPUT` /
  `GITHUB_STEP_SUMMARY` / comment-body). A sample lockfile referencing fixture packages
  *including the malicious one* → assert: exit non-zero when `fail-on: block` and the tree gates;
  exit 0 under `fail-on: none` with the comment still produced; `$GITHUB_OUTPUT` carries
  `verdict`/`gated`/counts/`sbom-path`; the SBOM file parses as CycloneDX; step-summary +
  comment-body files written; `::error::` annotations emitted for gated rows.
- **`renderPrComment` unit test** — a synthetic `TreeAuditResult` → asserted Markdown (headline
  verdict, counts, worst-offenders table surfacing a release-anomaly/provenance/integrity
  finding, and the hidden `<!-- sentinel-report -->` marker). Pure, injected `now`.
- **`fail-on` matrix** — block / warn / none over the same tree → the expected exit codes.
- **Lockfile auto-detection** — picks `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` from
  the working dir.
- **`action.yml` structural test** — parse the YAML (core's `yaml` dep) → assert
  `runs.using === 'composite'` and that every documented input/output is declared.
- **Hermetic + local-runnable** — `LocalFixtureUpstream`, no live npm; absent GitHub env ⇒
  stdout + correct exit code (a no-env test).

*Definition of done:* the new `packages/action` workspace wired into root `package.json`
workspaces + `tsconfig` project references; `npm run build` clean; `npm test` green (record
count); the malicious fixture still blocked (existing suite + the `runCi` e2e); ADR-0030
recorded; ARCHITECTURE (the CI/Action layer + the self-boot pattern), CLAUDE (phase summary +
the new workspace + test count), and README (a top-level "GitHub Action" section — `uses:`,
inputs/outputs, minimal `permissions`, the observe→enforce onboarding path) updated.

## Out of scope (deferred beyond Phase 17)

- **SARIF / code-scanning integration** (upload findings to the GitHub Security tab) — a richer
  surface; the workflow-command annotations cover inline PR annotation this phase.
- **GitLab CI / other CI templates** — GitHub Action first; the runner is CI-agnostic, so other
  CIs can call `sentinel-ci` directly later.
- **A pre-commit hook** — the runner is reusable, but the hook packaging is a follow-on.
- **Publishing the Action to the GitHub Marketplace** — the `action.yml` is written to be
  publishable; the release/versioning workflow is a follow-on.
- **Auto-remediation / suggested fixes in the comment** — the comment reports; turning a block
  into a suggested pin/removal is the separate "actionable remediation" direction.
- **Enforcing a specific per-enterprise policy in the Action beyond loading a signed file** —
  the `policy` input loads a signed policy; authoring/managing policies is out of scope.

## Invariants preserved

1. **Deterministic score** — the Action only *runs* the existing audit; scoring is untouched.
   `renderPrComment`/SBOM take an injected `now`; the run is reproducible given the same tree +
   policy.
2. **LLM never scores** — untouched.
3. **Sync gate cheap / slow-stuff-async** — the Action is the batch/CI path, never the inline
   tarball gate; fetching tarballs from npm to audit is the acquisition path (invariant #3 keeps
   the *audit* offline, not the fetch).
4. **Cache key = integrity** — unchanged; the self-booted proxy uses the same integrity-keyed
   audit path.
5. **Proxy transparency** — the Action boots the same `createServer`; packument/tarball handling
   is unchanged.
6. **Rules fail open / audit never crashes** — `runCi` wraps the run; an unresolvable package is
   an `error` row (gates only under `--fail-on-error`, ADR-0020); a malformed lockfile is a clear
   error, not a crash. GitHub env is read defensively.
7. **Private namespaces authoritative** — unchanged; the self-booted proxy resolves through the
   same routing (private store empty in CI ⇒ claimed names simply resolve as configured).
