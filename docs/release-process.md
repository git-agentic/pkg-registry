# Sentinel release process

How Sentinel versions, packages, and publishes its npm packages. The
two-stage automation lives in
[`.github/workflows/release.yml`](../.github/workflows/release.yml); the
native-helper packaging decision is [ADR-0052](./adr/0052-native-helper-release-packaging.md).

## Packages and publication order

Seven workspaces publish under the `@sentinel` scope; the root
`sentinel-registry` package is `private` and never publishes. Publication
must follow the internal dependency graph:

1. `@git-agentic/sentinel-core`
2. `@git-agentic/sentinel-proxy`, `@git-agentic/sentinel-sandbox`, `@git-agentic/sentinel-mcp`, `@git-agentic/sentinel-steward`
3. `@git-agentic/sentinel-cli` (depends on core + sandbox)
4. `@git-agentic/sentinel-action` (depends on core + proxy)

The release workflow publishes in exactly this order and stops at the first
failure without unpublishing anything already released.

## Prerelease versioning

- Pre-1.0 releases use `0.1.0-alpha.N` (then `-beta.N`, `-rc.N`) with the
  npm dist-tag matching the prerelease channel (`alpha`, `beta`, `rc`).
- **The `latest` dist-tag, pre-stable:** npm force-creates `latest` on a
  package's first publish (even with `--tag alpha`) and never moves it; it
  also cannot be deleted. Until a stable release exists, `latest` is
  therefore kept pointing at the **newest prerelease** — retargeted manually
  after each release (`npm dist-tag add @git-agentic/sentinel-<p>@<version>
  latest`, one per package; needs an interactive npm login — OIDC trusted
  publishing covers publish only, not dist-tag mutations). Stage B warns in
  the run summary when `latest` is stale. Once `0.1.0` stable ships with
  `--tag latest`, this manual step disappears.
- All seven packages version in lockstep — one release version across the
  workspace, even for packages with no changes. Lockstep keeps the internal
  dependency pins trivially correct and the support matrix one-dimensional.
- Internal dependencies are pinned **exact** (`"@git-agentic/sentinel-core": "0.1.0-alpha.1"`,
  no `^`/`~`, never `workspace:*` or `file:` in a published manifest). A
  prerelease must never float onto a different prerelease.
- User-visible hardcoded versions move with the release:
  `ENGINE_VERSION` (`packages/core/src/audit.ts`), the MCP server version
  (`packages/mcp/src/index.ts`), and the CLI `--version`
  (`packages/cli/src/index.ts`).

## Dependency update policy

- Third-party runtime dependencies use caret ranges pinned by
  `package-lock.json`; `npm ci` + the lockfile are the reproducibility
  boundary. Majors are not bumped without review (CLAUDE.md stack rules).
- GitHub Actions are pinned to full commit SHAs with a version comment;
  Dependabot raises SHA-pinned bumps (CONTRIBUTING.md).

## Release gate (what must be green)

`npm ci`, `npm run build`, `npm run typecheck`, `npm run fixtures`,
`npm test` (no weakened/skipped tests to make a release pass — the
package-contents test in `packages/core/test/package-contents.test.ts` is
part of the suite and gates tarball hygiene), `npm run benchmark:publish`,
`npm run compat:clients`, `npm audit --omit=dev`, a secret scan over history
and worktree, a dependency license scan, and
`npx tsx scripts/release-smoke.ts` (packs every workspace and validates the
packed artifacts in a fresh project: imports, types, every bin, proxy/MCP/
steward startup).

## Two-stage automation

**Stage A — build and verify** (`test`/`compat`/`build-and-verify` jobs):
manual dispatch or a prerelease tag push. Pinned action SHAs, Node 22 + 24
test matrix, one clean-checkout build, pack, packed-artifact smoke test, and
an uploaded artifact set: tarballs, `SHA256SUMS`, CycloneDX SBOM,
`release-manifest.json`, smoke results. No publication.

**Stage B — publish** (`publish` job): requires `publish=true` on the
dispatch **and** approval of the protected `npm-release` GitHub environment.
It downloads Stage A's exact artifacts, verifies checksums, verifies the tag
points at the tested commit, verifies every tarball declares the release
version, refuses to run if any target version already exists, publishes in
dependency order with `--access public --tag alpha --provenance`, verifies
each package via `npm view` (version + dist-tag), installs the published
packages from the public registry in a clean project, and only then creates
the GitHub prerelease with the artifacts attached.

Least privilege: top-level `permissions: {}`; the publish job alone gets
`contents: write` (release creation) and `id-token: write` (provenance).
`pull_request_target` is never used and no publish credential is reachable
from a PR-triggered workflow.

## Trusted publishing

Prefer npm **trusted publishing** (GitHub Actions OIDC) over any long-lived
token: configure the repo/workflow as a trusted publisher for each
`@git-agentic/sentinel-*` package on npmjs.com and leave `NPM_TOKEN` unset — npm ≥ 11.5
detects OIDC automatically and mints per-publish credentials. Until trusted
publishing is configured (it may not be configurable before a package's
first publish), use a **granular automation token scoped to the @sentinel
packages only**, stored as an **environment secret on `npm-release`**
(never repo-wide), and rotate or revoke it immediately after the release.
`--provenance` works with either auth mode and links each package to the
exact commit + workflow run.

## Rollback limitations (read before publishing)

- **npm versions are immutable in practice.** Unpublish is heavily
  restricted (72-hour/no-dependents rules) and even when allowed, a
  version number is spent forever. Plan on **fix-forward**: publish
  `-alpha.N+1`, never reuse a version.
- If a publish fails partway, the already-published packages stay
  published. Do **not** unpublish; publish the remaining packages from the
  same artifacts once the failure is fixed (the version-exists preflight
  skips nothing — a partial release is completed by re-running Stage B
  only if no published tarball changed; otherwise bump to the next
  prerelease number across the board).
- A Git tag and GitHub release can be deleted, but anyone may already have
  fetched them; treat both as public the moment they are pushed.

## Compromised-release response

1. **Deprecate immediately**: `npm deprecate @git-agentic/sentinel-<p>@<version>
   "SECURITY: compromised — do not install"` for every affected package.
2. Point the dist-tag at the last known-good version (`npm dist-tag add
   @git-agentic/sentinel-<p>@<good> alpha`).
3. Request npm unpublish/security takedown through npm support if within
   policy; do not rely on it.
4. Rotate every credential the pipeline touched (npm token, corpus/policy
   signing keys if exposure is plausible); revoke the trusted-publisher
   config until the workflow is audited.
5. Publish a GitHub security advisory and a fixed release; document the
   window and indicators. (Sentinel's own `known-advisory` corpus should
   carry the compromised versions in its next regeneration.)

## Deprecation procedure

`npm deprecate <pkg>@<range> "<message>"` — metadata-only, reversible with
an empty message. Use for: superseded prereleases after a stable release,
and versions with known defects that don't warrant the compromised-release
path.

## Promoting stable 0.1.0 later

1. Land fixes on `main`; bump all workspaces + internal pins +
   `ENGINE_VERSION`/CLI/MCP versions to `0.1.0` (no prerelease suffix).
2. Run the same two-stage pipeline with tag `v0.1.0`, publishing with
   `--tag latest` (the workflow's dist-tag is the one alpha-specific knob to
   change — everything else is identical).
3. Keep `alpha` pointing at the last alpha until `latest` exists, then move
   `alpha` forward to `0.1.0` as well so `@alpha` installs never resolve
   older than stable.
4. The GitHub release loses the `--prerelease` flag; SECURITY.md's supported
   versions section starts naming the stable line.
