# ADR-0007: Integrate with clients via registry redirection, not an npm wrapper

**Status:** Accepted
**Date:** 2026-06-24
**Deciders:** Founder/Eng
**Phase:** 1

## Context

For the audit to matter, real installs must flow through the proxy — including
transitive dependencies, which are where supply-chain attacks usually live. We need
a mechanism to route a client's package fetches through Sentinel that is robust,
works across package managers, and ideally requires no new tool in the developer's
muscle memory.

## Decision

Integrate by **pointing the client's registry at the proxy** — via
`--registry http://…`, an `.npmrc` `registry=` line, or env. The CLI's
`sentinel install` / `sentinel npx` are thin conveniences that inject
`--registry` and exec the real `npm`/`npx`; they are not a reimplementation of npm.
The CLI also offers `sentinel audit <pkg>` (a pre-install verdict with exit codes
for agents/CI) and `sentinel scan <file.tgz>` (offline), but the *enforcement* path
is registry redirection.

## Options Considered

### Option A: Registry redirection (chosen)
| Dimension | Assessment |
|-----------|------------|
| Cross-PM support | Works for npm, yarn, pnpm, bun, npx identically |
| Transitive coverage | Full — every fetch in the resolved tree |
| Maintenance | Low — we don't track npm CLI internals |

**Pros:** One mechanism covers all package managers and all transitive fetches;
survives npm version changes; trivial to enable per-project (`.npmrc`) or per-org;
naturally fails closed under `block` policy (npm sees a 403).
**Cons:** Configuration lives in the environment (must be set in CI/dev images);
auth/scopes for private registries need correct `.npmrc` handling.

### Option B: Wrapper binary that shims/parses the npm CLI
**Pros:** Could add bespoke UX and intercept commands.
**Cons:** Must track npm CLI flags and internals; breaks on npm upgrades; doesn't
help yarn/pnpm/bun; high maintenance for little gain. Rejected.

### Option C: Lockfile / post-install scanner only
**Pros:** No registry config.
**Cons:** Advisory and bypassable; runs after fetch (and possibly after
install-script execution); cannot gate. Useful as a complement, not the
enforcement path. Rejected as primary.

## Trade-off Analysis

Registry redirection wins on **coverage per unit of maintenance**: a single,
stable integration point (the registry URL is a first-class, documented setting in
every package manager) gives us every transitive tarball across the whole PM
landscape, while a wrapper would chase one CLI's internals and still miss the
others. The cost — getting registry config into dev and CI environments — is a
one-time setup that orgs already know how to do (private registries work the same
way).

## Consequences

- **Easier:** universal client support; transitive coverage; clean fail-closed
  semantics; `sentinel audit` doubles as an agent tool / CI gate via exit codes.
- **Harder:** we must handle `.npmrc` auth, scoped-registry config, and corporate
  proxies; onboarding includes an environment change.
- **Revisit:** Phase 2 private-namespace override and per-scope routing build on
  this same redirection point (scoped `registry` config).

## Action Items
1. [x] `sentinel install`/`npx` inject `--registry` and exec the real tool.
2. [x] `sentinel audit` returns exit 0/1/2 for allow/warn/block.
3. [ ] Document `.npmrc` patterns for private scopes + CI images.
