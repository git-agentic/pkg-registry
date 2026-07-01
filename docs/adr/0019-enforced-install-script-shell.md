# ADR-0019: Enforced install via script-shell interposition

**Status:** Accepted (Phase 6)
**Date:** 2026-07-01

## Context

`sentinel install` routed resolution through the proxy (audited + approval-gated downloads) but
npm still ran every lifecycle script UNSANDBOXED. Phases 3–5 built cross-platform containment
(`createSandbox()` + `scrubEnv`) but only reachable via `sentinel run-scripts <dir>` on one
unpacked package. ADR-0016/0017 deferred the full `npm install --enforce` tree orchestration and
flagged (ADR-0017) that the `npm_` env allowlist prefix must narrow / credential-screen before it.

## Decision

`sentinel install --enforce` runs a NORMAL `npm install --registry <proxy>` with
`npm_config_script_shell` set to a shipped `sentinel-script-shell` wrapper. npm invokes it as
`<wrapper> -c "<cmd>"` for every lifecycle script, in dependency order, with the full npm env,
cwd, and `.bin` PATH already constructed. The wrapper scrubs the env, resolves the package's
approved capabilities, and runs `<cmd>` under `createSandbox()`.

- **Why interposition, not `--ignore-scripts` + re-enumeration.** A probe confirmed npm calls a
  custom script-shell as `<shell> -c <cmd>` with cwd = the package dir and the full npm env
  (`npm_package_*`, `npm_lifecycle_*`, `INIT_CWD`, `.bin` PATH). Interposition reuses npm's
  ordering, env construction, workspaces, and tree walk; re-enumeration would re-implement all of
  it, brittly. Rejected.
- **Approval resolution.** A dependency's approved capabilities come from its proxy manifest
  (`GET /-/manifest/:name/:version`): `approved`/`inherited` ⇒ its detected capabilities,
  `n-a` ⇒ none, `required`/`denied` ⇒ fail closed. The install root's own scripts use
  operator-supplied `--approve` (default: none → strict).
- **Env credential-screen (the ADR-0017 pre-condition, now met).** `scrubEnv`'s blanket `npm_`
  prefix is narrowed to `npm_package_`/`npm_lifecycle_`/`npm_node_`/`npm_config_` (+ exact
  `npm_command`/`npm_execpath`), and ANY var matching
  `/_auth|authtoken|_password|passwd|token|secret|credential/i` is dropped regardless of allowlist
  match. A probe showed current npm exposes no credential `npm_config_*` (scoped `.npmrc` tokens do
  not leak), so the screen preserves working installs while failing closed on any auth-shaped config
  on any npm version.

## Fail-closed

`--enforce` NEVER runs a lifecycle script unsandboxed. The wrapper exits non-zero (npm aborts)
when: `SENTINEL_ENFORCE` is unset, the invocation isn't `-c <cmd>`, a dependency is unapproved,
the manifest is unreachable, or `createSandbox()` rejects the platform (Windows / missing bwrap /
refused userns). `install --enforce` also fail-fasts with a clean message before spawning npm if
the platform has no sandbox.

## Consequences

- Every lifecycle script in the tree is contained: the enforcement value is precisely catching
  UNDECLARED capabilities static analysis missed (an approved package's script attempting an
  action outside its detected/approved caps is still denied by the kernel). The DoD test proves
  this end-to-end: `enforce-probe`'s postinstall is `node probe.js` — not an inline shell command
  that triggers `install-scripts/critical` — so it passes the audit and installs with verdict
  `allow`. Its detected capabilities are a generic `filesystem:*` target that covers nothing;
  even when the package is approved, the sandbox still denies the postinstall's `~/.ssh/id_rsa`
  read. The install otherwise succeeds; an unenforced control run shows the read leaking. This
  demonstrates the sandbox backstopping the audit rather than re-denying an already-flagged
  capability.
- Native builds needing network (cold `node-gyp` header cache) require a `network` approval —
  the correct posture, documented.
- Windows: `--enforce` fails closed (no sandbox backend).

## Notes / gotchas

**npm `hasInstallScript` packument field.** npm skips running a by-name install's lifecycle
scripts unless the packument's version manifest advertises `hasInstallScript: true` (an
optimization that avoids unnecessary extraction). The `LocalFixtureUpstream` synthesized packument
(`packages/proxy/src/upstream.ts`, `getPackument`) was updated to carry this field from the
fixture `registry.json`, otherwise enforcement would never engage on a by-name `sentinel install
--enforce enforce-probe` call.

## Rejected

- `--ignore-scripts` + re-enumerate/re-order the tree and replicate npm's env — re-implements
  npm; brittle. (See Decision.)
- Blanket-drop all `npm_config_*` — breaks legitimate config (registry, cache, node_gyp); the
  credential-screen is the targeted fail-closed choice ADR-0017 offered.

Extends ADR-0011/0013 (approval gate), ADR-0016/0017/0018 (sandbox); supersedes nothing.
