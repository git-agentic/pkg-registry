# Sentinel Phase 6 — `sentinel install --enforce` (sandboxed install capstone) (design)

**Date:** 2026-07-01
**Status:** Approved (brainstorming) — ready for implementation planning
**Implements:** the full `npm install --enforce` tree orchestration deferred since ADR-0016,
and the `npm_config_*` credential-screen ADR-0017 mandated as a pre-condition for it.
**Sequence context:** Phase 1 (auditing proxy + scoring), Phase 2 (approval gate, signed
policy, private registry), Phase 3 (macOS Seatbelt runner), Phase 4 (env-scrub +
write-confinement), Phase 5 (Linux bubblewrap enforcement behind `createSandbox()`) are built.
Every enforcement primitive now exists on both macOS and Linux; Phase 6 welds them to a real
install command.

---

## 1. Goal & threat model

Today `sentinel install` sets `--registry` to the proxy: every tarball is **audited and
approval-gated on download**, but npm still runs each package's lifecycle scripts
**unsandboxed**. So the install-time-code-execution threat (a transitive dependency's
`postinstall` exfiltrating secrets or persisting — the event-stream pattern) is scored and
gated, but not *contained at runtime*. Phases 3–5 built the containment (`createSandbox()` +
`scrubEnv`) but only reachable via `sentinel run-scripts <dir>` on a single unpacked package.

Phase 6 closes the loop: `sentinel install --enforce <args>` runs a real `npm install` in which
**every lifecycle script in the dependency tree executes under the sandbox**, with npm's env
replicated but credential-screened, failing closed if containment is unavailable.

**Success criteria**
1. A dependency's `postinstall` that attempts a **denied** action (read a planted credential /
   network egress) under `--enforce` is **blocked** (assert on the protected-resource effect),
   while the install otherwise **succeeds** (the package is installed, benign scripts run).
2. The same install **without** `--enforce` runs the script unsandboxed (control — the action
   is *not* blocked), proving `--enforce` is what adds containment.
3. **Credential env-vars do not reach lifecycle scripts:** an `.npmrc` auth token / a
   credential-shaped `npm_config_*` var is absent from a script's environment under `--enforce`
   (assert the value never reaches the script), while benign npm-injected vars
   (`npm_package_*`, `.bin` PATH, `INIT_CWD`) are present so normal builds work.
4. **Fail closed:** if the sandbox is unavailable (Windows / missing `bwrap` / refused
   userns) or the wrapper cannot determine a package's approved capabilities or build a safe
   env, the script is **not** run unsandboxed — the wrapper exits non-zero and **npm aborts
   the install**.
5. **Determinism / offline invariants preserved:** scoring, rules, proxy audit path, policy,
   and approval store are UNCHANGED. This is orchestration + a new wrapper + an env-scrub
   narrowing only.

**Non-goals (deferred):** Windows enforcement (fails closed); per-host network filtering
(proxy's job); pre-warming `node-gyp`/header caches; sandboxing the *root* project's own
scripts with anything richer than operator-supplied approvals (see §4.4).

---

## 2. Empirical findings (probe-before-spec)

Validated with a real `npm install` (npm 11 / node — the version bundled with Node 24) of a
local dependency carrying a `postinstall`, with a custom `script-shell` wrapper and an
`.npmrc` containing scoped auth tokens.

| Probe | Result |
|---|---|
| npm invokes a custom `script-shell` as `<wrapper> -c "<cmd>"` | ✅ `ARGV: -c <cmd>`, ARGC=2 |
| cwd is the package's own directory | ✅ `node_modules/<pkg>` |
| full npm env is present in the wrapper | ✅ `npm_lifecycle_event`/`_script`, `npm_package_name`/`_version`, `npm_command`, `npm_execpath`, `npm_node_execpath`, `INIT_CWD`, and PATH with `node_modules/.bin` prepended |
| the install completes with the script run *through* the wrapper | ✅ "added 1 package" |
| scoped `//registry/:_authToken` + `_password` from `.npmrc` leaking into `npm_config_*` | ✅ **did NOT leak** — the only `npm_config_*` keys were benign (`audit`, `cache`, `node_gyp`, `prefix`, `user_agent`, …) |

**Consequences baked into this design:**
- **Architecture (B) — script-shell interposition — is confirmed viable and chosen** (§3). npm
  owns tree order, per-package env construction, `.bin` PATH, cwd, and workspaces; the wrapper
  only interposes the sandbox. This eliminates architecture (A)'s brittle re-implementation and
  sidesteps the "does re-running scripts reproduce a working install" problem entirely (npm
  runs the scripts itself, in its normal flow, via the wrapper).
- The current-npm auth non-leak is **reassuring but version-dependent** (older npm / legacy
  user-config `_authToken` forms differ; npm 11 merely *rejects* legacy keys in project
  config). The `npm_config_*` **credential-screen (§4.3) stays as version-independent,
  fail-closed defense-in-depth** — precisely the ADR-0017 pre-condition.

---

## 3. Architecture — script-shell interposition

```
sentinel install --enforce <args>
        │
        ├─ spawn: npm install --registry <proxy> <args>
        │     env += { npm_config_script_shell = <sentinel-script-shell>,
        │              SENTINEL_ENFORCE=1, SENTINEL_PROXY=<proxy>,
        │              SENTINEL_APPROVE=<operator --approve flags, for root scripts> }
        │
        └─ npm resolves + downloads (audited + approval-gated by the proxy, unchanged),
           then for EACH lifecycle script in the tree, in dependency order, invokes:
                 <sentinel-script-shell> -c "<lifecycle cmd>"   (cwd = that package's dir)
                        │
                        ├─ identify package (npm_package_name@version, cwd)
                        ├─ resolve APPROVED capabilities for it (§4.2)
                        ├─ build scrubbed env (§4.3)
                        └─ createSandbox().run(cmd, { cwd, approved, homeDir, env })
                                 → propagate child exit code; fail closed on any inability to enforce
```

**Rejected — (A) `--ignore-scripts` + re-enumerate/re-order the tree and replicate npm's env
per package.** It re-implements npm's dependency ordering, `npm_package_*` flattening, `.bin`
PATH assembly, and workspace handling — a large, brittle surface the probe shows (B) gets for
free. (B) reuses `createSandbox` (Phases 3–5) and `scrubEnv` (Phase 4) nearly as-is; the only
genuinely new runtime code is the wrapper + the per-package approval lookup, which (A) needs
too.

---

## 4. Components

### 4.1 `sentinel install --enforce` (CLI flag on the existing `install` command)
Adds `--enforce` to the current `install` command. When set, before spawning npm it:
- resolves the absolute path to the `sentinel-script-shell` bin (shipped in `@sentinel/cli`),
- injects `npm_config_script_shell=<that path>` plus `SENTINEL_ENFORCE=1`,
  `SENTINEL_PROXY=<proxy>`, and `SENTINEL_APPROVE=<operator --approve values>` into the npm
  child's env,
- runs `npm install --registry <proxy> <args>` exactly as today (stdio inherited).
Without `--enforce`, behavior is unchanged (registry redirect only). `--enforce` also accepts
`--approve <kind:target>` (repeatable), used for the root project's own scripts (§4.4).

### 4.2 `sentinel-script-shell` (new bin in `@sentinel/cli`)
A small Node executable with one responsibility: run one lifecycle command under the sandbox.
On invocation (`-c "<cmd>"`):
1. Refuse unless `SENTINEL_ENFORCE=1` is set (guards against accidental use as a general shell).
2. Identify the package: `npm_package_name`@`npm_package_version` + cwd.
3. Resolve **approved capabilities**:
   - **Dependency script** (cwd under a `node_modules`): fetch the package's manifest from the
     proxy (`GET /-/manifest/:name/:version`, `SENTINEL_PROXY`). Approved capabilities are the
     manifest's capabilities when `approvalState` is `approved`/`inherited`; if `required`
     (unapproved) → **fail closed** (exit non-zero). (Under a `block` policy the proxy already
     403s the download so an unapproved package's scripts never run; this is defense-in-depth
     and the enforcing gate under an `observe` policy.)
   - **Root/local project script** (cwd is the install root, no proxy manifest): use the
     operator's `SENTINEL_APPROVE` capabilities; default is none (strict). (§4.4)
4. Build the scrubbed env (§4.3).
5. `createSandbox().run(cmd, { cwd, approved, homeDir, env })`; exit with the child's code.
6. **Fail closed** on any step that can't guarantee containment (sandbox unavailable, manifest
   unreachable for a dependency, env build failure): print a clear `sentinel:` message and exit
   non-zero so npm aborts. Never `exec` the command outside the sandbox.

### 4.3 Env replication + `npm_config_*` credential-screen (the ADR-0017 deliverable)
Extend `scrubEnv` so the `npm_` handling is **narrowed and credential-screened** instead of a
blanket `npm_` prefix allow:
- Keep the npm-injected vars a lifecycle script legitimately needs:
  `npm_package_*`, `npm_lifecycle_*`, `npm_node_*`, `npm_command`, `npm_execpath`,
  `npm_config_*` **except credential-shaped keys**, plus `INIT_CWD` and the PATH npm hands us
  (with `.bin` prepended — passed through since the wrapper receives it).
- **Drop any `npm_config_*` key whose name matches `/_auth|authtoken|_password|token|secret/i`**
  (case-insensitive). Probe shows current npm exposes no such key, so this preserves working
  installs while failing closed on any auth-shaped config on any npm version.
- Approved `env:NAME` capabilities still pass their exact var through, unchanged from Phase 4.
`scrubEnv` stays pure and deterministic; the narrowing replaces the inert `npm_` prefix entry
flagged in ADR-0017 §"Known scope note".

### 4.4 Root project's own scripts
The primary threat is **dependency** scripts (transitive, untrusted). The root project's own
lifecycle scripts are the operator's own code. Under `--enforce` they still run **sandboxed**
(defense-in-depth), but with the operator-supplied `SENTINEL_APPROVE` capabilities and
otherwise strict denies. Exact identification of "root vs dependency" (cwd equals `INIT_CWD`
/ install root vs. under `node_modules`) is pinned in the plan; the default is fail-closed
(no approvals ⇒ strict sandbox).

---

## 5. Fail-closed invariant (non-negotiable)

`--enforce` must **never** silently degrade to running a lifecycle script unsandboxed. Every
path in `sentinel-script-shell` that cannot guarantee kernel containment exits non-zero
*before* running the command, which makes npm abort the install. This is the extension of
Phase 5's backend fail-closed contract to the orchestration layer, and it is the entire
security difference from today's `sentinel install` (registry redirect, scripts wide open).
On Windows or any platform `createSandbox()` rejects, `--enforce` refuses.

---

## 6. Native builds / network caveat

Under the sandbox a `node-gyp`/native build that writes to `build/`, `node_modules`, and tmp
works (allow-default reads+writes; only sensitive paths are denied). A build that needs
**network egress** — e.g. downloading node headers on a cold `~/.node-gyp` cache — is denied
unless a `network` capability is approved for that package. This is the correct security
posture (a build reaching the network is a capability the operator approves), documented rather
than worked around. `~/.node-gyp` itself is not a sensitive path, so header *caching* to it is
allowed.

---

## 7. Testing / DoD

The capstone test proving Phases 2–6 compose (platform-gated: Seatbelt on darwin, bwrap in
Linux CI; effect-asserted; fixtures never live):
- A **benign** fixture package whose `postinstall` attempts a denied action (reads a planted
  secret and writes what it read to an output file, swallowing errors like real exfil).
- Install it via a **real `npm install --registry <local-proxy> --enforce`** against
  `LocalFixtureUpstream`, in a temp project.
- Assert: (a) the secret bytes were **not** obtained (effect), (b) the package **is installed**
  and a benign marker from the same script *did* run (positive control — the script executed,
  it was the denied action that was blocked), and (c) the same install without `--enforce`
  does **not** block the action (control).
Plus unit tests: `scrubEnv` drops credential-shaped `npm_config_*` and keeps benign npm vars;
the wrapper fails closed when the sandbox is unavailable / manifest unreachable.

---

## 8. Scope / out of scope

**In:** `--enforce` flag on `install`; `sentinel-script-shell` bin; `scrubEnv` npm-narrowing +
credential-screen; approval lookup (proxy manifest for deps, operator flags for root);
fail-closed wiring; the capstone DoD test; ADR-0019; ARCHITECTURE §3.6 + CLAUDE updates.

**Out (deferred):** Windows enforcement (fail closed); per-host network filtering; node-gyp
cache pre-warming; richer root-vs-dependency policy; caching manifest lookups. Scoring, rules,
proxy audit path, policy, approval store — untouched.

---

## 9. Definition of done

`npm run build` clean; `npm test` green on both hosts (the new enforced-install effect-test is
platform-gated — Seatbelt on the macOS dev host, bwrap in Linux CI); the malicious fixture is
still blocked by the audit path; a benign package installs and runs its (allowed) scripts under
`--enforce`; a denied action is blocked while the install otherwise succeeds; CLAUDE.md count
line honest; ADR-0019 added (script-shell interposition + credential-screen decision, with the
probe evidence and the rejected re-enumeration alternative); ARCHITECTURE §3.6 updated to
describe the enforced-install path.
