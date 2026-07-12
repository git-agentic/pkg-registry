# ADR-0051: Sandboxed `sentinel exec` — scoped runtime containment for Sentinel-mediated command execution

**Status:** Accepted
**Date:** 2026-07-12

Extends ADR-0019 (enforced installs — lifecycle scripts run under the sandbox
via `npm_config_script_shell` interposition), ADR-0038 (sandbox default-deny),
and ADR-0042/0043/0044 (exec deny-by-default, both platforms). Supersedes
nothing.

## Context

Enforced installs (`sentinel install --enforce`, ADR-0019) sandbox every
lifecycle script. That closes the install-time gap, but it is not the only
place a package's code runs. ADR-0049's Gen-2 finding is a reminder of the
shape of the residual problem even after the audit rule catches the specific
loader: once a package is on disk, *importing it* (`require()`/`import`) or
*running its CLI* (`npx <pkg>`, or invoking its `bin` directly) executes
arbitrary code with none of the containment enforced installs provide. The
audit engine (rules, magic-byte classification, `native-payload-loader`) is
the layer that decides whether that code *should* run at all; nothing in the
shipped system contains it at the point it *does* run, outside the lifecycle-
script path.

A full solution — interposing on every possible way a package's code can be
invoked (module resolution hooks, arbitrary `npx`/package-manager bin
resolution, editor/test-runner integrations) — is a large surface with no
single trust boundary to anchor it. What the sandbox backends already expose
is a way to run *one* command, by explicit file/args, under the same
approved-capability profile as an enforced install. That is a boundary we can
ship precisely, without pretending to cover everything a package can do.

## Decision

### `Sandbox.runArgv(file, args, opts)`

Both backends (`SeatbeltSandbox`, `BubblewrapSandbox`) implement `runArgv` in
`packages/sandbox/src/types.ts`, alongside the existing `run(cmd, opts)`:

- `run` invokes `/bin/sh -c <cmd>` — a shell string, as lifecycle scripts are
  defined in `package.json`.
- `runArgv(file, args, opts)` invokes `file` with `args` **directly, with no
  shell** — execFile-style, argument boundaries preserved (no re-quoting, no
  shell metacharacter expansion). Seatbelt's `execWithTail` and bubblewrap's
  equivalent are shared between `run` and `runArgv`; only the argv tail
  differs (`["/bin/sh", "-c", cmd]` vs. `[file, ...args]`). The profile
  generation, deny-set computation, and `classifyViolation` violation
  telemetry are the *same code path* for both entry points — `runArgv` is not
  a parallel, differently-audited enforcement mechanism.

### `sentinel exec` CLI command

```
sentinel exec [--approve <cap...>] -- <command> [args...]
```

Implemented in `packages/cli/src/index.ts`. On invocation:

1. `createSandbox()` selects Seatbelt (darwin) or bubblewrap (linux); failure
   (unsupported platform, missing `sandbox-exec`/`bwrap`) exits non-zero
   rather than falling back to unsandboxed execution — the existing
   fail-closed contract (ADR-0016/0018).
2. `parseApprovals(opts.approve)` — the identical capability-parsing path
   `run-scripts`/`install --enforce` use. `--approve <cap...>` accepts
   repeated `kind:target` pairs (`network:host`, `process:curl`, `env:NAME`,
   `filesystem:/path`).
3. `scrubEnv(process.env, approved)` — the same fail-closed environment
   scrub enforced installs apply; a credential-shaped var is stripped unless
   explicitly approved via `env:NAME`.
4. `cwd` and `projectRoot` are both set to `process.cwd()` — `sentinel exec`
   runs relative to wherever it's invoked, with the project-root exec-floor
   carve-out (ADR-0042) anchored there, not to some other install directory.
5. `sandbox.runArgv(command, args, { cwd, approved, homeDir: homedir(), env,
   projectRoot: cwd })` runs the command.
6. The child's `stdout`/`stderr` are written through
   (`process.stdout.write`/`process.stderr.write`), and the command's exit
   code is set via `process.exitCode = r.exitCode` — not `process.exit()` —
   so Node drains buffered stdout before the process actually exits, avoiding
   truncation of piped output (a `sentinel exec -- cmd | head` style
   invocation gets the full write, not a torn one).

Because it reuses `runArgv`, `sentinel exec` gets, for free, the same
approved-capability write/read/network/exec floors, the same
`SENSITIVE_PATHS`/`SENSITIVE_EXECUTABLES` carve-outs, and the same
`computeDenySet` + `classifyViolation` best-effort violation telemetry as
enforced installs (ADR-0023, ADR-0038, ADR-0042/0043/0044) — no new
enforcement logic was written for this feature, only a new entry point into
the existing one.

### Scope limitation (stated plainly)

**`sentinel exec` protects only Sentinel-mediated execution.** It contains
exactly the command given after `--`, run through this CLI, and nothing else.
Concretely, it does **not** contain:

- A raw `require()`/`import` of a package performed outside `sentinel exec`
  (an ordinary `node script.js`, a test runner loading a dependency, an
  editor extension resolving a module).
- `npx foo` (or any package manager's bin resolution) run directly, without
  going through `sentinel exec` first.

This is **defense-in-depth behind the registry-gate static detection**
(rules + magic-byte classification + `native-payload-loader`, ADR-0049),
which remains the primary and independently-sufficient control: a package
that should be blocked is blocked at audit time, before any of its bytes are
trusted to run anywhere, sandboxed or not. `sentinel exec` narrows the blast
radius of an audit-time false negative for the one invocation path an
operator chooses to route through it; it is not a substitute for the audit,
and its absence from a given invocation is not a containment regression —
the registry gate was never conditioned on it.

v1 ships a **single explicit interface**: `exec -- <command> [args...]`. It
is deliberately **not** a package-bin resolver — it does not look up a
package's declared `bin` field, does not walk `node_modules/.bin`, and does
not attempt to intercept `npx`/`npm exec` transparently. The operator names
the exact executable and arguments; `sentinel exec` does not guess what a
package "would" run.

### Future-resolver constraint

If a later phase adds `npx`/package-manager-aware resolution on top of this
(e.g. `sentinel npx <pkg>` routing through `runArgv` the way `sentinel npx`
already routes package resolution through the proxy), that resolution
**must not silently bypass the configured Sentinel registry** — any such
resolver has to fetch/verify packages the same gated way `sentinel install`
and `sentinel npx` already do, not introduce a second, unaudited path to
running a package's code. This is a constraint on future work, not a shipped
behavior; no such resolver exists in v1.

## Consequences

- Sentinel-mediated command execution (`sentinel exec -- <cmd>`) is now
  contained under the same approved-capability model as enforced installs —
  a materialization-and-launch chain that reaches this entry point is
  subject to the same write/exec floors and carve-outs a lifecycle script
  would be.
- The residual runtime gap this ADR does not close: imports and CLI
  invocations that don't go through `sentinel exec` remain uncontained. This
  is stated as a permanent scope limitation, not a future TODO — closing it
  fully would require intercepting module resolution and process-launch
  paths system-wide, which is out of scope for a per-invocation CLI command.
- No change to scoring, the rule pipeline, the proxy, or any Accepted
  invariant (#1–#7) — this is additive containment surface on the sandbox
  package plus one new CLI command.
- `Sandbox` implementations gain one new method (`runArgv`) with the same
  fail-closed contract as `run`; no new sandbox backend was introduced.

## Rejected alternatives

- **A package-bin resolver in v1** (resolve a package's `bin` field or
  `node_modules/.bin` entry and run it under the sandbox automatically) —
  rejected: it invites exactly the future-resolver registry-bypass risk
  this ADR flags, and the explicit `exec -- <cmd>` interface is sufficient
  for the immediate need (an operator or CI step choosing to run one
  command under containment) without designing that resolution surface
  under time pressure.
- **Transparent interposition on `require()`/`import`** — rejected as far
  larger in scope (a Node loader hook affecting every process on the
  machine, not a scoped CLI invocation) and not needed to close the
  Gen-2-shaped gap ADR-0049 already closes at audit time; `sentinel exec` is
  a narrower, additive control, not a replacement for the registry gate.
- **Falling back to unsandboxed execution when `createSandbox()` fails** —
  rejected as inconsistent with the fail-closed contract every other
  sandbox entry point holds (ADR-0016/0018); `sentinel exec` exits non-zero
  instead.
