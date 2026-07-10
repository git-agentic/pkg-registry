# Sentinel Phase 3 — Sandboxed Install Runner (design)

**Date:** 2026-06-26
**Status:** Approved (brainstorming) — ready for implementation planning
**Implements:** ADR-0011 Option A (sandboxed install runner — "make approvals enforceable")
**Sequence context:** Phase 1 (auditing proxy) and Phase 2 (approval gate, signed policy,
private registry) are built. Every control so far attaches *signal* or gates
*distribution*; none constrains what code does **when it runs**. Phase 3 closes that gap
for macOS, turning an *approved* capability set into *enforced* runtime least-privilege.

---

## 1. Goal & driver

The 0011 approval gate makes capability an explicit, recorded decision — but a
`postinstall` still executes with full ambient authority once it runs. Phase 3 runs
lifecycle scripts under an OS sandbox whose profile is **generated from the package's
approved capabilities**: an un-approved attempt to read credentials or reach the network
is **denied by the kernel**. This is the staged completion of ADR-0011 (stage B was
approve-without-enforcement; this is enforce).

Success criteria:
1. A lifecycle script's attempt to read a credential path or open a network connection
   that is **not** in the package's approved set is **blocked** by the sandbox — proven
   by asserting the protected resource stayed protected (secret bytes never obtained,
   connection never landed), not merely by a non-zero exit.
2. Approving the capability (and regenerating the profile) lets the same action through.
3. **Fail closed:** on a non-darwin platform the runner refuses loudly ("enforcement
   unavailable") — it never silently runs unsandboxed.
4. Detection and enforcement never drift: the sandbox's credential deny-list is the same
   `SENSITIVE_PATHS` source the `secret-exfil` rule uses.
5. The malicious public fixture stays both **blocked** (by the engine) and **unexecuted**
   (the synthetic-malware-is-never-run rule holds; enforcement is tested with a dedicated
   benign probe).

## 2. Decisions locked during brainstorming

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Sandbox = macOS Seatbelt (`sandbox-exec`)** behind a `Sandbox` interface | A real kernel sandbox, present + hermetically testable on the dev/CI-here platform; Linux (landlock/bubblewrap) is a future impl via the same seam. |
| D2 | **Enforcement unit = per-package lifecycle scripts** | True least-privilege matching the 0011 manifest. |
| D3 | **Enforce + actionable report** (no observe mode) | Stage B was the advisory stage; this is enforce. |
| D4 | **Enforced surface = filesystem-reads + network egress**, relaxed by approvals | The secret-exfil + egress threat; Seatbelt enforces both reliably; children/native inherit it. |
| D5 | **Build shape = `@sentinel/sandbox` package + `sentinel run-scripts` command**; full `npm install --enforce` tree orchestration **deferred** | Demonstrable end-to-end without reimplementing npm. |

## 3. Empirical grounding (probed, not recalled)

All verified in this environment before speccing:
- `sandbox-exec` is present (`/usr/bin/sandbox-exec`) and **enforces**: a denied
  `file-read*` yields `Operation not permitted` (exit 1); allowed paths read fine.
- **Allow-default + targeted-deny runs scripts cleanly** (exit 0); deny-by-default
  SIGABRTs (the dyld/system-machinery baseline problem) — so the model is allow-default.
- **Network deny works** — a connection to a *reachable loopback listener* succeeds
  unsandboxed (exit 0) and is **blocked** under `(deny network*)` / `(deny network-outbound)`
  (exit 1). (Earlier doc-IP probes were confounded — a doc IP routes nowhere regardless.)
- Network filtering is **all-or-nothing** (no per-host) in Seatbelt.
- The **unified log is not accessible here** (`log show` returns nothing), so structured
  per-denial capture is unavailable → the report is *inferred*, not kernel-observed (§6).
- `extractCapabilities` over a raw package dir (paths normalized to `package/<rel>`)
  finds the fixture's 7 capabilities — the detected-capability report is **non-vacuous**.

## 4. Architecture (Approach A)

- **`@sentinel/core`** — add `SENSITIVE_PATHS`: the canonical list of credential
  locations, each entry carrying a `denyPath` (absolute or `~`-relative, for the sandbox)
  and a `detectRe` (for `secret-exfil`). `secret-exfil.ts` is refactored to source its
  **file-path** detections from it (its env-var detections stay), so detection and
  enforcement can't drift. Pure; no OS deps. Existing `secret-exfil` tests pin behavior.
- **`@sentinel/sandbox`** (new package — shells out, so deliberately not core):
  - `types.ts`: `Sandbox` interface, `SandboxResult` (`{ exitCode, stdout, stderr }`).
  - `profile.ts`: `generateProfile(approved: Capability[], opts: { homeDir: string }): string`
    — **pure** SBPL generation. Unit-testable with a fixed `homeDir`, no kernel.
  - `seatbelt.ts`: `SeatbeltSandbox implements Sandbox` — spawns
    `sandbox-exec -f <profileFile> sh -c "<cmd>"`; **throws on non-darwin**
    ("sandbox enforcement unavailable on <platform>").
  - `runner.ts`: `runLifecycleScripts({ packageDir, profile, sandbox }): ScriptRunResult`.
- **`@sentinel/cli`** — `sentinel run-scripts <package-dir> [--approve <kind:target>…]
  [--home <dir>]`.

Boundary: profile **generation** is pure (CI-grade testable everywhere); profile
**execution** is impure/OS (darwin-gated tests). The `Sandbox` interface is the insurance
against `sandbox-exec` being Apple-deprecated and against the future Linux impl.

## 5. Profile generation — `generateProfile(approved, { homeDir })`

Pure function; same inputs ⇒ same SBPL string.

```scheme
(version 1)
(allow default)
;; for each SENSITIVE_PATHS entry NOT covered by an approved `filesystem` capability:
(deny file-read* (subpath "<homeDir>/.ssh"))
(deny file-read* (literal "<homeDir>/.npmrc"))
(deny file-read* (literal "/etc/passwd") (literal "/etc/shadow"))
;; … rest of SENSITIVE_PATHS …
;; if the package has NO approved `network` capability:
(deny network*)
```

- **Filesystem:** one `deny file-read*` per `SENSITIVE_PATHS` entry, omitted when an
  approved `filesystem` capability's target covers that path. `~` is expanded to `homeDir`
  at generation time.
- **Network:** emit `(deny network*)` unless the package has **any** approved `network`
  capability. All-or-nothing — Seatbelt can't host-filter; per-host fidelity lives on the
  proxy fetch path, **not** claimed here (stated honestly).
- **Process / native:** no rules — children and native addons **inherit** the sandbox, so
  fs+network denies constrain them transitively.
- **`SENSITIVE_PATHS`** is the credential subset only — `~/.ssh`, `~/.aws`, `~/.npmrc`,
  `~/.gnupg`, `~/.netrc`, `~/.git-credentials`, `~/.docker/config.json`, `~/.kube`,
  shell rc files (`~/.bashrc`/`~/.zshrc`/`~/.profile`), `/etc/passwd`, `/etc/shadow`.
  **Not** `~/.npm` (npm's own cache/config — denying it would break normal installs) and
  **not** broad paths like `~/.config`.

## 6. Runner, report & fail-closed behavior

**`SeatbeltSandbox.run(cmd, { cwd, profile })`:** checks `process.platform === 'darwin'`
first (else throws); writes the profile to a temp file; spawns
`sandbox-exec -f <file> sh -c "<cmd>"` with `cwd`; returns `{ exitCode, stdout, stderr }`.

**`runLifecycleScripts({ packageDir, profile, sandbox })`:** reads `package.json`; for each
present `preinstall`/`install`/`postinstall`, runs its command under the sandbox with
`cwd = packageDir` and `env` inheriting `process.env` (full `npm_config_*`/`npm_package_*`
replication is deferred). Returns per-hook results.

**`sentinel run-scripts <package-dir> [--approve <kind:target>…] [--home <dir>]`:**
1. Non-darwin → refuse (fail closed).
2. No lifecycle scripts → exit 0 ("nothing to enforce").
3. Read the dir's files (paths normalized to `package/<rel>`) → `extractCapabilities` →
   **detected** capabilities. Parse `--approve` flags → approved set.
4. `generateProfile(approved, { homeDir })` → `runLifecycleScripts(...)`.
5. **On a loud script failure:** report the **detected-but-unapproved** capabilities
   (detected − approved, by atom) as the *likely* cause + "approve and retry, or treat as
   malicious." Exit non-zero.
6. All scripts pass → exit 0.

**Report honesty (advisor):** the report is **inferred from static analysis**
(detected vs. approved), *not* kernel-observed — the unified log isn't reliably available.
And a competent exfil script **swallows the EPERM and exits 0**, so the report is
**best-effort, only on a loud failure**. The hard guarantee is **enforcement** (the kernel
denied the access); the report is opportunistic. The spec/output say this plainly.

**Fail-closed:** non-darwin refuses loudly. In the *deferred* full `sentinel install
--enforce` orchestration, an unapproved script-bearing package will **refuse** (point at
`sentinel preflight`) rather than run under a guessed baseline — consistent with the
proxy's block path. The MVP `run-scripts` primitive runs-under-enforcement-and-reports
because the approved set is passed explicitly.

## 7. Scope fence (deferred)

Full `sentinel install --enforce` tree orchestration + faithful npm-env replication
(`npm_config_*`, `npm_package_*`, ancestor `.bin` PATH, implicit node-gyp builds); Linux
enforcement (landlock/bubblewrap); per-host script network + the force-`HTTP_PROXY`
enhancement; kernel-observed denial capture for exact-path reports; write-confinement /
persistence denies; observe/dry-run mode; proxy-approval fetch in `run-scripts` (MVP uses
explicit `--approve`; wiring `/-/manifest` is a small forward step).

## 8. Testing

- **Pure profile-gen tests** (run on every platform, no kernel): fixed `homeDir` →
  the SBPL denies the right paths + network; an approved `filesystem` capability **omits**
  its deny; an approved `network` capability **omits** `(deny network*)`. Deterministic.
- **Seatbelt enforcement tests, gated on `process.platform === 'darwin'`** (skipped
  elsewhere so the suite stays green cross-platform — never fake enforcement):
  - A dedicated **benign "sandbox-probe" fixture** package whose `postinstall` *attempts*
    to (a) read a **test-planted** sensitive file and (b) connect to a **loopback listener
    the test starts**, writing what it *managed* to obtain to an output file. Assertions
    are on the **effect**: under a no-approval profile the secret content is **absent** from
    the output and the connection **didn't land**; a plain `echo` script runs clean; with
    `--approve filesystem:<planted> network:127.0.0.1` the actions succeed. (This keeps the
    synthetic-malware fixtures text-only/unexecuted; the probe is benign-but-restricted.)
  - `SeatbeltSandbox` throws on a simulated/asserted non-darwin path (fail-closed).
  - `run-scripts` end-to-end on the probe fixture: no approvals → blocked + the report
    lists the detected unapproved capabilities (assert the report is **non-vacuous**).
- **DRY regression:** the existing `secret-exfil` tests stay green after sourcing paths
  from `SENSITIVE_PATHS`.

**Invariants:** profile-gen pure/deterministic; the audit engine's behavior unchanged
(only `secret-exfil`'s path *source* moves); the malicious public fixture stays blocked +
unexecuted; no new runtime deps; suite green on non-darwin; enforcement fails closed
off-darwin.

## 9. Docs

New **ADR-0016** (Seatbelt choice; allow-default model; fs+network surface with
all-or-nothing network; inferred-not-observed, best-effort-on-loud-failure report;
fail-closed-off-darwin; the descope). Annotate **ADR-0011** (stage-A macOS primitive
landed, partial). ARCHITECTURE.md: a sandbox/enforcement section + the new package.
README: `sentinel run-scripts`. CLAUDE.md: the new package in the stack list, the test
count, and a reaffirmation that synthetic malware is scored-as-text-never-executed (the
enforcement probe fixture is benign).

## 10. Out of scope (recap)

Everything in §7; plus Windows; container/microVM sandboxes; signing/notarization of the
runner; and any change to the deterministic scoring engine beyond the `SENSITIVE_PATHS`
refactor.
