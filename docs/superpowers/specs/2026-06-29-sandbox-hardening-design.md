# Sentinel Phase 4 — Sandbox Hardening (design)

**Date:** 2026-06-29
**Status:** Approved (brainstorming) — ready for implementation planning
**Implements:** the env-scrub + write-confinement gaps ADR-0016 explicitly deferred
**Sequence context:** Phase 1 (auditing proxy + deterministic scoring), Phase 2 (approval
gate, signed policy, private registry), and Phase 3 (macOS Seatbelt runner) are built.
Phase 3's sandbox is **allow-default** with two targeted denies — `file-read*` on
credential paths and all-or-nothing `network*`. Two exfil/persistence holes remain open;
Phase 4 closes both.

---

## 1. Goal & threat model

The Phase 3 sandbox blocks reading credential *files* and (optionally) all network egress.
A malicious lifecycle script can still:

1. **Exfiltrate env-borne credentials** — scripts inherit `process.env` wholesale, so
   `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, etc. are readable **without ever
   touching a file**. The `file-read*` deny does nothing here. (Flagged in the Phase 3
   whole-branch review; `process.env` scrubbing was explicitly deferred in ADR-0016.)
2. **Persist / tamper via writes** — allow-default means writes are unrestricted. A script
   can append to `~/.bashrc`/`~/.zshrc`, overwrite `~/.ssh/authorized_keys`, inject into
   `~/.npmrc`, drop a `LaunchAgent`, or edit a crontab — none denied today.

Phase 4 closes both. Per-host network filtering and kernel-observed denial capture stay
deferred (Seatbelt can't host-filter; the unified log isn't accessible here) — unchanged
from Phase 3.

**Success criteria**
1. A script's attempt to read a credential env-var that is **not** approved finds that var
   **absent from its environment** (proven by asserting the value never reaches the script's
   output, not by an exit code).
2. A script's attempt to write a protected path that is **not** approved is **denied by the
   kernel** (proven by asserting the planted file is unchanged).
3. Approving the capability (`--approve env:<NAME>` / `--approve filesystem:<path>`) lets the
   same action through.
4. **Fail closed:** env scrubbing is allowlist-based — an unmatched var (including a
   novel-named credential) is dropped, not passed. Off-darwin enforcement still refuses
   loudly (unchanged).
5. Detection and enforcement never drift: env detection reuses `secret-exfil`'s existing
   env-var patterns; write denies and read denies share the single `SENSITIVE_PATHS` source.

**Invariants preserved.** Deterministic scoring is untouched — this is enforcement-side plus
capability *data*. Profile and env generation stay **pure** (same inputs ⇒ same output,
unit-testable with no kernel). Synthetic malware fixtures stay scored-as-text and **never
executed**; enforcement is tested with the benign sandbox-probe fixture. No new runtime deps.

## 2. Empirical grounding (probed, not recalled)

Confirmed by reading the current code before speccing:
- **`CapabilityKind`** is `"network" | "filesystem" | "process" | "native"`
  (`packages/core/src/types.ts:47`). The whole capability pipeline — `extractCapabilities`,
  `capabilityAtom`, `diffCapabilities`, `unapprovedAtoms` — is **kind-generic**; adding a
  fifth kind flows through with no special-casing.
- **`extractCapabilities`** delegates detection to `scanForCapabilities(file)` in
  `detect/patterns.ts` and is itself kind-agnostic, so emitting `env` capabilities is purely
  a matter of adding env patterns + extending the union.
- **`parseApprovals`** (`packages/cli/src/index.ts:255`) validates `kind` against the literal
  list `["network","filesystem","process","native"]` — `env` must be added there.
- **The runner does not pass `env` today** — `runLifecycleScripts` calls
  `sandbox.run(cmd, { cwd, profile })` with no `env`, so `SeatbeltSandbox` falls back to
  `opts.env ?? process.env` (full inheritance). The `Sandbox.run` signature **already
  accepts `env?`** (`packages/sandbox/src/types.ts`), so the scrub seam needs **no interface
  change** — the runner just computes and passes a scrubbed env.
- **`generateProfile`** already has `pathCovers` (path-segment-anchored coverage) and
  `canonicalizeMacPath` (firmlink `/etc`→`/private/etc`) — both reused for write denies.

The **`ENV_ALLOWLIST` contents must be validated against a real `npm install` lifecycle**
before the plan locks (see §4) — an over-tight allowlist that breaks legitimate installs is
the primary risk of the fail-closed choice.

## 3. Decisions locked during brainstorming

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Close env-scrub AND write-confinement in one phase** | Both halves share the `SENSITIVE_PATHS` source and are darwin-testable; together they form a coherent "close exfil + persistence" phase. |
| D2 | **Env scrubbing is allowlist-based (fail-closed)** | Pass only known-safe vars; any unmatched var (incl. a novel-named credential) is dropped. Consistent with the project's fail-closed ethos (private namespaces, off-darwin refusal). |
| D3 | **Env passthrough is relaxed via a new `env` capability kind** | `--approve env:NPM_TOKEN` extends the allowlist for that package — exactly like network/filesystem approvals relax their denies. Detected env reads appear in the detected-but-unapproved report for free. |
| D4 | **One protected-path list with per-mode flags** (`modes: ("read"\|"write")[]`) | Single source of truth keeps the detection↔enforcement no-drift invariant strongest. Credential paths are `["read","write"]`; persistence targets are `["write"]`. |
| D5 | **A `filesystem` approval relaxes both read and write** for its target | Keep the `filesystem` capability mode-agnostic; read/write sub-kinds are YAGNI and deferred. |

## 4. Env-scrubbing half

### 4.1 Core — the `env` capability kind
- `CapabilityKind` gains `"env"`. `target` = the env var **name** (e.g. `NPM_TOKEN`); `"*"`
  remains the dynamic/uncomputable sentinel.
- `scanForCapabilities` (`detect/patterns.ts`) gains env-credential patterns: `process.env.X`,
  `process.env["X"]`, and destructured `const { X } = process.env` where `X` matches the
  credential shape (`*_TOKEN`, `*_SECRET`, `*_KEY`, `*_PASSWORD`, `AWS_*`, plus known names
  like `NPM_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `ANTHROPIC_API_KEY`). **These mirror
  `secret-exfil`'s existing env-var detections** so detection and enforcement share one
  source. Emits `{ kind: "env", target: "<NAME>", evidence }`.
- `parseApprovals` accepts `env:<NAME>` (add `"env"` to its kind whitelist).

### 4.2 Sandbox — `scrubEnv` (pure)
- New pure function `scrubEnv(sourceEnv: NodeJS.ProcessEnv, approvedEnv: Capability[]):
  NodeJS.ProcessEnv` in `@sentinel/sandbox` — sibling to `generateProfile`, no kernel,
  unit-testable everywhere, deterministic.
- **`ENV_ALLOWLIST`** lives in `@sentinel/sandbox` (only the runner consumes it; core needs
  nothing). Names + prefixes npm lifecycle scripts genuinely need:
  `PATH`, `HOME`, `SHELL`, `USER`, `LOGNAME`, `PWD`, `TMPDIR`, `TMP`, `TEMP`, `LANG`,
  `LC_*`, `TERM`, `NODE*`, `npm_config_*`, `npm_package_*`, `npm_lifecycle_*`, `npm_node_*`.
  **Validate against a real `npm install` lifecycle before locking the plan** (probe-first).
- `scrubEnv` returns every var whose name matches `ENV_ALLOWLIST`, **plus** any var named by
  an approved `env` capability. Everything else is dropped — **fail-closed**.

### 4.3 Seam
- `runLifecycleScripts` gains an `approved: Capability[]` parameter, computes
  `scrubEnv(process.env, approvedEnv)`, and passes the result as the already-existing
  `opts.env` to `sandbox.run`. **No `Sandbox` interface change.**

## 5. Write-confinement half

### 5.1 Core — per-mode `SensitivePath`
- `SensitivePath` gains `modes: ("read" | "write")[]`.
- **Credential entries** (`~/.ssh`, `~/.aws/credentials`, `~/.npmrc`, `~/.gnupg`, `~/.netrc`,
  `~/.git-credentials`, `~/.docker/config.json`, `~/.kube`, shell rc files, `/etc/passwd`,
  `/etc/shadow`) → `["read","write"]` (block exfil **and** tamper).
- **New persistence-only entries** → `["write"]`: `~/Library/LaunchAgents`,
  `~/Library/LaunchDaemons`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`, the crontab
  dir (`/private/var/at/tabs`), `~/.config/autostart`. No `detectRe`.
- **Consumers stay narrow:** `secret-exfil` consumes only entries that have a `detectRe`
  (behavior unchanged — its tests stay green). The sandbox reads `modes`.

### 5.2 Sandbox — write denies in `generateProfile`
- For each entry whose `modes` includes `"write"` and which is **not covered** by an approved
  `filesystem` capability, emit a `(deny file-write* <items>)` line — reusing the existing
  `pathCovers` and `canonicalizeMacPath`.
- **Read denies** come from entries whose `modes` includes `"read"` (functionally identical to
  today, since every current read path keeps `"read"`).
- A `--approve filesystem:<target>` relaxes **both** the read and write deny for that path
  (the `filesystem` capability stays mode-agnostic).

## 6. CLI / report integration
- `run-scripts` threads the parsed `approved` set into `runLifecycleScripts` (so `scrubEnv`
  sees approved `env` caps).
- Add an operator note (mirroring the existing all-or-nothing-network warning): credential
  env-vars are scrubbed by default; grant one with `--approve env:NAME`.
- `unapprovedAtoms` already covers `env` atoms (kind-generic), so a script failing after
  reaching for an un-approved `NPM_TOKEN` or writing a `LaunchAgent` surfaces in the inferred
  failure report. Honesty caveat unchanged: the report is static-inferred and best-effort on
  loud failure; the hard guarantee is kernel enforcement.

## 7. Testing
- **Pure, every-platform (no kernel):**
  - `scrubEnv` — allowlisted vars pass; credential vars (matched and novel-named) drop; an
    approved `env:` cap lets its var through; deterministic for the same inputs.
  - `generateProfile` — write denies emitted for write-mode entries, firmlink-canonicalized;
    omitted when a `filesystem` approval covers them; persistence paths denied; read-deny
    behavior unchanged; deterministic.
- **Darwin-gated enforcement (skipped elsewhere — never faked):** extend the benign
  **sandbox-probe** fixture so its `postinstall` attempts to (a) read a credential env-var and
  write its value to an output file, and (b) write to a **test-planted** sensitive path.
  Assert on the **effect**: under no-approval the env-var value is **absent** from output and
  the planted file is **unchanged**; with `--approve env:<NAME>` / `--approve
  filesystem:<planted>` the actions succeed. Synthetic malware fixtures stay
  text-only/unexecuted.
- **DRY regression:** `secret-exfil` tests stay green after `SensitivePath` gains `modes`.

**Invariants under test:** profile-gen + `scrubEnv` pure/deterministic; the deterministic
audit engine's scoring unchanged; the malicious public fixture stays blocked + unexecuted;
suite green on non-darwin; enforcement fails closed off-darwin and env scrubbing fails closed
on unmatched vars.

## 8. Docs
New **ADR-0017** (env allowlist fail-closed; `env` capability kind; per-mode `SensitivePath`;
write-confinement surface incl. persistence paths; `filesystem` approval relaxes both modes).
Annotate **ADR-0016** (env-scrub + write-confinement gaps now closed). ARCHITECTURE.md sandbox
section gains the env-scrub + write-confinement surfaces. CLAUDE.md: the new `env` kind and the
updated test count.

## 9. Scope fence (deferred)
Read/write sub-kinds on the `filesystem` capability; per-host script network; kernel-observed
denial capture for exact-path reports; Linux enforcement (landlock/bubblewrap); full `sentinel
install --enforce` tree orchestration. Unchanged from Phase 3. Plus Windows; container/microVM
sandboxes; any change to the deterministic scoring engine beyond the `SensitivePath.modes` +
`env`-detection additions (which add capability *data*/detections, not scoring weights).
