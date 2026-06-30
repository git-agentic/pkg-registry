# Sentinel Phase 5 — Linux Sandbox Enforcement (design)

**Date:** 2026-06-30
**Status:** Approved (brainstorming) — ready for implementation planning
**Implements:** cross-platform sandbox enforcement; closes the "macOS-only" gap ADR-0016
explicitly left open (`SeatbeltSandbox` fails closed off-darwin — Linux gets *refusal*, not
*enforcement*, today).
**Sequence context:** Phase 1 (auditing proxy + deterministic scoring), Phase 2 (approval
gate, signed policy, private registry), Phase 3 (macOS Seatbelt runner), and Phase 4 (sandbox
hardening: fail-closed env-scrub + write-confinement) are built. The sandbox enforces an
*approved* capability set as runtime least-privilege — but only on macOS. Phase 5 brings the
**same enforcement to Linux**, where most CI and agent installs actually run.

---

## 1. Goal & threat model

Phases 3–4 turn an approved capability manifest into enforced least-privilege at install time
on macOS via Seatbelt. Off-darwin, `SeatbeltSandbox.run` throws — correct (fail closed, never
run unsandboxed) but it means **Linux gets no enforcement at all**. Every threat Phases 3–4
close on macOS — credential-file reads, network exfil, persistence/tamper writes, env-borne
secret theft — is wide open on Linux, which is where the bulk of npm installs run (CI, build
agents, containers).

Phase 5 ports the enforcement model to Linux using **bubblewrap (`bwrap`)**. The capability
model, the approval flow, the env-scrub (Phase 4, platform-neutral), and the
`SENSITIVE_PATHS` source are reused unchanged. Only the *enforcement backend* is new.

Per-host network filtering stays deferred (bwrap, like Seatbelt, is all-or-nothing on the
network — per-host fidelity lives on the proxy). Windows is out of scope and fails closed.

**Success criteria**
1. On Linux, a lifecycle script's attempt to **read** an unapproved credential path finds it
   inaccessible (proven by asserting the planted secret never reaches the script's output —
   the protected-resource *effect*, not an exit code).
2. A script's attempt to **write** an unapproved protected/persistence path is denied (proven
   by asserting the planted file is unchanged).
3. A script's attempt at **network egress** with no approved `network` capability fails
   (proven by an unreachable host inside the sandbox).
4. Approving the capability (`--approve filesystem:<path>` / `--approve network:<host>`) lets
   the same action through; a non-denied path stays readable/writable.
5. **Fail closed:** if `bwrap` is absent or the kernel refuses namespace creation, the sandbox
   **refuses** — it never falls through to running the script unsandboxed. (Mirrors Seatbelt's
   off-darwin throw.)
6. **No drift between backends:** Linux and macOS share one `SENSITIVE_PATHS` source and one
   capability-coverage matcher (`pathCovers`). Detection (`secret-exfil`) is untouched.
7. **Determinism preserved:** both profile generators are pure given their inputs; the existing
   SBPL determinism tests stay green, and the new bwrap-args generator gets its own.

**Invariants preserved.** Deterministic scoring is untouched — this is enforcement-side only.
No change to the proxy, rules, scoring, policy, or approval store.

---

## 2. Empirical findings (probe-before-spec)

Validated on a **real Ubuntu 24.04 host** (Colima VM, kernel 6.8.0, AppArmor enabled — the
distro/kernel family `ubuntu-latest` runs). Docker-in-container probes were discarded as
unrepresentative (Docker's own seccomp/AppArmor confinement masks the host behavior).

| Probe | Result |
|---|---|
| Unprivileged `bwrap`, stock config | **Blocked** — `kernel.apparmor_restrict_unprivileged_userns = 1` → `Creating new namespace failed` |
| After `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` | `bwrap` runs fully |
| Read-deny via `--tmpfs` overlay over `~/.ssh` | secret **inaccessible** ✓ |
| Write-deny via `--ro-bind <path> <path>` over a persistence file | append **denied** ✓ |
| Network-deny via `--unshare-net` | host **unreachable** ✓ |
| Allowed (non-denied) read inside sandbox | still works ✓ |

**Consequences baked into this design:**
- bubblewrap's bind/overlay model maps **exactly** onto Sentinel's allow-default + deny-path
  model. (This is *why* bubblewrap, not Landlock — see §7.)
- The Ubuntu 24.04 unprivileged-userns restriction is real and would silently break CI. CI is
  the *only* place Linux effect-tests execute, so the mitigation
  (`sysctl kernel.apparmor_restrict_unprivileged_userns=0`) is **load-bearing** and goes in
  `ci.yml` (§6). The same failure at runtime must fail closed (§5, criterion 5).

---

## 3. Architecture — decouple the backend from SBPL

Today the macOS specifics leak: `generateProfile(approved, {homeDir})` returns an **SBPL
string**, the `Sandbox` interface takes that `profile: string`, and `runLifecycleScripts` /
the CLI pass it straight to `sandbox-exec`. SBPL is meaningless on Linux.

**Change the seam so each backend owns its own compilation.**

```ts
// types.ts — structured policy in, no pre-compiled string
interface Sandbox {
  run(cmd: string, opts: {
    cwd: string;
    approved: Capability[];
    homeDir: string;
    env?: NodeJS.ProcessEnv;
  }): SandboxResult;
}
```

- **`generateProfile(approved, {homeDir})`** stays (macOS, SBPL) — pure, and its determinism
  tests stay untouched.
- **`generateBwrapArgs(approved, {homeDir})`** is new (Linux, `string[]` argv after `bwrap`) —
  pure and independently tested, mirroring `generateProfile`.
- **`SeatbeltSandbox`** internally calls `generateProfile`; **`BubblewrapSandbox`** internally
  calls `generateBwrapArgs`. The runner/CLI no longer know SBPL exists.
- **`createSandbox(): Sandbox`** factory:
  - `darwin` → `SeatbeltSandbox`
  - `linux` → `BubblewrapSandbox` (probes `bwrap` on PATH **and** a one-shot namespace
    self-test; throws fail-closed if either fails)
  - else → throw (fail closed)

`runLifecycleScripts` changes its `{ profile, sandbox }` input to `{ sandbox, approved, homeDir }`
and forwards the structured policy. The CLI's hardcoded `process.platform !== "darwin"` exit is
replaced by `createSandbox()` wrapped in fail-closed error handling.

**Shared matcher.** `pathCovers` / `segments` (currently private to `profile.ts`) move to a
shared util imported by both generators, so capability-coverage semantics are single-sourced —
an approval can't cancel a deny on one platform but not the other.

---

## 4. bubblewrap invocation mapping

`generateBwrapArgs(approved, {homeDir})` emits argv replicating Seatbelt's allow-default +
targeted-deny:

| Concern | Seatbelt (existing) | bubblewrap (new) |
|---|---|---|
| Allow-default (read+write) | `(allow default)` | `--bind / /` `--dev /dev` `--proc /proc` |
| Read+write deny (credentials) | `(deny file-read* …)` | overlay target inaccessible — `--tmpfs <dir>`; files masked with an empty read-only source |
| Write-only deny (persistence) | `(deny file-write* …)` | `--ro-bind <path> <path>` (read passes, write fails) |
| Network deny | `(deny network*)` | `--unshare-net` |
| `filesystem` approval | omits that path's deny (`pathCovers`) | omits that path's overlay/ro-bind (`pathCovers`) |
| `network` approval | omits `(deny network*)` | omits `--unshare-net` |

- **Allow-default is read+write** (`--bind`, not `--ro-bind`): lifecycle scripts legitimately
  write to the package dir, `node_modules`, and tmp (e.g. `node-gyp`). Denies are overlaid on
  top of the writable root.
- The **file-vs-directory masking mechanic** for read+write credential targets (tmpfs for
  dirs, an empty read-only bind for single files like `~/.npmrc`) is pinned by a live probe in
  implementation — the spec fixes the *strategy* (real content must be inaccessible), the plan
  fixes the exact flag per target without an impure `stat` in the pure generator.
- **No firmlink canonicalization** on Linux (no firmlinks; probe-confirmed bind matches the
  literal path). That logic stays macOS-only.

---

## 5. Fail-closed behavior (non-negotiable)

`BubblewrapSandbox.run` must **refuse, never degrade**:
- `bwrap` not on PATH → throw with an actionable message (install hint).
- Kernel refuses namespace creation at runtime (the 24.04 restriction, or a kernel without
  unprivileged userns) → treated as an **enforcement failure**; the script is **not** run
  unsandboxed. Surface it the way Seatbelt surfaces its off-darwin throw.
- Non-linux call (defense-in-depth even though the factory gates platform) → throw.

This matches invariant: *a sandbox that cannot enforce blocks; it never silently runs
install-time code without the sandbox.*

---

## 6. CI & tests

**`ci.yml`** (runs on `ubuntu-latest`, node 22/24) gains, before `npm test`:
```yaml
- run: sudo apt-get update && sudo apt-get install -y bubblewrap
- run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   # 24.04 userns restriction (probe-proven)
```
This is the first time Linux *effect* enforcement is exercised in CI. (Today CI is Linux, so
the macOS effect-tests skip there and run only on the dev's Mac; symmetrically, these Linux
effect-tests run in CI and skip on the dev's Mac.)

**Tests:**
- **Pure generator** (`generateBwrapArgs`) — runs on every platform: argv contains the right
  `--tmpfs` / `--ro-bind` / `--unshare-net`; `filesystem`/`network` approvals omit the right
  entries; determinism (pinned inputs ⇒ identical argv); shared `pathCovers` semantics match
  the SBPL side.
- **Linux effect-tests** — gated `process.platform === "linux"` *and* bwrap-available, skipped
  on darwin; mirror `seatbelt.test.ts`: plant a fake secret / persistence file, run a probe
  command under the sandbox, assert it **cannot** read the secret, **cannot** egress, **cannot**
  write the persistence file, and **can** touch a non-denied path; approving the capability lets
  it through.
- **Fail-closed test** — bwrap-absent path throws (stubbable, runs anywhere).
- **CLAUDE.md `npm test` count line** updated to honestly state the platform-skip split (a
  darwin dev host skips the Linux effect-tests; CI skips the darwin ones). Exact numbers fixed
  in the plan once the suite is written.

---

## 7. Alternatives considered & rejected

- **Landlock + seccomp (no external binary).** Rejected: Landlock is **allow-list-only** — it
  grants access to path hierarchies and has no way to *deny a subpath of a granted hierarchy*,
  so "allow `~` except `~/.ssh`" is inexpressible. Sentinel's whole model is allow-default +
  carve-out-denies; Landlock would force a different, less faithful model and require a native
  helper (Node has no Landlock binding) plus kernel-version juggling (network rules need ABI v4
  / kernel 6.7). bubblewrap replicates the existing model exactly with a widely-available
  userspace binary.
- **Stacking seccomp/Landlock on top of bwrap "for depth."** Rejected by YAGNI — no specific
  threat in scope demands syscall-level filtering beyond what the bind/overlay/unshare model
  already denies.
- **Reusing the `profile: string` slot for bwrap argv.** Rejected — a leaky abstraction; the
  string is SBPL-specific. The backend owns its compilation (§3).

---

## 8. Scope / out of scope

**In:** `BubblewrapSandbox`, `generateBwrapArgs`, `createSandbox` factory, the `Sandbox`
interface refactor, Linux persistence entries in `SENSITIVE_PATHS` (`platforms` tag), CLI
wiring via the factory, `ci.yml` mitigation, ADR-0018, ARCHITECTURE §3.6 update.

**Out (deferred, unchanged):** per-host network filtering (proxy's job); filesystem read/write
sub-kinds (mac-consistent YAGNI); `npm install --enforce` orchestration; Windows enforcement
(fails closed). LLM, scoring, proxy, policy, approval store — all untouched.

---

## 9. Definition of done

`npm run build` clean; `npm test` green on both the dev's macOS host (Linux effect-tests
skipped) and in Linux CI (Linux effect-tests **running and passing**, macOS ones skipped);
malicious fixture still blocked; CLAUDE.md count line honest; ADR-0018 added (cross-platform
backend abstraction + the userns/CI mitigation); ARCHITECTURE §3.6 updated to describe both
backends behind `createSandbox`.
