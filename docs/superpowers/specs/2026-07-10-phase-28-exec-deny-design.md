# Phase 28 — macOS exec deny-by-default (+ #4 README Status fix)

**Date:** 2026-07-10
**Issues:** [#8](https://github.com/git-agentic/pkg-registry/issues/8) (process/native detected but not enforced — this phase),
[#4](https://github.com/git-agentic/pkg-registry/issues/4) (README Status inconsistency — standalone companion fix)
**Status:** Approved design, pre-implementation

## Decision summary

Issue #8 offered a choice: implement a feasible exec policy, or formally keep
`process`/`native` advisory-only. Decision: **enforce, cross-platform, using each
platform's path-based kernel primitive** — no runtime supervisor. Decomposed:

1. **Phase 28 (this spec):** macOS Seatbelt exec deny-by-default via `process-exec*`.
2. **Phase 29 (follow-up, new issue):** Linux exec deny-by-default via **Landlock**
   (`LANDLOCK_ACCESS_FS_EXECUTE`, kernel ≥ 5.13; needs a small native piece since Node
   exposes no Landlock syscalls — probe-before-spec applies).
3. **Runtime supervisor (seccomp-notify/pidfd):** shelved; only if path-based gating ever
   proves insufficient. It layers on top of this design rather than replacing it.
4. **`native` kind:** formally advisory-only on both platforms, permanently — no
   path-level sandbox primitive distinguishes loading a `.node`/WASM artifact from
   reading it. Recorded in the ADR.

`#8` stays open until Phase 29 lands (its claim is cross-platform); the Phase 28 PR
comments on it and ADR-0042 records the whole decision immediately.

## Companion quick fix: issue #4 (separate tiny branch/PR)

The README Status section says "built through Phase 25" while the body documents
Phase 26 material (`SENTINEL_AUTO_QUARANTINE`, `SENTINEL_MAX_UNPACKED_BYTES`) and the
repo is at Phase 27 — the phase number drifts every phase. Fix: **drop phase numbering
from Status**. Status becomes a pre-1.0 maturity statement + capability list (proxy,
policy gate, deny-by-default sandbox, CLI, MCP server, GitHub Action, CI posture) +
a pointer to `docs/adr/` as the authoritative build log. Also sweep the README tail
summary (~lines 740–760, currently ends at Phase 25) so no other spot makes a
phase-count claim. No capability claims added or removed. Independent of Phase 28;
closes #4 on merge.

## Phase 28 scope

**In scope:** the Seatbelt backend (`packages/sandbox`) gains an exec deny-by-default
layer enforcing the `process` capability kind on macOS, mirroring Phase 25's write-deny
architecture: blanket deny → floor re-allow → Grant re-allow → curated carve-out
re-deny, relying on SBPL last-match-wins.

**Non-goals (stated in ADR-0042):** Linux enforcement (Phase 29); `native` enforcement
(advisory forever); runtime per-spawn decisions; a policy-configurable floor (matches
Phase 25's deliberately non-configurable write floor). Scoring, the approval/manifest
model, and the proxy are untouched (invariants #1–#7).

## Design

### Exec floor (`packages/sandbox/src/exec-floor.ts`, new)

Pure `execAllowFloor({ nodePrefix, projectRoot })` — sibling of `write-floor.ts` —
returns the fixed, non-configurable set of subpaths where exec is allowed without any
Grant:

- `/bin`, `/usr/bin`, `/usr/sbin` — system tools (`sh`, `make`, `cc` shims, …)
- `nodePrefix` — the node runtime itself (nvm/fnm/volta installs under `$HOME` included)
- `projectRoot` — `node_modules/.bin` shims and local scripts (see residual risk)
- `/Library/Developer`, `/Applications/Xcode.app` — Apple toolchains (node-gyp builds)
- `/opt/homebrew`, `/usr/local` — Homebrew prefixes (arm64 / Intel), user-installed tools

### Curated exec carve-out (`SENSITIVE_EXECUTABLES`)

A static table — sibling of `SENSITIVE_PATHS` — of exfil-capable commands re-denied
*after* the floor allow unless a `process:` Grant lifts them: `curl`, `wget`, `nc`,
`ncat`, `socat`, `osascript`, `scp`, `sftp`. Each command expands to fixed candidate
literals across the floor's bin dirs (`/bin`, `/usr/bin`, `/opt/homebrew/bin`,
`/usr/local/bin`). No PATH resolution anywhere — the generator stays pure and
deterministic (same inputs ⇒ same profile string).

### Profile changes (`packages/sandbox/src/profile.ts`)

`generateProfile` appends an exec section (last-match-wins, same layering discipline as
the write section):

```
(deny process-exec*)
(allow process-exec* (subpath "…floor…") … (subpath "…path-Grants…"))
(deny process-exec* (literal "…uncovered carve-out entries…"))
```

`process-fork` stays allowed (fork without exec is just node). The initial
`sandbox-exec → /bin/sh` exec is covered by `/bin` in the floor. `seatbelt.ts` already
passes `nodePrefix` and `projectRoot` to `generateProfile` — **no new sandbox inputs**.

### Grant semantics (`--approve process:<target>`)

Three target shapes, disambiguated by syntax — a target containing `/` (or starting
with `~`) is a path; a bare word is a command name; `*` is the wildcard:

| Target shape | Example | Effect |
|---|---|---|
| Command name (no `/`) | `process:curl` | Lifts that command's carve-out literals only; floor unchanged |
| Path (contains `/` or starts with `~`) | `process:/opt/tools/foo` | Appended to the exec allow as a path Grant (guarded like filesystem Grants — `isSafeGrantTarget`-style check, `expandHome` resolves `~` against `homeDir`) |
| `*` (detector's target for a bare `child_process` import) | `process:*` | Lifts the entire carve-out set; does **not** open non-floor paths — exec from `/tmp` still needs an explicit path Grant |

Deny-by-default stays meaningful even under the broadest detected capability.

### Violation telemetry

`computeDenySet` gains the uncovered carve-out exec literals so `classifyViolation` can
report a denied exec (`Operation not permitted` + non-zero exit) as a
`confirmed`/`suspected` runtime violation. Best-effort, containment-unchanged — the
ADR-0023 contract holds; a denial the script swallows evades telemetry, not containment.
Denied execs from non-floor paths (not in the deny set) classify as `suspected` at best,
same as today's out-of-set permission errors — acceptable, documented.

### Accepted residual risk (recorded in ADR-0042 + threat model)

`projectRoot` is in the floor, so a package can write a binary into its own tree and
exec it. The strict alternative (floor without `projectRoot`/Homebrew) was rejected: it
breaks every `node_modules/.bin` shim and brew-installed build tool out of the box.
Existing mitigations: bundled native/oversized content surfaces as `unscanned-content`
(Phase 27), and the spawn pattern surfaces via `process` capability detection/scoring.
What Phase 28 kills is the drop-outside-the-tree pattern: exec from `/tmp`, `~/Downloads`,
caches, or any writable-but-not-project location is kernel-denied.

## ADR + docs

- **ADR-0042** — exec deny-by-default on darwin; Landlock plan recorded for Linux
  (Phase 29); `native` formally advisory-only; floor + carve-out contents; the
  projectRoot residual risk with rejected alternatives. Extends ADR-0038; supersedes
  nothing.
- **ARCHITECTURE §3.6** — replace the "process/native are advisory-only" enforcement-scope
  note with the new split: `process` enforced on darwin (Phase 28), Linux pending
  (Phase 29), `native` advisory by decision.
- **Threat model §3.9**, **CLAUDE.md**, **README sandbox section** — same update.
- File the Phase 29 (Linux/Landlock) issue; comment on #8; #8 closes when Phase 29 lands.

## Testing

Hermetic, platform-neutral generator tests:

- blanket `(deny process-exec*)` present; floor re-allow follows it
- carve-out literals emitted *after* the floor allow (last-match-wins ordering)
- `process:curl` Grant removes curl's carve-out literals
- `process:/abs/path` Grant appends to the allow; unsafe/relative targets guarded
- `process:*` lifts all carve-outs but adds no path allows
- deny-set non-drift check extended to the exec entries

Darwin-gated Seatbelt effect tests (benign probes only — synthetic malware fixtures stay
scored-as-text, never executed; same gating pattern as Phase 25's effect tests):

1. **Positive control:** a lifecycle script exec'ing `/bin/echo` and a
   `node_modules/.bin` shim succeeds.
2. **Dropped binary:** a script writes an executable to `$TMPDIR` (inside the write
   floor), `chmod +x`, execs it → **denied**; the deny surfaces as a runtime violation.
3. **Carve-out:** `/usr/bin/curl --version` denied without a Grant; allowed with
   `--approve process:curl`.

Definition of done: `npm run build` clean, `npm test` green (count updated in
CLAUDE.md), malicious fixtures still blocked, ADR-0042 + doc updates landed.

## Rejected alternatives

- **Formalize advisory-only everywhere** — cheapest honest close, but leaves the one
  platform with a native exec primitive unused while the sandbox permits running
  dropped binaries.
- **Strict floor (system + node only)** — stronger (denies project-tree exec) but
  breaks ordinary installs wholesale; unacceptable default friction.
- **Configurable floor** — diverges from Phase 25's non-configurable-floor precedent;
  grows the policy surface for no demonstrated need.
- **Runtime supervisor (seccomp-notify / ptrace broker)** — per-spawn runtime decisions
  we don't need at Chrome-sandbox-class complexity; kept as a future escalation path.
