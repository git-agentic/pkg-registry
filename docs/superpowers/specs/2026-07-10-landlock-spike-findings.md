# Landlock exec-floor spike — findings (2026-07-10)

**Verdict:** PASS (CI run: https://github.com/git-agentic/pkg-registry/actions/runs/29091874486)

Feasibility is **PROVEN**: Landlock exec-restriction (`LANDLOCK_ACCESS_FS_EXECUTE`) works inside
`bwrap` on GitHub-hosted `ubuntu-latest` runners, and the floor's deny behavior is empirically
attributable to Landlock (not a `/tmp`-noexec or other mount-level artifact).

This is the third and final iteration of the spike. Two earlier CI runs are part of the record:

- `29091111051` — **FAILED** (exit 11). The original floor (`--allow /bin --allow /usr/bin
  --allow /usr/sbin --allow $NODE_PREFIX`) omitted the dynamic-linker/library directories, so
  section A's positive control (`/bin/sh`, dynamically linked) failed to `execve` —
  `landlock-exec: execve(/bin/sh): Permission denied`, `exit=127` — before section B ever ran.
- `29091363907` — **PASS** after adding `--allow /lib --allow /lib64 --allow /usr/lib --allow
  /usr/lib64` to the floor (see "IMPORTANT Phase-2 finding" below). Section A, B, and C all
  passed, but section B's denial had not yet been differentially proven Landlock-attributable
  (that gap was closed in the next iteration).
- `29091874486` — **PASS**, now with a section-B differential control (B-control) added, proving
  attribution, and with section C's label corrected to honestly state it is a mount-level (DAC)
  property, not a Landlock one. This is the **authoritative run** cited above.

## Environment (ubuntu-latest runner)

- cc: `/usr/bin/cc`, `cc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`
- bwrap: `/usr/bin/bwrap`, `bubblewrap 0.9.0`
- kernel: `6.17.0-1018-azure`
- Ubuntu: 24.04
- node prefix: `/opt/hostedtoolcache/node/24.18.0/x64`
- Landlock ABI inside bwrap: not explicitly printed by the compiled helper (no ABI-version log
  line was emitted by `landlock-exec` in any run's captured output) — but Landlock was
  demonstrably **available and enforcing** inside bwrap: section A's positive control succeeded
  once the floor was correct, section B's dropped-binary denial flipped to a successful run in
  B-control purely by adding `/tmp` to the floor, and the runner's 6.17 kernel supports Landlock
  ABI ≥ 3. The spike did not need to determine the exact negotiated ABI number to prove
  feasibility.

## Section results

- **A — positive control (floor exec allowed):** PASS (on the second and third iterations, after
  the lib-dir floor fix; FAILED on the first iteration for the reason recorded above).
  `FLOOR-OK`, `NODE-OK`, `exit=0`.
- **B — floor bites (dropped `/tmp` binary denied):** PASS. The `chmod +x` payload dropped into
  `/tmp/spikestash/payload` (outside the floor) was denied.
- **B-control — differential attribution check:** PASS. The identical payload, run with `/tmp`
  added to the floor, **executed** (stdout `PWNED`, exit 0). This is the proof that section B's
  denial is Landlock-attributable — flipping purely on floor membership, not a `/tmp`-noexec
  mount artifact (confirmed independently: `/tmp` is not a separate mountpoint on this runner, it
  inherits `/`'s mount options, which include exec).
- **C — composition with the Phase 29 `/dev/null` carve-out:** PASS, but honestly re-labeled —
  this check is **mount-level (DAC)**, not Landlock-specific. `/usr/bin/curl` was masked by a
  `--ro-bind /dev/null /usr/bin/curl` bind (the pre-existing Phase 29 carve-out mechanism); it
  stayed denied under an allowed `/usr/bin` even with an active Landlock floor. The denial here
  comes from `/dev/null` having no execute bit, not from Landlock — the check demonstrates the
  two mechanisms don't conflict, not that Landlock enforced it.

## Captured denial error shape (Phase 2 classifier input)

Verbatim section-B stderr (from the authoritative run, `29091874486`):

```
=== B: the floor bites (dropped binary denied) ===
--- B stderr (CAPTURE for Phase 2 classifier) ---
/bin/sh: 1: /tmp/spikestash/payload: Permission denied
exit=126
B: dropped binary was denied (good)
```

This is a **shell-level EACCES surfaced by `/bin/sh` itself** (dash's own exec-and-report path,
since the payload was invoked via `/bin/sh -c "$STASH/payload"`), not a kernel-level message
printed directly by the Landlock helper. The wording is `Permission denied`, prefixed with the
dash line-number convention (`/bin/sh: 1: <path>: Permission denied`), and the shell's own exit
code is **126** — the standard shell convention for "found but not executable / permission
denied". The **regex** is reusable: this is the same shape Phase 29's `LINUX_EXEC_PATH` /
`firstLinuxExecLine` matcher already handles (`/bin/sh: 1: <path>: Permission denied`, exit 126).

**But Phase 2 needs classifier branch-logic changes, not just regex reuse — do not understate
this.** Phase 29's Linux exec branch only fires inside `linuxCarveMode`, which is gated on
`execAllowedPaths.length === 0` (`packages/sandbox/src/violation.ts`). Phase 2 will *populate*
`execAllowedPaths` from the Landlock floor — which flips `linuxCarveMode` to false, so a Landlock
denial's stderr line would fall through to the macOS exec branch (which matches
`OPERATION_NOT_PERMITTED`, i.e. macOS's "Operation not permitted" wording, **not** dash's
"Permission denied") and then through the quoted-path fs branch, ultimately returning `null`
(ambient) instead of `confirmed`. So Phase 2 must add a **Landlock-floor mode** to
`classifyViolation` that applies the "Permission denied"/`LINUX_EXEC_PATH` matcher *with* a
populated floor (confirm on a denied floor-outside exec), rather than reusing the existing
carve-out-only branch. Scope this in the Phase 2 spec.

## Any surprises

- **Phase 2 note (helper):** `landlock-exec` silently `continue`s past a missing `--allow` path (open() failure), unlike the `add_rule` failure path which logs. Intentional for merged-usr symlink tolerance, but Phase 2 should add a debug-only diagnostic so a typo'd floor entry isn't silent when wiring for real.

- **Static-vs-dynamic linking:** not directly tested (the payload and `/bin/sh` are both
  dynamically linked in this environment), but the lib-dir floor finding below is a direct
  consequence of dynamic linking's mmap requirements.
- **Missing floor entries (the headline surprise):** see "IMPORTANT Phase-2 finding" below — this
  is the substantive discovery of the spike and reshapes Phase 2's floor design.
- **AppArmor interaction:** the workflow disables the Ubuntu 24.04 unprivileged-userns
  restriction via `sysctl kernel.apparmor_restrict_unprivileged_userns=0` (the same mitigation
  already used by the project's existing bwrap effect-test CI job) before invoking `bwrap`; no
  further AppArmor interaction with Landlock was observed or needed.
- **`/tmp` is not a separate mount** on `ubuntu-latest` (`mount | grep ' /tmp '` and `findmnt
  /tmp` both missed — `/tmp` inherits `/`'s mount options). This matters because it rules out a
  `noexec`-mount explanation for section B's denial, which is exactly what B-control was added to
  prove empirically rather than by parsing mount flags.

## IMPORTANT Phase-2 finding: the Linux exec floor MUST include library/linker directories

`LANDLOCK_ACCESS_FS_EXECUTE` gates not just `execve()` but also `mmap(PROT_EXEC)` — loading a
dynamically-linked binary's ELF interpreter (e.g. `/lib64/ld-linux-x86-64.so.2`) and its shared
libraries also requires an execute grant on the directories they live in. The first CI run
(`29091111051`) **FAILED** precisely because the floor was mirrored from the macOS Seatbelt
`execAllowFloor` and omitted `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64` — so `/bin/sh` (dash,
dynamically linked) failed to `mmap` its own interpreter, producing
`landlock-exec: execve(/bin/sh): Permission denied`.

**This is a Linux-specific floor requirement the macOS Seatbelt floor does not have** — dylib
loading on macOS is mediated as file-read, not process-exec, under Seatbelt. Consequently:

> **Phase 2's Linux exec floor is NOT the same as the macOS floor.** It must independently
> include the dynamic-linker/library directories, or every dynamically-linked binary invocation
> (which is nearly all of them) will be denied as a false positive.

The corrected floor used for the two passing runs:

```
FLOOR=(--allow /bin --allow /usr/bin --allow /usr/sbin --allow /lib --allow /lib64 \
       --allow /usr/lib --allow /usr/lib64 --allow "$NODE_PREFIX")
```

## Decision

**GO — proceed to Phase 2.**

Feasibility is proven: Landlock exec-restriction enforces correctly inside `bwrap` on hosted
`ubuntu-latest` runners, the deny behavior is empirically Landlock-attributable (not a mount
artifact), and the denial shape is compatible with the existing Phase 29 classifier pattern.

Phase 2 gets its **own spec**, scoped to:

- Building the Landlock helper (`landlock-exec` / equivalent) from source at install time.
- Wiring it as the bwrap-inner launcher in `BubblewrapSandbox`.
- Upgrading the Phase 29 Linux `computeDenySet` branch to a real exec floor
  (`execAllowedPaths` populated) — **including the library/linker directories** found above,
  which the macOS floor construction must NOT be copied verbatim for.
- Extending `classifyViolation` to match the captured denial shape (reusing the existing Phase 29
  Linux carve-out regex path — no new pattern needed).
- A loud-advisory fallback for when Landlock or `cc` is unavailable at install time (fail
  advisory-only, never silently unenforced without a warning).
- Keeping the existing Phase 29 `/dev/null` carve-out (proven to still compose, section C).
- An ADR recording this decision, plus a doc sweep (ARCHITECTURE.md, CLAUDE.md).
- Closing #8.

**None of the above is built in this spike.** #8 stays **open** this round — the spike proves
feasibility only; it does not ship the enforcing floor.
