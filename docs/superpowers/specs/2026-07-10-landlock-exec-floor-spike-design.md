# Landlock Linux exec floor — spike-first design

**Date:** 2026-07-10
**Issue:** [#8](https://github.com/git-agentic/pkg-registry/issues/8) — the deferred Linux exec floor (the one piece that closes #8)
**Follows:** ADR-0042 (macOS exec floor), ADR-0043 (Linux carve-out + advisory floor).
**Status:** Approved design (spike phase), pre-implementation

## What this round delivers

**A throwaway CI spike, not a full implementation.** Phase 29 established that a real Linux
exec *floor* is impossible in pure TypeScript (bwrap has no `noexec`; Node has no syscall
API — [nodejs/node#51189](https://github.com/nodejs/node/issues/51189) open, and no
maintained npm Landlock package). The only route is **Landlock via a first-party compiled
helper**. The user has chosen to pursue it as a standard requirement (like bwrap itself).

But the whole endeavour hinges on one unproven fact: **does Landlock exec-restriction
actually work inside bwrap on GitHub's `ubuntu-latest` runners?** Those runners are VMs;
Landlock in a nested sandbox on hosted runners is not guaranteed (the LSM may be disabled,
or bwrap's namespacing may interfere). So this is probe-gated, exactly like Phase 29's
bwrap-noexec question was.

- **Phase 1 (THIS spec's deliverable): a CI spike** proving the whole chain end-to-end on
  CI. Green → Phase 2. Red → stop; #8 stays open, documented; one CI run spent, not a phase.
- **Phase 2 (only if the spike is green): the full implementation**, which gets its **own
  spec** informed by the spike's captured output (the real Linux exec-denial error strings,
  linking realities, ABI facts). Sketched here only for direction — not approved in detail.

### Decisions locked in during brainstorming

1. **Pursue the Landlock floor** (the user's call), as a standard requirement — but
   **spike-first**: no classifier/wiring spec until the spike is green.
2. **Delivery: build from source at install.** A self-contained C file lives in the repo
   (source-auditable, nothing opaque vendored); a Linux build step compiles it with the
   system `cc`. Rejected: shipping prebuilt per-arch binaries (an opaque binary inside a
   supply-chain-security tool + arch matrix + signing pipeline — worst fit for the repo's
   identity).
3. **Fallback (parallel to Phase 29's settled posture): loud advisory, proceed.** When
   Landlock is unavailable (old kernel / ABI < 1 / LSM disabled) or `cc` is absent (helper
   can't build), fall back to Phase 29's carve-out + advisory floor and run the script
   confined — never silent, never fail-closed-refuse (that would regress availability).
4. **The Phase 29 `/dev/null` carve-out stays.** Landlock is allow-list-only and cannot
   deny a literal (curl) under an allowed parent (`/usr/bin`), so the carve-out masks remain
   the mechanism for the exfil tools. Landlock adds the *floor*; the two compose to full
   macOS parity.

## The helper (`landlock-exec`)

A self-contained C file (~150 lines) in the repo — proposed
`packages/sandbox/native/landlock-exec.c`. It **inlines the Landlock uapi constants and
structs** (`struct landlock_ruleset_attr`, `struct landlock_path_beneath_attr`, the
`LANDLOCK_ACCESS_FS_EXECUTE` bit, and the three syscall numbers) so it needs **no kernel
headers** — only `cc` and libc's `syscall()`. Built from source on Linux install into
e.g. `packages/sandbox/dist/landlock-exec`.

Invoked as the innermost command inside bwrap:

```
bwrap … /…/landlock-exec --allow /bin --allow /usr/bin --allow <nodePrefix> \
        --allow <projectRoot> --allow /opt/homebrew … -- /bin/sh -c <script>
```

Sequence:

1. `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` — makes `landlock_restrict_self` work
   unprivileged (no `CAP_SYS_ADMIN`). bwrap already sets `no_new_privs`; this is
   belt-and-suspenders and keeps the helper correct if invoked outside bwrap.
2. `landlock_create_ruleset(&attr, sizeof(attr), 0)` → fd. `attr.handled_access_fs =
   LANDLOCK_ACCESS_FS_EXECUTE` (ABI v1). If `landlock_create_ruleset(NULL, 0,
   LANDLOCK_CREATE_RULESET_VERSION)` reports ABI < 1 or `ENOSYS`/`EOPNOTSUPP`, the helper
   exits with a distinct code so the caller can invoke the loud-advisory fallback.
3. For each `--allow <path>`: open the path `O_PATH|O_CLOEXEC`,
   `landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &{allowed_access:
   LANDLOCK_ACCESS_FS_EXECUTE, parent_fd}, 0)`.
4. `landlock_restrict_self(fd, 0)` — applies to the calling thread; inherited across
   `execve` and by all children (verified: the restriction "will restrict the thread and
   its future children for their entire life").
5. `execve("/bin/sh", ["/bin/sh", "-c", script, NULL], environ)`.

The `--allow` floor is the **same `execAllowFloor`** (`packages/sandbox/src/exec-floor.ts`)
Phase 28 uses on macOS — the caller passes its entries as `--allow` args. Reads/writes are
untouched by the helper (bwrap already handles those, Phase 25); the helper adds *only* the
exec-allow ruleset.

## The spike

A throwaway Linux-CI-only artifact (a temporary workflow step or a `describe`-gated test
that runs only on `ubuntu-latest`), compiling the helper with `cc` and asserting **inside
bwrap on the runner**:

1. **Positive control:** exec from the floor succeeds — `/bin/echo`, a `node_modules/.bin`
   shim, and `node` all run under `landlock-exec` with the floor allow-list.
2. **The floor bites:** a binary written into `/tmp` (or `$TMPDIR`) and `chmod +x`'d is
   **denied** exec (the headline dropped-binary threat).
3. **Composition:** a `/dev/null`-masked `curl` under an *allowed* `/usr/bin` stays denied
   — confirming Landlock's floor allow doesn't lift the Phase 29 carve-out.
4. **Capture (drives Phase 2):** the **exact stderr shape** of a Landlock exec denial (the
   shell's message + errno — likely `EACCES`, but the precise `dash` wording is what the
   Phase 2 classifier regexes need), and the helper's own diagnostics.
5. **Environment facts:** `cc` present on the runner? Landlock ABI ≥ 1 actually enabled in
   the nested bwrap context? static vs dynamic linking constraints?

**Hard gate:** all of 1–3 green (and Landlock genuinely available inside bwrap) → Phase 2.
Any of: Landlock unavailable in the nested sandbox, the floor doesn't bite, or the helper
can't build/run on the runner → **stop**, record the finding, keep #8 open. Do not fake a
floor.

The spike is throwaway — its assertions become the Phase 2 effect tests, but the spike
itself is not the shippable artifact; it exists to de-risk the compile-and-nest chain
before any product code.

## Phase 2 outline (contingent — its own spec after a green spike)

Sketched for direction only:

- **Build:** compile `landlock-exec.c` from source at install on Linux (a build step /
  guarded postinstall), into the sandbox package's `dist/`. `cc`-absent ⇒ no helper ⇒
  fallback.
- **Wiring:** `BubblewrapSandbox` prepends `landlock-exec --allow <floor> --` before
  `/bin/sh -c <cmd>` when the helper exists and Landlock is available; otherwise the
  Phase 29 path (carve-out + advisory floor) unchanged.
- **Deny-set upgrade:** the Phase 29 Linux `computeDenySet` branch gains a **real floor** —
  populate `execAllowedPaths` (from `execAllowFloor`) when the Landlock helper is active, so
  `classifyViolation`'s existing floor logic attributes a denied dropped-binary exec as
  `confirmed` (the Phase 29 "no floor, never suspected" guard is relaxed *only* in
  Landlock-active mode).
- **Classifier:** a Landlock exec-denial shape (from the spike capture) → `confirmed`
  process violation on the floor, mirroring macOS.
- **Fallback:** Landlock/`cc` unavailable ⇒ loud-advisory Phase 29 floor (never silent).
- **Carve-out:** unchanged (still masks the exfil tools).
- **Docs + #8:** a new ADR (Landlock exec floor; from-source helper; fallback; the ABI/nest
  facts); ARCHITECTURE/threat-model/README/CLAUDE updated to "Linux exec floor enforced
  where Landlock is available, advisory otherwise"; **close #8** (cross-platform floor
  achieved, with the documented Landlock-availability caveat).

## Testing (spike phase)

- The spike's three assertions run on `ubuntu-latest` CI (they cannot run on the macOS dev
  host — Landlock is Linux-only). Benign probes only; no synthetic malware executed.
- The helper's C is small enough to eyeball; its correctness is proven by the spike's
  effect assertions (floor bites / floor allows), not by unit-testing C.
- No change to any shipped code path this round — the spike is throwaway.

## Rejected / deferred alternatives

- **Prebuilt per-arch binaries** — opaque binary in a supply-chain tool; arch matrix;
  signing pipeline. Rejected in favour of from-source.
- **N-API / node-gyp addon** — the helper is a spawned subprocess, not loaded into Node;
  an addon is strictly more complex for no benefit. Rejected.
- **External Landlock CLI dependency** (landrun / kernel `sandboxer`) — unlike bwrap, no
  such tool is packaged in distro repos, so "just install it" has no clean story. Rejected.
- **Fail-closed refusal when Landlock is unavailable** — an availability regression vs.
  today's Linux (Phase 29 runs scripts with an advisory floor). Rejected; loud-advisory
  fallback instead.
- **Skipping the spike / speccing Phase 2 now** — the nested-bwrap-on-hosted-runners
  Landlock availability is genuinely unknown and premise-killing; speccing the classifier
  against unconfirmed error shapes repeats a mistake Phase 29's probe caught. Rejected.
