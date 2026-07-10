# Landlock Linux exec floor — Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove — on `ubuntu-latest` CI, inside bwrap — that a small from-source C helper can apply a Landlock exec-allow ruleset that denies exec of a dropped binary while allowing the floor, and capture the exact denial error shape + environment facts that a future Phase 2 needs. This is a throwaway feasibility spike, not shippable enforcement.

**Architecture:** A self-contained C helper (`landlock-exec.c`, inline Landlock uapi constants, three syscalls via `syscall()` + `execve`) is compiled with `cc` in a dedicated throwaway GitHub workflow and driven by a bash harness that runs the assertions inside bwrap on the runner. The dev host is macOS, so **all verification is on CI** (Landlock is Linux-only) — the loop is push → read `gh` logs → interpret.

**Tech Stack:** C (libc `syscall()`, no kernel headers), bash, GitHub Actions (`ubuntu-latest`), bwrap, `gh` CLI.

**Spec:** `docs/superpowers/specs/2026-07-10-landlock-exec-floor-spike-design.md`

## Global Constraints

- **This is a spike.** The deliverable is a go/no-go finding + captured facts, not shipped code. Nothing here alters any existing runtime path or the main test suite.
- **CI-only verification.** Landlock is Linux-only; it cannot run on the macOS dev host. The C helper won't even compile on macOS (Linux syscalls). Do NOT try to build/run it locally — push and read CI.
- **Fail loud, never silent.** The spike harness must print an unambiguous `SPIKE-RESULT:` verdict line and exit non-zero on any failure (helper won't compile, Landlock unavailable, floor doesn't bite, or floor over-blocks). A red job is an informative outcome, not a bug to paper over.
- **Actions are SHA-pinned** (repo convention, Phase 27). Reuse the exact pins from `.github/workflows/ci.yml`: `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4`.
- The spike lives on branch `landlock-spike-spec` (the spec is already committed there). Do NOT merge to main.
- Commit messages end with the `Claude-Session:` trailer used in recent commits.
- Landlock facts (verified during brainstorming): ABI v1 (kernel ≥ 5.13) has `LANDLOCK_ACCESS_FS_EXECUTE`; the restriction is inherited across `execve` and by children; it works unprivileged once `PR_SET_NO_NEW_PRIVS` is set (bwrap already sets it). Syscall numbers `landlock_create_ruleset`=444, `landlock_add_rule`=445, `landlock_restrict_self`=446 (same on x86_64 and aarch64).

---

### Task 1: The `landlock-exec` C helper

**Files:**
- Create: `packages/sandbox/native/landlock-exec.c`

**Interfaces:**
- Produces: a binary invoked as `landlock-exec --allow <path> [--allow <path> …] -- <cmd> [args…]`. Sets no_new_privs, builds a Landlock ruleset granting `LANDLOCK_ACCESS_FS_EXECUTE` beneath each `--allow` path, applies it, then `execve`s the command after `--`. Exit codes: `3` = Landlock unavailable (ABI < 1 / ENOSYS / EOPNOTSUPP — the fallback signal), `4` = create_ruleset failed, `5` = restrict_self failed, `2` = usage error, `127` = execve failed. Task 2's harness relies on these.

- [ ] **Step 1: Write the helper**

Create `packages/sandbox/native/landlock-exec.c` with exactly this content:

```c
/*
 * landlock-exec: apply a Landlock exec-allow floor, then exec the given command.
 * Invoked as the innermost command inside bwrap:
 *   landlock-exec --allow /bin --allow /usr/bin ... -- /bin/sh -c <script>
 * Grants LANDLOCK_ACCESS_FS_EXECUTE beneath each --allow path; exec of anything
 * outside the floor is then kernel-denied. Restriction is inherited across execve.
 * Self-contained: inlines the Landlock uapi so it needs no kernel headers.
 * SPIKE ARTIFACT (Phase 1). Linux-only; does not compile on macOS.
 */
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_RULE_PATH_BENEATH 1
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)

/* ABI v1 ruleset attr: just the fs-access mask. Passing size=8 is accepted on all
 * ABIs (newer kernels zero-fill the rest). */
struct ll_ruleset_attr { unsigned long long handled_access_fs; };
/* Exact 12-byte layout the kernel expects: u64 + s32, no padding. */
struct ll_path_beneath_attr { unsigned long long allowed_access; int parent_fd; } __attribute__((packed));

extern char **environ;

static long ll_create(const void *attr, unsigned long size, unsigned int flags) {
  return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
static long ll_add(int fd, unsigned int type, const void *attr, unsigned int flags) {
  return syscall(__NR_landlock_add_rule, fd, type, attr, flags);
}
static long ll_restrict(int fd, unsigned int flags) {
  return syscall(__NR_landlock_restrict_self, fd, flags);
}

int main(int argc, char **argv) {
  /* Parse: --allow <path> ... -- <cmd> [args...] */
  const char *allows[256];
  int nallow = 0;
  int i = 1;
  for (; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) { i++; break; }
    if (strcmp(argv[i], "--allow") == 0 && i + 1 < argc) {
      if (nallow < 256) allows[nallow++] = argv[++i];
      else { fprintf(stderr, "landlock-exec: too many --allow entries\n"); return 2; }
    } else {
      fprintf(stderr, "landlock-exec: unexpected arg '%s'\n", argv[i]);
      return 2;
    }
  }
  if (i >= argc) { fprintf(stderr, "landlock-exec: no command after --\n"); return 2; }
  char **cmd = &argv[i];

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("landlock-exec: prctl(NO_NEW_PRIVS)"); return 2; }

  long abi = ll_create(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 1) {
    fprintf(stderr, "landlock-exec: Landlock unavailable (abi=%ld errno=%d %s)\n",
            abi, errno, strerror(errno));
    return 3; /* fallback signal */
  }

  struct ll_ruleset_attr rattr;
  rattr.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE;
  int rfd = (int)ll_create(&rattr, sizeof(rattr), 0);
  if (rfd < 0) { perror("landlock-exec: create_ruleset"); return 4; }

  for (int a = 0; a < nallow; a++) {
    int pfd = open(allows[a], O_PATH | O_CLOEXEC);
    if (pfd < 0) continue; /* a missing floor entry is simply not granted */
    struct ll_path_beneath_attr pb;
    pb.allowed_access = LANDLOCK_ACCESS_FS_EXECUTE;
    pb.parent_fd = pfd;
    if (ll_add(rfd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0)
      fprintf(stderr, "landlock-exec: add_rule(%s) failed: %s\n", allows[a], strerror(errno));
    close(pfd);
  }

  if (ll_restrict(rfd, 0)) { perror("landlock-exec: restrict_self"); return 5; }
  close(rfd);

  execve(cmd[0], cmd, environ);
  fprintf(stderr, "landlock-exec: execve(%s): %s\n", cmd[0], strerror(errno));
  return 127;
}
```

- [ ] **Step 2: Eyeball-check (no local compile — it won't build on macOS)**

Confirm by reading: (a) the three syscall numbers are guarded with `#ifndef`; (b) `ll_path_beneath_attr` is `__attribute__((packed))`; (c) the ABI check returns `3` on `abi < 1`; (d) parsing stops at `--` and execs the rest; (e) a missing `--allow` path is skipped, not fatal. Do NOT run `cc` locally (macOS clang will fail on the Linux syscalls — that's expected; CI compiles it).

- [ ] **Step 3: Commit**

```bash
git add packages/sandbox/native/landlock-exec.c
git commit -m "spike(sandbox): landlock-exec helper — Landlock exec-allow floor + execve (Phase 1 spike)"
```

---

### Task 2: Spike harness + throwaway CI workflow

**Files:**
- Create: `spike/landlock-spike.sh`
- Create: `.github/workflows/landlock-spike.yml`

**Interfaces:**
- Consumes: `packages/sandbox/native/landlock-exec.c` (Task 1), exit code `3` = Landlock-unavailable.
- Produces: a CI job that prints a `SPIKE-RESULT:` verdict and the captured denial error shape; Task 3 reads its logs.

- [ ] **Step 1: Write the harness script**

Create `spike/landlock-spike.sh` with exactly this content:

```bash
#!/usr/bin/env bash
# Landlock-in-bwrap feasibility spike. Runs ONLY in CI (ubuntu-latest). Prints a
# SPIKE-RESULT verdict and captures the denial error shape for Phase 2. Throwaway.
set -uo pipefail

HELPER=/tmp/landlock-exec
NODE_PREFIX="$(dirname "$(dirname "$(command -v node)")")"
echo "=== env ==="
echo "cc: $(command -v cc || echo MISSING)"; cc --version 2>&1 | head -1 || true
echo "bwrap: $(command -v bwrap || echo MISSING)"; bwrap --version 2>&1 || true
echo "kernel: $(uname -r)"
echo "node prefix: $NODE_PREFIX"

echo "=== compile helper ==="
if ! cc -O2 -o "$HELPER" packages/sandbox/native/landlock-exec.c; then
  echo "SPIKE-RESULT: FAIL (helper did not compile)"; exit 10
fi
echo "compiled OK: $HELPER"

# A minimal bwrap wrapper mirroring how BubblewrapSandbox invokes bwrap (ro root,
# dev, proc, no network), running the helper as the innermost command.
run_bwrap() { # args: extra-bwrap-args... -- helper-and-cmd...
  bwrap --ro-bind / / --dev /dev --proc /proc --unshare-net "$@"
}
FLOOR=(--allow /bin --allow /usr/bin --allow /usr/sbin --allow "$NODE_PREFIX")

echo "=== A: positive control (floor exec allowed) ==="
A_OUT="$(run_bwrap "$HELPER" "${FLOOR[@]}" -- /bin/sh -c '/bin/echo FLOOR-OK; node -e "console.log(\"NODE-OK\")"' 2>&1)"
A_RC=$?
echo "$A_OUT"; echo "exit=$A_RC"
if [ $A_RC -ne 0 ] || ! echo "$A_OUT" | grep -q FLOOR-OK || ! echo "$A_OUT" | grep -q NODE-OK; then
  # Distinguish Landlock-unavailable (exit 3) from a real floor-allow failure.
  if echo "$A_OUT" | grep -q "Landlock unavailable"; then
    echo "SPIKE-RESULT: LANDLOCK-UNAVAILABLE (abi<1 inside bwrap on this runner)"; exit 3
  fi
  echo "SPIKE-RESULT: FAIL (floor exec was blocked — over-restrictive)"; exit 11
fi

echo "=== B: the floor bites (dropped binary denied) ==="
# Write a payload OUTSIDE the floor (/tmp is not in FLOOR), make it executable, try to exec it.
STASH=/tmp/spikestash; mkdir -p "$STASH"
printf '#!/bin/sh\necho PWNED\n' > "$STASH/payload"; chmod +x "$STASH/payload"
B_OUT="$(run_bwrap "$HELPER" "${FLOOR[@]}" -- /bin/sh -c "$STASH/payload" 2>&1)"
B_RC=$?
echo "--- B stderr (CAPTURE for Phase 2 classifier) ---"; echo "$B_OUT"; echo "exit=$B_RC"
if echo "$B_OUT" | grep -q PWNED; then
  echo "SPIKE-RESULT: FAIL (dropped binary EXECUTED — floor does not bite)"; exit 12
fi
echo "B: dropped binary was denied (good)"

echo "=== C: composition with the Phase 29 /dev/null carve-out ==="
# Landlock allows /usr/bin, but a /dev/null mask over curl must still deny it.
if [ -x /usr/bin/curl ]; then
  C_OUT="$(run_bwrap --ro-bind /dev/null /usr/bin/curl "$HELPER" "${FLOOR[@]}" -- /bin/sh -c '/usr/bin/curl --version' 2>&1)"
  C_RC=$?
  echo "--- C stderr ---"; echo "$C_OUT"; echo "exit=$C_RC"
  if echo "$C_OUT" | grep -qi "curl [0-9]"; then
    echo "SPIKE-RESULT: FAIL (masked curl ran despite /dev/null — carve-out defeated)"; exit 13
  fi
  echo "C: masked curl stayed denied under an allowed /usr/bin (good)"
else
  echo "C: curl not present, skipping composition check"
fi

echo "SPIKE-RESULT: PASS (Landlock exec floor works inside bwrap; floor allows, dropped-binary denied, carve-out intact)"
exit 0
```

- [ ] **Step 2: Write the throwaway workflow**

Create `.github/workflows/landlock-spike.yml` with exactly this content:

```yaml
name: landlock-spike
on:
  push:
    branches: [landlock-spike-spec]
  workflow_dispatch:
jobs:
  spike:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
        with:
          node-version: "24"
      - run: sudo apt-get update && sudo apt-get install -y bubblewrap
      - run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 || true
      - run: bash spike/landlock-spike.sh
```

- [ ] **Step 3: Make the script executable and commit**

```bash
chmod +x spike/landlock-spike.sh
git add spike/landlock-spike.sh .github/workflows/landlock-spike.yml
git commit -m "spike(sandbox): CI harness — compile landlock-exec + assert floor-bites inside bwrap (Phase 1 spike)"
```

- [ ] **Step 4: Push and trigger the spike on CI**

```bash
git push -u origin landlock-spike-spec
```

The `landlock-spike` workflow triggers on push to this branch. Watch it:

```bash
RID=$(gh run list --repo git-agentic/pkg-registry --workflow landlock-spike --branch landlock-spike-spec --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch --repo git-agentic/pkg-registry "$RID" --exit-status || true
```

- [ ] **Step 5: Capture the raw job log**

```bash
gh run view --repo git-agentic/pkg-registry "$RID" --log > /tmp/landlock-spike.log 2>&1 || \
  gh run view --repo git-agentic/pkg-registry "$RID" --log-failed > /tmp/landlock-spike.log 2>&1
grep -nE "SPIKE-RESULT|B stderr|exit=|abi=|cc:|kernel:|Landlock" /tmp/landlock-spike.log
```

If the workflow doesn't appear (e.g. workflow file only takes effect after it exists on the branch), re-run via `gh workflow run landlock-spike.yml --repo git-agentic/pkg-registry --ref landlock-spike-spec` and re-watch. If CI is stuck > ~15 min, stop and report the run URL rather than looping.

---

### Task 3: Findings, decision, and #8 disposition

**Files:**
- Create: `docs/superpowers/specs/2026-07-10-landlock-spike-findings.md`

**Interfaces:** none (a findings record + a decision).

- [ ] **Step 1: Write the findings record**

Create `docs/superpowers/specs/2026-07-10-landlock-spike-findings.md` capturing, from the CI log:
- The `SPIKE-RESULT:` verdict (PASS / LANDLOCK-UNAVAILABLE / FAIL-<reason>).
- The captured **denial error shape** from section B's stderr (verbatim — this is what a Phase 2 classifier regex would match; note the errno/wording, e.g. `EACCES` / "Permission denied" / dash line-number prefix).
- Environment facts: `cc` version, `bwrap --version`, `uname -r`, whether the Landlock ABI was ≥ 1 inside bwrap.
- Any surprises (static-vs-dynamic linking, missing floor entries, AppArmor interaction).

Template — fill each field from the log, no placeholders left:

```markdown
# Landlock exec-floor spike — findings (2026-07-10)

**Verdict:** <PASS | LANDLOCK-UNAVAILABLE | FAIL-reason>  (CI run: <url>)

## Environment (ubuntu-latest runner)
- cc: <version>   bwrap: <version>   kernel: <uname -r>
- Landlock ABI inside bwrap: <n or "unavailable">

## Section results
- A positive control (floor exec allowed): <PASS/FAIL + notes>
- B floor bites (dropped /tmp binary denied): <PASS/FAIL>
- C composition (masked curl stays denied under allowed /usr/bin): <PASS/FAIL/skipped>

## Captured denial error shape (Phase 2 classifier input)
```
<verbatim section-B stderr>
```

## Decision
<If PASS: proceed to Phase 2 — write the implementation spec (helper build-at-install,
BubblewrapSandbox wiring, computeDenySet floor upgrade, classifier against the captured
shape, loud-advisory fallback, ADR, docs, close #8).
If LANDLOCK-UNAVAILABLE/FAIL: stop — Landlock-in-bwrap doesn't work on hosted runners
(or the floor doesn't bite); keep #8 open with this finding; note whether self-hosted or
a different nesting approach could change it.>
```

- [ ] **Step 2: Commit the findings**

```bash
git add docs/superpowers/specs/2026-07-10-landlock-spike-findings.md
git commit -m "spike(sandbox): Landlock-in-bwrap feasibility findings + go/no-go (Phase 1 spike)"
```

- [ ] **Step 3: Comment on #8 with the spike outcome**

```bash
gh issue comment 8 --repo git-agentic/pkg-registry --body "<one paragraph: the spike verdict, whether Landlock exec-restriction works inside bwrap on ubuntu-latest, and the go/no-go — link the spike-findings doc. If PASS: Phase 2 (the shippable Landlock floor) is next and will close #8. If not: #8 stays open with the documented reason.>"
```

(#8 stays open either way this round — the spike is feasibility, not the shipped floor.)

---

## Verification checklist (Definition of Done for the spike)

- [ ] The `landlock-spike` CI job ran on `ubuntu-latest` and produced a clear `SPIKE-RESULT:` verdict
- [ ] The section-B denial error shape is captured verbatim in the findings doc
- [ ] Environment facts (cc, bwrap, kernel, ABI-inside-bwrap) recorded
- [ ] A go/no-go decision is written, and #8 is commented (still open)
- [ ] No shipped runtime path or the main test suite was touched (the spike workflow/script/helper are additive and throwaway; the main `ci.yml` is unchanged)

## Not in scope (Phase 2 — only if the spike is green)

The shippable floor gets its **own spec**: building the helper from source at install; wiring it as the bwrap-inner launcher in `BubblewrapSandbox`; upgrading the Phase 29 Linux `computeDenySet` branch to a real floor (`execAllowedPaths` populated) + `classifyViolation` against the captured denial shape; the loud-advisory fallback when Landlock/`cc` is unavailable; keeping the Phase 29 carve-out; the ADR and doc sweep; and closing #8. None of that is built in this spike.
