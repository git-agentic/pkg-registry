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
echo "/tmp mount opts: $(mount | grep ' /tmp ' || findmnt /tmp || echo UNKNOWN)"

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
# Landlock's FS_EXECUTE right gates not just execve() but also mmap(PROT_EXEC) —
# so loading a dynamically-linked binary's ELF interpreter (e.g.
# /lib64/ld-linux-x86-64.so.2) and its shared libraries ALSO requires an execute
# grant on the directory they live in. /bin/sh (dash) is dynamically linked, so
# without the lib/linker dirs in the floor, execve succeeds past the initial check
# but the interpreter mmap fails, surfacing as EACCES. This is a Linux-specific
# floor requirement the macOS Seatbelt floor doesn't have (Seatbelt doesn't gate
# library mmap the same way). Some of these are merged-usr symlinks (e.g. /lib ->
# usr/lib); the helper opens each with O_PATH which follows symlinks, and a
# missing one is silently skipped — harmless to list all four unconditionally.
FLOOR=(--allow /bin --allow /usr/bin --allow /usr/sbin --allow /lib --allow /lib64 --allow /usr/lib --allow /usr/lib64 --allow "$NODE_PREFIX")

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

echo "=== B-control: same payload, but /tmp ADDED to the floor (proves attribution) ==="
# If adding /tmp to the floor makes the payload RUN, the section-B denial was
# Landlock-attributable (lifting the floor lifted the denial). If it's STILL
# denied even with /tmp in the floor, /tmp is noexec (or another confound) and
# section B proves nothing about Landlock.
BC_OUT="$(run_bwrap "$HELPER" "${FLOOR[@]}" --allow /tmp -- /bin/sh -c "$STASH/payload" 2>&1)"
BC_RC=$?
echo "--- B-control stderr (CAPTURE verbatim) ---"; echo "$BC_OUT"; echo "exit=$BC_RC (informational; PWNED presence is the authoritative 'it ran' signal)"
if ! echo "$BC_OUT" | grep -q PWNED; then
  echo "SPIKE-RESULT: INCONCLUSIVE (/tmp appears noexec — section B denial not Landlock-attributable; check mount opts)"
  exit 14
fi
echo "B-control: payload RAN with /tmp in the floor (good — confirms section B's denial was Landlock-attributable)"

echo "=== C: composition with the Phase 29 /dev/null carve-out (mount-level, NOT Landlock) ==="
# NOTE: this denies curl via DAC — a non-executable /dev/null char device masks
# the real binary — not via Landlock. It confirms the Phase 29 mount-mask still
# composes with an active Landlock floor; it is NOT a Landlock-specific property.
C_RAN=0
if [ -x /usr/bin/curl ]; then
  C_RAN=1
  C_OUT="$(run_bwrap --ro-bind /dev/null /usr/bin/curl "$HELPER" "${FLOOR[@]}" -- /bin/sh -c '/usr/bin/curl --version' 2>&1)"
  C_RC=$?
  echo "--- C stderr ---"; echo "$C_OUT"; echo "exit=$C_RC"
  if echo "$C_OUT" | grep -qi "curl [0-9]"; then
    echo "SPIKE-RESULT: FAIL (masked curl ran despite /dev/null — carve-out defeated)"; exit 13
  fi
  echo "C: Phase 29 /dev/null carve-out still denies curl with the Landlock floor active (mount-level, composes)"
else
  echo "C: curl not present, skipping composition check"
fi

if [ $C_RAN -eq 1 ]; then
  echo "SPIKE-RESULT: PASS (Landlock exec floor works inside bwrap: A+B/B-control prove floor-allow + dropped-binary-denied are Landlock-attributable; C confirms the pre-existing Phase 29 /dev/null carve-out still composes with an active Landlock floor, a mount-level property, not a Landlock-specific one)"
else
  echo "SPIKE-RESULT: PASS (Landlock exec floor works inside bwrap: A+B/B-control prove floor-allow + dropped-binary-denied are Landlock-attributable; C skipped — curl absent)"
fi
exit 0
