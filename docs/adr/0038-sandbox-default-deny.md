# ADR-0038: Sandbox default-deny (writes + reads)

Date: 2026-07-09
Status: Accepted
Supersedes: ADR-0016 (Seatbelt runner), ADR-0017 (write confinement), ADR-0018 (cross-platform backends) — the allow-default-plus-deny-list stance, now completely inverted (both writes and `$HOME` reads).

## Context

The prior sandbox was allow-default (`(allow default)` / `--bind / /`) minus a
fixed `SENSITIVE_PATHS` deny list, so a lifecycle script could write — and
read — anywhere not explicitly enumerated, contradicting the "approved
capability manifest" model. An external audit flagged this. Phase 25 inverts
the posture in two slices because writes and `$HOME` reads have sharply
different risk profiles: Slice 1 (writes, landed first) and Slice 2
(`$HOME`-read-deny, this update) — both are now Accepted and implemented on
this branch.

## Decision (Slice 1 — writes)

Writes are **deny-by-default**. A blanket deny, then re-allow a **fixed write
floor**: the Install directory (`cwd`), the OS temp dir, `/tmp`, `/dev` (device
writes like `2>/dev/null`), and the node build caches (`~/.node-gyp`,
`~/.cache/node-gyp`, `~/.npm/_logs`). The floor is not operator-configurable —
widening it silently reopens the persistence class; per-package needs are met by
approved `filesystem:` **Grants**, which now emit positive write allows instead
of cancelling a deny. `pathCovers` is **directional**: a Grant covers exactly
its own subtree, never widening to an ancestor.

- **Seatbelt:** `(deny file-write*)` + `(allow file-write* …floor…grants)`
  (last-match-wins). Reads unchanged.
- **bwrap:** `--ro-bind / /` (read-only root) + `--bind-try` the floor/grants
  read-write. Reads unchanged.

`SENSITIVE_PATHS` is unchanged as a data table. Its write entries are emitted as
a **carve-out** re-deny *after* the floor allow (SBPL last-match-wins; bwrap
mask-after-bind), so a persistence path is denied even when it sits under an
allowed ancestor — e.g. under the floor's temp dir. That makes them load-bearing
enforcement, not merely redundant, and they still drive Phase 10 attribution and
the `secret-exfil` detection rule. A Grant covering the path lifts its carve-out.

A bare-relative approved `filesystem:` target (e.g. `.config/app`, no leading
`/` or `~/`) is resolved against `homeDir` (`expandHome` in `deny-set.ts`) when
emitted as a positive write Grant, the same as an explicit `~/`-prefixed
target — an absolute target is left unchanged.

Because a Grant now emits a *positive* write allow rather than merely
cancelling a deny, a broad or pathological operator-supplied target is broadly
writable — so grant targets are guarded (`isSafeGrantTarget` in
`deny-set.ts`, applied only to the Grant emission in both generators, never to
read-deny coverage): an empty/`*` target, a bare root `/`, or any target
containing a `..` segment is fail-closed rejected (the grant is dropped, so
the write stays denied) instead of becoming `(subpath "/")` or an
escape-the-home writable bind.

## Decision (Slice 2 — reads)

`$HOME` reads are now **deny-by-default** too. A blanket deny over `$HOME`,
then a **read-allow list** (`packages/sandbox/src/read-allow.ts`,
`readAllowList({ nodePrefix, projectRoot })`) re-opens exactly what a
lifecycle script legitimately needs to read from inside `$HOME`: the node
runtime's install prefix (`nodeInstallPrefix(execPath)` —
`dirname(dirname(execPath))`, so a node-under-`$HOME` runtime — nvm/fnm/volta
— can still load its own stdlib), the project root
(`resolveProjectRoot(cwd, INIT_CWD)` — trusts npm's `INIT_CWD` when it's
absolute, else walks up from `cwd` to the nearest ancestor `package.json`,
else falls back to `cwd`; this is what makes a lifecycle script's `require()`
resolve across the whole project tree, not just its own install directory
deep in `node_modules`), and the build caches `~/.node-gyp` and `~/.cache`.
System paths (`/usr`, `/etc`, …) stay readable via each backend's existing
allow-default / `--ro-bind / /` — Slice 2 only inverts the region *inside*
`$HOME`. Two new inputs feed the allow list: `nodePrefix` (derived from
`process.execPath`) and `projectRoot` (derived from `INIT_CWD`); `Sandbox.run`
gained an optional `projectRoot` parameter, defaulting to `cwd` when absent.

- **Seatbelt (`generateProfile`).** Three SBPL layers, in order (last-match-wins):
  1. `(deny file-read* (subpath $HOME))` — the blanket deny.
  2. `(allow file-read-metadata (subpath $HOME))` — **load-bearing**: without
     it, `require()` breaks. A blanket `file-read*` deny also denies
     `lstat`/`stat`, and node's module resolution needs to *traverse*
     (not read the contents of) every directory from `cwd` up to the
     project root to find `node_modules`/`package.json`. This was
     probe-verified during Task 1 — omitting the metadata layer produces an
     EPERM on `require()` itself, not just on unapproved file contents.
  3. `(allow file-read* …read-allow-list…)` — re-opens data reads for the
     node prefix, project root, and caches.

  The existing SENSITIVE read carve-out (`(deny file-read* /etc/passwd
  /etc/shadow …)`) is unchanged and still applies *after* this, so
  `/etc/passwd` stays denied even though `/etc` itself is read-allowed via
  `(allow default)`.
- **bwrap (`generateBwrapArgs`).** Mechanically different (bwrap has no
  metadata-vs-data read distinction), same intent:
  1. `--tmpfs $HOME` — replaces `$HOME` with an empty tmpfs, denying its
     reads (and writes, but the write floor below re-opens what's needed).
  2. Read-allow list re-bound read-only on top, `--ro-bind-try` (tolerant of
     an absent `~/.node-gyp`/`~/.cache`).
  3. The Slice 1 write floor re-bound read-write *on top of that* — order
     matters: the broad ro project bind must land before the narrow rw `cwd`
     bind, or a later ro mount would silently make `cwd` read-only again.
  4. `SENSITIVE_PATHS` masks applied last, as before.

  System paths outside `$HOME` are unaffected — the base `--ro-bind / /`
  already covers them.

**Accepted telemetry asymmetry (extends ADR-0023, confirmed by CI):** a
denied read that hits the deny surfaces differently per backend. Seatbelt's
`(deny file-read* …)` produces an `EPERM`, which `classifyViolation`
recognizes and reports as a `confirmed` runtime violation (same effect-test
pattern as the write-deny credential-read case). bwrap's `--tmpfs $HOME`
instead makes the path *not exist* from the sandboxed process's point of
view — a read of it fails `ENOENT`, which `classifyViolation` does not
classify as a violation signature. The read is still **contained** (the
sandboxed script never obtains the data) on both backends — only the
*telemetry* differs: Seatbelt reports the denial, bwrap doesn't. This is the
same containment-over-telemetry principle as the Slice 1 write carve-out and
the Phase 10 swallowed-denial case: a backend evading *reporting* never means
it evaded *enforcement*. Both backends' effect tests assert containment;
only the Seatbelt test additionally asserts the violation record.

This **completes** the supersession of ADR-0016/0017/0018's allow-default
stance: both writes (Slice 1) and `$HOME` reads (Slice 2) are now
deny-by-default on both backends.

## Consequences

- Persistence/tamper writes (shell rc, LaunchAgents, systemd units, any
  non-floor path) are denied at the kernel — the whole class, not an enumerated
  list.
- Credential/secret reads under `$HOME` outside the read-allow list (SSH
  keys, cloud credential files, arbitrary user documents) are denied at the
  kernel by default — the whole class, not an enumerated list — while the
  node runtime and the project tree stay readable so ordinary lifecycle
  scripts keep working.
- **Telemetry gap (accepted, per ADR-0023):** Phase 10 `classifyViolation`
  attributes a *confirmed* write violation only for `SENSITIVE_PATHS` targets
  (the finite `deniedPaths` list). A denied write to a non-sensitive, non-floor
  path is *contained* but attributes as ambient (`null`) — containment ≥
  telemetry, same principle as a swallowed denial. Slice 2 extends this gap
  to reads on bwrap specifically (see the telemetry asymmetry above).
- **Cross-backend `/dev` asymmetry:** `/dev` sits in the shared write floor for
  Seatbelt, which has no `--dev`-style isolated-device-tree primitive and whose
  prior allow-default posture already permitted `/dev` writes (not a
  regression here). The bwrap generator deliberately does **not** re-bind host
  `/dev` into the floor's read-write set: `--dev /dev` already gives the
  sandbox its own isolated, writable `/dev`, and binding the host `/dev` on
  top would overmount that isolation with the real host device tree
  (bwrap: later mount wins).

## Alternatives considered

- **Operator-configurable write floor** — rejected; a widenable floor is a
  footgun that reopens the persistence class. Grants are the per-package escape.
- **Keep enumerated write-deny list** — rejected; it's the exact gap the audit
  named (a novel persistence path stays writable).
- **Deny all of `$HOME` with no read-allow list** — rejected; a node-under-
  `$HOME` runtime (nvm/fnm/volta) couldn't load its own stdlib, and `require()`
  couldn't resolve the project tree, breaking ordinary benign installs.
- **Skip the `file-read-metadata` traversal layer on Seatbelt** — rejected;
  probe-verified to break `require()` itself (an EPERM on `lstat`, not just on
  file contents), which would make Slice 2 non-shippable as a default.
- **Make `--tmpfs $HOME` report like Seatbelt's EPERM** — no equivalent bwrap
  primitive exists that both denies the read and surfaces the same
  classifiable signature; accepted as the same class of gap as the Slice 1
  write telemetry asymmetry rather than blocking the slice on it.
