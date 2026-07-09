# ADR-0038: Sandbox default-deny (write slice)

Date: 2026-07-09
Status: Accepted
Supersedes: ADR-0016 (Seatbelt runner), ADR-0017 (write confinement), ADR-0018 (cross-platform backends) — the allow-default-plus-deny-list stance only.

## Context

The prior sandbox was allow-default (`(allow default)` / `--bind / /`) minus a
fixed `SENSITIVE_PATHS` deny list, so a lifecycle script could write anywhere
not explicitly enumerated — contradicting the "approved capability manifest"
model. An external audit flagged this. Phase 25 inverts the posture; it lands as
two slices (writes now, `$HOME` reads as a gated follow-up) because their risk
profiles differ sharply (see the design spec).

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

## Consequences

- Persistence/tamper writes (shell rc, LaunchAgents, systemd units, any
  non-floor path) are denied at the kernel — the whole class, not an enumerated
  list.
- **Telemetry gap (accepted, per ADR-0023):** Phase 10 `classifyViolation`
  attributes a *confirmed* write violation only for `SENSITIVE_PATHS` targets
  (the finite `deniedPaths` list). A denied write to a non-sensitive, non-floor
  path is *contained* but attributes as ambient (`null`) — containment ≥
  telemetry, same principle as a swallowed denial.
- `$HOME`-read-deny (Slice 2) is a separate follow-up; reads remain
  allow-default-minus-`SENSITIVE_PATHS` until then.
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
