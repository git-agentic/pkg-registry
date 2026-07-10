# Design: fix #28 — a `process:` path grant under `$HOME` can never exec on Linux (`--tmpfs $HOME` hides it before Landlock is consulted)

**Date:** 2026-07-10
**Issue:** [#28](https://github.com/git-agentic/pkg-registry/issues/28) (found while fixing #25; predicted by that spec's "Out of scope" note)
**Scope:** `packages/sandbox` only — `bwrap.ts`, `deny-set.ts`, and their tests.
Fail-closed direction today (over-blocks; no exec escape). No scoring, policy,
or approval-model changes (invariants #1–#7 untouched). Also folds in the two
same-seam items from the #25 final whole-branch review (issue #28's comment):
the bare-`~` grant guard and the `~`-form deny-set test's runtime-visibility
comment.

## The bug

On Linux, a `process:` path grant under `$HOME` (e.g. `process:~/tools/bin/x`)
is correctly appended to the Landlock `--allow` set since #25
(`landlockAllowPaths`), but `generateBwrapArgs` (`packages/sandbox/src/bwrap.ts`)
mounts `--tmpfs $HOME` (Phase 25 Slice 2, ADR-0038), which empties `$HOME`
before the helper runs. The exec fails **ENOENT** — the file isn't visible
inside the sandbox — so Landlock is never consulted. A filesystem-visibility
gap, not an exec-floor gap. `filesystem:` grants under `$HOME` already re-bind
after the tmpfs; `process:` path grants never do.

## The fix

### 1. Visibility (`bwrap.ts`)

Hoist the existing `process:`-target computation
(`procTargets`/`grantedCmds`/`execWildcard`/`execPathGrants`, today computed
just before the carve-out mask loop) above the Slice 2 `ro` list. Extend the
`ro` list with:

```ts
...execPathGrants.filter((p) => p.startsWith(home + "/"))
```

— safe, expanded `process:` path grants **strictly under** `$HOME` — so they
are `--ro-bind-try`'d back into the fresh tmpfs alongside the read-allow
re-binds (step 3), before the rw binds (step 4).

- **Read-only is sufficient.** bwrap has no noexec (ADR-0043); exec
  permission is Landlock's job. On a Landlock-active host the grant is
  already in `--allow` (#25); on an advisory host the visible file simply
  execs.
- **Strictly-under filtering** keeps the argv byte-identical for every
  configuration without an under-home path grant, and prevents re-binding
  `$HOME` itself or an ancestor (which would nullify the tmpfs) — including an
  absolute grant target literally equal to `homeDir`, which the syntactic
  guard below cannot see (with the §2 guard rejecting the `.`/empty-segment
  shapes that would normalize back to it).
- Grants **outside** `$HOME` (e.g. `/opt/vendor/bin/tool`) get no re-bind —
  they're already visible through the `--ro-bind / /` root.
- The `execWildcard` check keeps wrapping only the mask loop — a path grant
  re-binds regardless of a co-present `*` grant (wildcard lifts the
  carve-out; it opens no paths).
- A grant target that duplicates a read-allow entry produces a redundant
  `--ro-bind-try` — harmless (later identical bind overmounts identically).

### 2. Guard (`deny-set.ts`)

`isSafeGrantTarget` rejects `~` and `~/` syntactically:

```ts
export function isSafeGrantTarget(target: string): boolean {
  if (!target || target === "*" || target === "/") return false;
  if (target === "~" || target === "~/") return false; // expands to all of $HOME (#28)
  // A `.` or empty (non-leading) segment lets the path normalize back to an
  // ancestor at mount/rule time (e.g. `~//`, `~/.`, `/home/x/` → $HOME itself),
  // defeating every strictly-under check downstream (#28) — reject fail-closed,
  // same class as `..`.
  const segs = target.split("/");
  return !segs.some((s, i) => s === ".." || s === "." || (s === "" && i > 0));
}
```

It rejected `/` as "everything" but accepted bare `~`, which `expandHome`
turns into all of `$HOME` — including the writable write-floor entries under
home — re-opening nearly as much as the rejected `/`. This becomes practical
exactly when fix (1) makes `~`-form grants live on Linux for the first time.
One line, no signature change, and it applies at every existing call site for
free: darwin Seatbelt (`profile.ts` write + exec grants), `landlockAllowPaths`,
both `computeDenySet` branches, `bwrap.ts` rw grants, and the new re-bind —
so the generator/classifier non-drift property holds with no further work.

**Behavior change to note:** a bare-`~` grant now silently drops to deny on
**both** platforms (previously it opened nearly-all-of-`$HOME` on darwin,
Phase 28 semantics). Fail-closed direction; operator-gated either way. A
literal absolute path equal to `homeDir` (e.g. `filesystem:/home/user`) still
passes the syntactic guard — maximally explicit operator intent, and the
strictly-under filter in (1) keeps even that from nullifying the tmpfs.

Follow-up hardening from the final whole-branch review: a "." or non-leading
empty segment (trailing slash, //) is rejected too — such a target normalizes
back to an ancestor at mount/rule time (e.g. ~// → $HOME itself), defeating
the strictly-under filter; this also closes the pre-existing filesystem:~//
rw variant of the same class.

### 3. No classifier change

`computeDenySet`/`classifyViolation` need zero changes: visibility isn't
classified. Before the fix the tmpfs ENOENT carried no perm signature and
degraded safely to unclassified; after the fix a granted path execs and no
denial occurs. The `~`-guard flows into both `computeDenySet` branches through
the shared predicate, keeping them mirror-exact with the generators.

## Tests

Hermetic, platform-neutral:

- `deny-set.test.ts` (or the existing `isSafeGrantTarget` home) —
  - `isSafeGrantTarget` rejects `~` and `~/`; still accepts `~/x`.
  - `landlockAllowPaths` drops a bare-`~` grant (floor-only result).
  - The existing "a ~-form path grant expands against homeDir" test keeps its
    `~/…`-form target; its caveat comment flips to
    `// runtime visibility: fixed by #28 — see the bubblewrap effect test`.
- `generateBwrapArgs` tests —
  - a `process:~/tools/bin/x` grant emits `--ro-bind-try <home>/tools/bin/x`
    **after** `--tmpfs <home>` (order asserted).
  - a `process:` path grant outside `$HOME` emits no new ro-bind (argv
    unchanged vs. the no-grant baseline apart from existing carve-out-lift
    behavior).
  - a bare-`~` grant (both `filesystem:` and `process:`) emits nothing: no rw
    bind, no ro-bind.
  - an absolute `process:` grant equal to `homeDir` does not re-bind home
    (strictly-under filter).
- `profile.ts` (darwin generator) — bare `~` no longer emits a
  `(subpath $HOME)` allow (write or exec).

Linux CI-only effect tests (inside `bubblewrap.test.ts`'s existing
describe-skip-on-darwin `BubblewrapSandbox enforcement` block, same
built-helper gating as the Phase 2 Landlock effect tests):

- Copy a real binary (e.g. `/usr/bin/env`) to `<fakeHome>/tools/bin/x`; with
  `--approve process:~/tools/bin/x` it execs (exit 0, no violation) — the
  regression test for this bug.
- The same exec **without** the grant stays contained: non-zero exit,
  **containment-only** assertion — the tmpfs ENOENT carries no perm
  signature, so no violation classification is asserted (the accepted
  ADR-0038/ADR-0023 telemetry asymmetry).

## Docs

No new ADR and no ADR edits: like #25, this makes ADR-0038/0044's documented
grant semantics actually true — a reversal of nothing. Update CLAUDE.md's
test-notes line. Close #28 on merge.

## Out of scope

- Any parent-directory or sibling-file re-expose: the bind is the grant
  target exactly (least privilege). An operator whose tool needs adjacent
  files grants the directory instead — grants are subtree-covering already.
- Landlock `--allow` handling — done in #25; unchanged here.
- The Phase 29 `/dev/null` carve-out masking and its #21 resolved-grant lift
  logic — untouched (different layer, runs after the re-binds).

## Definition of done

`npm run build` clean, `npm test` green on darwin (hermetic tests; the effect
tests verify on Linux CI), the new grant tests prove the fix, bare-`~` grants
are inert on both platforms, and the generated argv is byte-identical for
every configuration with no under-home path grant and no bare-`~` grant.
