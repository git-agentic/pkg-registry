# Loader-chain analyzer v2 — remediation design note

Date: 2026-07-13
Status: Contract for the remediation round (delta over the 2026-07-12 design spec)
Trigger: A sharp adversarial review of the merged branch found the v1 analyzer is
**name-based and unscoped** — it identifies primitives by method name alone, keys
taint by identifier text globally, treats every file read as packaged input, and
misses several loader forms. This note is the corrective contract.

## Root cause

v1 `analyzeLoaderChain` matches `READ_FNS`/`DECODE_FNS`/`WRITE_FNS`/`LAUNCH_FNS`
by the callee's final property name and taints by bare identifier spelling. That
produces both false positives (any `obj.readFileSync()` is a "read"; a decode on
unrelated data satisfies correlation; shadowed/stale names form chains) and false
negatives (literal / `path.join(...)` write paths evade; base64 / native-require
loaders evade).

## The keystone: constrain taint at ORIGIN

The single decision that makes the rest safe: a **READ only originates
packaged-payload taint when its path argument is package-relative** — `__dirname`,
`require.resolve(...)`, a relative string literal (`"./x"`, `"x/y"`, not absolute,
not a bare-URL), or `path.join(__dirname, ...)`. `fs.readFileSync("/etc/passwd")`,
`fs.readFileSync(externalVar)`, or a read of a CLI-arg path does NOT originate
taint. Once the source is constrained, downstream write-path/launch matching can be
liberal (structural, not just Identifier) without reintroducing false criticals.

## Redesign order (implement in this sequence, tests pinned first)

1. **Binding tracking (S1).** Resolve `require`/`import` bindings: record which
   local names (and destructured members) refer to `fs`/`zlib`/`child_process`/
   `os`/`path` and their functions. `fs.readFileSync(...)` is a READ only when `fs`
   is bound to the fs module; a destructured `readFileSync(...)` is a READ only
   when that name is bound to `fs.readFileSync`. An arbitrary `obj.readFileSync()`
   whose `obj` is not a tracked fs binding is NOT a primitive.
2. **Lexical scope + kill-on-reassign (S2).** Taint is scoped to a lexical
   binding, not a global identifier string. A reassignment REPLACES the variable's
   tags (a var that was `decoded` and is reassigned from an untainted read becomes
   `read`, not both). Shadowing in a nested scope does not inherit the outer var's
   taint.
3. **Package-relative READ origin (Spec1, the keystone).** As above.
4. **Structural write-path ↔ launch matching (S3).** Tag the write target when it
   is an Identifier OR a structurally-recognizable path expression, and set
   `correlated` when the launch target is the same Identifier or a
   structurally-equal expression to a tainted written path. Cover the common
   `const out = path.join(tmpdir(), name); write(out, bin); spawn(out)` AND the
   inline-repeat `write(path.join(tmpdir(),'x'), bin); spawn(path.join(tmpdir(),'x'))`.
5. **Additional forms (Spec2) — the tractable subset only.**
   - DECODE += `Buffer.from(<tainted>, 'base64')` (and `atob`).
   - LAUNCH += native `require(<writtenPath>)` and `process.dlopen(_, <writtenPath>)`
     when the required/opened path carries `written-path` taint; and `require()` of
     a NON-JS packaged asset counts as a READ+LAUNCH of that asset.
   - DECODE += promisified/`await`ed `zlib` (`gunzip`/`inflate`/`brotliDecompress`
     used with `promisify` or `.promises`) — match the zlib function binding, not
     the await wrapper.
6. **Rule READ↔asset booster link (Spec6).** In `native-payload-loader.ts`, the
   content-mismatch booster fires only when the loader's READ target resolves to a
   file that has a content-mismatch observation — not when ANY mismatch exists
   anywhere in the package.

## Explicitly OUT of scope (narrow the claim, document honestly)

Static "does this materialize-and-execute a payload" is undecidable in general. v2
does NOT attempt: header-offset byte reads as a decode signal, arbitrary
expression-equality beyond the structural subset above, cross-file dataflow, or
data-flow through arbitrary higher-order functions. These are **documented residual
evasions** in ADR-0049, not silent gaps. Correspondingly, **invariant #8's wording
is tightened** from "any scanned package code" to the binding-tracked / lexically-
scoped / package-relative-origin model actually delivered.

## Acceptance — both directions, at VERDICT level

Benign fixtures that MUST stay `allow` (false-positive controls):
- custom `obj.readFileSync()/obj.gunzipSync()` where `obj` is a user object (S1);
- external-file read → decompress → write → spawn (path not package-relative, Spec1);
- shadowed / reassigned names across scopes that don't actually form a chain (S2).

Malicious fixtures that MUST `block` (evasion closures):
- literal / `path.join(...)` inline write-path loader (S3);
- `Buffer.from(read, 'base64')` → write → chmod → spawn loader (Spec2 base64);
- `require(writtenPath)` native-load loader (Spec2 native require).

Plus: every existing benign fixture's verdict unchanged; the real Gen-1/Gen-2
fixtures still `block`; the `scoring is deterministic across runs` pin green; each
rule pure + fail-open.

## Re-review

Adversarial, checklist-driven against the reviewer's exact ten findings; the
re-reviewer must supply concrete evasion/FP source snippets for the analyzer (as
the original reviewer did), not merely read the diff.
