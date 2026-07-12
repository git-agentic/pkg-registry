# ADR-0049: Native-payload-loader detection — raw-byte magic classification + dataflow-correlated loader rule

**Status:** Accepted
**Date:** 2026-07-12

## Context

An unauthorized publisher shipped compromised `jscrambler` versions in two
generations (see [Socket's incident report](https://socket.dev/blog/jscrambler-supply-chain-attack)
and the local research note,
[`docs/research/jscrambler-supply-chain-attack.md`](../research/jscrambler-supply-chain-attack.md)):

- **Gen-1** (`8.14.0`/`8.16.0`/`8.17.0`): an npm `preinstall` hook
  (`node dist/setup.js`) unpacked and launched a concealed ~7.8 MB native
  container.
- **Gen-2** (`8.18.0`/`8.20.0`): the *same loader* was inlined as an
  immediately-invoked function at the top of the package entry point
  (`dist/index.js`) and CLI (`dist/bin/jscrambler.js`). No lifecycle script —
  importing the module or running its command was enough, and `--ignore-scripts`
  was not a defense.

The loader, in both generations: recognizes a container by a magic header;
selects a platform entry; gzip-decompresses it into a randomly named hidden
file under the OS temp dir; makes it executable; spawns it detached with
ignored stdio; and calls `unref()`.

Reading the engine as it stood: **Gen-1 is (probably) already blocked** —
`installScriptsRule` resolves the local file referenced by a lifecycle command
and scans it for `child_process`/`spawn(` etc., producing a critical → `block`.
**Gen-2 is the real gap.** The loader's network/secret behavior lives in the
*unscanned binary container*, so `network-egress`, `secret-exfil`, and
`obfuscation` all miss it; `capability-novelty` fires only in diff mode and
only at `medium`. Net verdict today: `warn` at worst — not `block`. Worse, the
disguised container evades classification entirely: `extractTarball`
classified files by *file extension only*, so a `.js` file holding
executable/gzip magic bytes at ≤2 MB was read as UTF-8 and scanned as garbage
(escaping the text rules and the unscanned-content flag); at >2 MB it was
flagged only `low` "large-code". Magic bytes were never inspected.

## Decision

### Deliverable A — raw-byte magic classification (`packages/core/src/detect/magic.ts`)

`extractTarball` (`packages/core/src/extract.ts`) now classifies **raw bytes
before UTF-8 conversion**, for every file entry regardless of size, via
`classifyContent(prefix)`:

- **Bounded prefix sniff** — a single buffered read of a **hard-capped 512-byte
  prefix** (`MAGIC_PREFIX_BYTES`), validated only as far as the bytes actually
  present. Recognized signatures: ELF (`7f 45 4c 46`), Mach-O (`fe ed fa
  ce/cf` + byte-reversed), gzip (`1f 8b`), WASM (`00 61 73 6d`, treated as
  executable content), xz (`fd 37 7a`), zstd (`28 b5 2f fd`), bzip2 (`42 5a
  68`).
- **ZIP requires the complete 4-byte local-file-header signature** (`50 4b 03
  04`, or the empty/spanned variants `50 4b 05 06` / `50 4b 07 08`) — not the
  bare `50 4b` prefix.
- **PE validation is fully in-bounds or it downgrades.** `4d 5a` (`MZ`) at
  offset 0 triggers a read of the little-endian 4-byte `e_lfanew` at `0x3C`;
  `50 45 00 00` (`PE\0\0`) is asserted **only** when `e_lfanew` is a valid
  non-negative offset **and** `e_lfanew + 4 <= actualPrefixLength` (the real
  bytes read, which may be <512 for a short file) — so the signature read is
  always in-bounds. Otherwise the weaker `detectedKind: "mz"` is recorded
  instead of asserting PE or reading out of bounds.
- **`ca fe ba be` is flagged ambiguous** (fat Mach-O vs. Java `.class` share
  the header; cannot disambiguate from bytes alone) — as is bare `mz` (DOS
  stub, PE not validated within the prefix). Both are scored one step below a
  validated executable signature.
- **Detected-kind classes** drive all downstream behavior: `executable` (ELF,
  Mach-O, validated PE, WASM), `compressed` (gzip/xz/zstd/bzip2), `archive`
  (validated ZIP), `ambiguous` (`cafebabe`, `mz`), `text` (no binary signature
  matched — the normal case).
- **A mismatch finding fires only when a binary/compressed/archive/ambiguous
  signature hides behind a text-looking extension** (the existing `TEXT_EXT`
  set — `.js`/`.json`/`.ts`/`.map`/…). A **correctly-declared** binary,
  archive, or compressed asset produces no mismatch finding — accounting is
  unchanged, keeping genuine native-binary and compressed-asset packages
  false-positive-free. Any file whose sniff is non-`text` is never retained as
  a text `PackageFile`, even if ≤2 MB — this fixes the sub-2 MB disguise hole
  and stops concealed binaries from being retained as text.
- `ExtractResult` gains `contentMismatch: ContentMismatchEntry[]` (a capped
  evidence list, `{ path, declaredExt, detectedKind, size }`) and
  `contentMismatchTotals` (complete, never-capped: overall count +
  counts-by-detected-kind), following the existing `unscanned`/
  `unscannedTotals` pattern. The `unscanned` union (`large-code | native`) is
  **not** extended — mismatch files are tracked only in the new structures, so
  the two never double-count (a mismatched file requires a text-looking
  extension, so it can never also qualify as `native` by extension).
- `runAudit` synthesizes a `content-mismatch` finding (`metadata` category)
  from `contentMismatchTotals` when non-empty: **medium** when any mismatched
  file's detected kind is executable (`elf`/`macho`/`pe`/`wasm`), **low**
  otherwise (compressed/archive/ambiguous alone behind text). This is
  synthesized directly in `runAudit`, the same placement as `resource-abuse`
  and `unscanned-content` — **not** a registered `Rule`, because it needs
  `ExtractResult` data the pure per-file rule pipeline doesn't see. It is an
  independent transparency signal and a confidence booster, **never a
  standalone critical**.

### Deliverable B — `native-payload-loader` rule (`packages/core/src/rules/native-payload-loader.ts`)

A new pure rule, registered in `rules/index.ts` as the **10th** registered
rule (the pipeline was 9: install-scripts, secret-exfil, network-egress,
obfuscation, provenance, typosquat, release-anomaly, known-advisory,
known-vulnerability). Adds **acorn** as `@sentinel/core`'s first parser
dependency.

- **Four chain stages** are detected per file via AST analysis
  (`packages/core/src/detect/loader-chain.ts`): **READ** (reads a packaged
  file — `fs.readFile*`/`createReadStream` on a package-relative path, or
  `require()` of a non-JS packaged asset), **DECODE**
  (`zlib`/`gunzip`/`inflate`/`brotli`, base64 decode, or a read past a known
  magic-header offset), **WRITE** (`fs.writeFile*`/`createWriteStream`/
  `fs.cp`), **LAUNCH** (`child_process` spawn/exec family; `process.dlopen`/
  native `require` only when it references the materialized output).
- **Confidence is correlation, not co-occurrence.** `critical` requires
  **bounded local dataflow correlation** — the rule follows aliases and
  simple variable assignments to link *packaged input → decoded material →
  written output path → that same output path is launched*. A large build
  tool that reads, decompresses, writes, and spawns in one file **without**
  this link is never `critical`. If all four stages are present but the
  values/paths cannot be connected, the finding caps at **high**. A partial
  chain (e.g. a materialization signal — decode or write — combined with
  another stage, but not all four) is **medium**.
- **Boosters** strengthen confidence but never substitute for the dataflow
  link: content-mismatch on the read file (consumed from
  `AuditInput.extractionObservations` — Deliverable C, a booster only, not a
  re-sniff), a temp/hidden output path (`os.tmpdir()`, `/tmp`, dotfile),
  `chmod +x` on the written path, detached spawn / `stdio:'ignore'` /
  `unref()`, and module-load execution (the chain sits in top-level/IIFE code
  reachable from `main`/`bin`/practical `exports` shapes, resolved without
  full Node resolution). Module-load reachability is a booster, not a
  prerequisite — a callable loader activated later is still dangerous.
- **Parse-failure fallback (invariant #6, explicit).** acorn parses
  JavaScript only — TypeScript and JSX throw. On any parse failure (caught
  inside the rule's own try/catch), the rule falls back to a **regex
  co-occurrence scan** of the same four primitive families, **capped below
  critical (≤ high)**. The regex fallback detects signals independently and
  **never claims dataflow correlation** — a working loader is valid JS, so
  "unparseable" must not read as "safe," but a mangled file must not
  hard-block either. The rule never crashes the audit; a bug here is caught
  by the same `runRules` try/catch every rule gets.
- **No one-off rule keyed to `jscrambler`, a hash, or a known C2 address** —
  the rule detects the *shape* of the chain, generically.
- **No score-time waiver with `install-scripts`.** When both this rule and an
  install-script critical cite the same file, both stand as distinct facts
  (the file runs at install **and** is a materialization chain); the verdict
  is already `block` and the score floor is 0. Presentation-level dedup, if
  ever needed, is a separate design.

### Deliverable C — `ExtractionObservations` channel

Rules previously received `meta`, text `files`, `mode`, `releaseContext`,
`advisories`, `vulnerabilities` — but content-mismatch facts are discovered in
`extractTarball`, and `buildAudit` runs rules **before** the old `runAudit`
synthesis site. A typed, **policy-independent** field closes that gap:

```ts
interface ExtractionObservations {
  contentMismatch: ContentMismatchEntry[];        // capped evidence
  contentMismatchTotals: { count: number; byKind: Record<string, number> };
  unscannedTotals: { count: number; native: number; bytes: number };
}
```

`AuditInput.extractionObservations` is threaded from the `ExtractResult`
through `runAudit` → `buildAudit` → the rule pipeline. `native-payload-loader`
consumes mismatch facts as a booster rather than re-sniffing raw bytes,
keeping the byte-level facts in one place (extraction) and the rule pure.

## New non-negotiable invariant

> Sentinel must critically flag a **dataflow-correlated** packaged-payload
> materialization-and-execution chain in any scanned package code, independent of
> lifecycle scripts, baseline availability, advisories, filenames, or known
> indicators; and separately expose raw-content/extension mismatches for every
> file, including oversized ones.

## Consequences

- **The registered-rule count moves from 9 to 10.** `native-payload-loader`
  is a genuine registered `Rule`, unlike `content-mismatch` (synthesized
  inline in `runAudit`, alongside `resource-abuse`/`unscanned-content`/
  `capability-novelty`/`dependencyConfusion` — the rule count is otherwise
  unaffected by this ADR).
- **The sub-2 MB disguise hole is closed.** Any file whose raw bytes sniff as
  non-`text` is never retained as a text `PackageFile`, regardless of size —
  closing the specific gap that let a Gen-2-style container hide behind a
  small `.js` extension.
- **Gen-2 now reaches `block` without a lifecycle script.** The
  dataflow-correlated chain in `main`/`bin`-reachable code is a `critical`
  finding independent of `--ignore-scripts`, closing the zero-day gap
  described in Context.
- **False-positive posture is preserved.** Genuine build tools, compression
  utilities, `child_process`-only CLIs, and correctly-declared native-binary
  packages do not trigger `critical` — the dataflow-correlation requirement
  and the content-mismatch/correctly-declared-extension distinction are both
  designed around this acceptance criterion; the malicious fixtures are
  distinguished from their benign counterparts precisely by presence/absence
  of the linked chain, not by any single primitive.
- **Deterministic and offline, like every other rule.** No wall-clock, no
  network call, no LLM involvement — `LlmAuditAdapter` and the async
  *enrich* phase are untouched by this ADR, and the `scoring is deterministic
  across runs` pin stays green with the new rule included in the default
  pipeline.

## Extends ADR-0041

This ADR extends [ADR-0041](./0041-review-hardening.md) (review hardening —
the `unscanned-content` finding and SLSA-predicate-required provenance).
ADR-0041 made the >2 MB / native-extension scan boundary *visible*; this ADR
closes the disguised-container blind spot that boundary didn't cover — a file
that hides binary/compressed/archive content behind a text-looking extension
at *any* size, which ADR-0041's extension-only accounting could not see.
ADR-0041 is not modified beyond a one-line pointer to this ADR.

## Rejected

- **A one-off rule matching known loader signatures/hashes/C2 addresses** —
  rejected: it would catch only this incident and nothing shaped like it;
  the dataflow-correlation model generalizes to any packaged-payload loader.
- **Treating content-mismatch alone as a hard block** — rejected: a
  correctly-declared native asset is common and benign, and even a
  mismatched file alone (no dataflow chain) is only a transparency signal —
  see ADR-0041's own rejection of hard-blocking `unscanned-content` for the
  same reasoning. Only the correlated chain reaches `critical`.
- **Full Node module resolution for entry-point awareness** — rejected as
  unnecessary complexity for a booster signal; practical `main`/`bin`/
  `exports` shapes (string, `.`/`"./"` conditional maps) are resolved without
  it, sufficient to know which files execute on import/CLI-run.

## Deferred

- **Cross-file correlation.** v1 correlates per-file for precision; the
  detector's internal representation is a per-file primitive map keyed for
  aggregation, so a later change can union primitives across a
  tightly-connected entry-point-reachable module set (bundler-split loaders)
  without reworking the rule.
- **Presentation-level dedup** between `native-payload-loader` and
  `install-scripts` findings that cite the same file — noted above as a
  separate design, not introduced here.
