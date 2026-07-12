# Design — Static detection of native-payload loader chains (Jscrambler-class)

Date: 2026-07-12
Status: Approved (brainstorming) — ready for implementation planning
Related research: [`docs/research/jscrambler-supply-chain-attack.md`](../../research/jscrambler-supply-chain-attack.md),
[Socket incident report](https://socket.dev/blog/jscrambler-supply-chain-attack)

## 1. Problem & threat model

An unauthorized publisher shipped compromised `jscrambler` versions in two
generations:

- **Gen-1** (`8.14.0`/`8.16.0`/`8.17.0`): an npm `preinstall` hook
  (`node dist/setup.js`) unpacked and launched a concealed ~7.8 MB native
  container.
- **Gen-2** (`8.18.0`/`8.20.0`): the *same loader* was inlined as an
  immediately-invoked function at the top of the package entry point
  (`dist/index.js`) and CLI (`dist/bin/jscrambler.js`). No lifecycle script —
  importing the module or running its command was enough, and `--ignore-scripts`
  was not a defense.

The loader, in both generations: recognizes a container by a magic header;
selects a platform entry; gzip-decompresses it into a randomly named hidden file
under the OS temp dir; makes it executable; spawns it detached with ignored
stdio; and calls `unref()`.

### How Sentinel scores this today (verified reading of the engine)

- **Gen-1 is (probably) already blocked.** `installScriptsRule` resolves the
  local file referenced by a lifecycle command via `referencedFiles()` and scans
  it for `child_process|spawn(` etc., producing a **critical** → `block`. This
  must be **empirically confirmed** with a synthetic fixture before writing any
  new rule; if confirmed, the new rule does not re-cover preinstall.
- **Gen-2 is the real gap.** The loader's network/secret behavior lives in the
  *unscanned binary container*, so `network-egress`, `secret-exfil`, and
  `obfuscation` all miss it. `capability-novelty` fires only in **diff mode** and
  only at **medium**. Net verdict today: `warn` at worst — **not `block`**. This
  is the zero-day gap.
- **The disguised container evades classification.** `extractTarball` classifies
  by *file extension only*. A `.js` file holding executable/gzip magic bytes that
  is ≤2 MB is read as UTF-8 and scanned as garbage (escaping the text rules and
  the unscanned-content flag); >2 MB it is flagged only `low` "large-code". Magic
  bytes are never inspected.

### Target invariant (new non-negotiable)

> Sentinel must critically flag a **dataflow-correlated** packaged-payload
> materialization-and-execution chain in any scanned package code, independent of
> lifecycle scripts, baseline availability, advisories, filenames, or known
> indicators; and separately expose raw-content/extension mismatches for every
> file, including oversized ones.

## 2. Non-goals / invariants preserved

- No one-off rule keyed to `jscrambler`, `intro.js`, specific hashes, or known
  C2 addresses.
- Scoring stays deterministic given a policy (invariant #1); the LLM never
  influences verdicts (#2); the inline gate stays sync + cheap (#3); cache key
  stays the integrity hash (#4); packument passthrough stays transparent (#5);
  rules fail open individually (#6).
- **No wall-clock enters the engine or any rule.** The cooldown gate is a
  serve-time overlay only.
- **No score-time auto-waiver / dedup.** `waived` keeps its single meaning
  (explicit policy exemption + hard-block exclusion). Two corroborating criticals
  are acceptable — the verdict is already `block` and each explains a distinct
  fact. Any future presentation-dedup is a separate design introducing an
  explicit `corroborates` / incident-group relationship.

## 3. Deliverable A — Extraction: raw-byte content classification

In `extractTarball` (`packages/core/src/extract.ts`), classify **raw bytes
before UTF-8 conversion**, for **every** file entry regardless of size.

- **Bounded prefix sniff** (~64 bytes) against an extensible signature table,
  validated **as far as the bounded prefix permits**:
  - ELF `7f 45 4c 46`; PE — `4d 5a` (`MZ`), and where the prefix reaches it,
    validate the PE header offset at `0x3C` (bare `MZ` is a *weaker* signal than
    a validated PE); Mach-O `fe ed fa ce/cf` + byte-reversed; **`ca fe ba be`
    flagged ambiguous** (fat Mach-O vs Java class); gzip `1f 8b`; WASM
    `00 61 73 6d` (treated as executable content); containers/archives — zip
    `50 4b`, xz `fd 37 7a`, zstd `28 b5 2f fd`, bzip2 `42 5a 68`.
- **Content/extension mismatch**: when a sniffed signature is
  binary/executable/compressed but the path has a text-looking extension
  (`.js/.json/.ts/.map/...`), record a mismatch.
- **Memory discipline**: only the bounded prefix is retained for classification.
  A file whose sniff says "binary" is **never retained as a text `PackageFile`**
  even if ≤2 MB — it goes to mismatch/unscanned accounting instead. This fixes
  the sub-2 MB disguise hole and avoids retaining concealed binaries as text.
- `ExtractResult` gains, following the existing `unscanned`/`unscannedTotals`
  pattern:
  - `contentMismatch: ContentMismatchEntry[]` — **capped** evidence list
    (`{ path, declaredExt, detectedKind, size }`).
  - `contentMismatchTotals` — **complete, never-capped** totals: overall count +
    **counts-by-detected-kind**, so facts stay complete past the evidence cap.
- `runAudit` synthesizes an extraction finding from the mismatch totals:
  **medium** for executable magic (ELF/PE/Mach-O/WASM) behind a text extension;
  **low** for gzip-alone-behind-`.js`. This is an independent transparency signal
  and a confidence booster — **never a standalone critical**.
- ADR-0041 gets an addendum documenting magic-byte sniffing.

## 4. Deliverable B — `native-payload-loader` rule (the critical trigger)

New pure rule `packages/core/src/rules/native-payload-loader.ts`, registered in
`rules/index.ts`. Adds **acorn** as the first parser dependency of
`@sentinel/core`.

### Primitives (per file, AST-based)

Four chain stages plus context boosters:

| Stage | Matches |
|---|---|
| **READ** | reads a packaged file — `fs.readFile*`/`createReadStream` on a package-relative path (`__dirname`/`require.resolve`/relative), or `require()` of a non-JS packaged asset |
| **DECODE** | `zlib`/`gunzip`/`inflate`/`brotli`, `Buffer.from(...,'base64')`, or reads past a known magic-header offset |
| **WRITE** | writes material to disk — `fs.writeFile*`/`createWriteStream`/`fs.cp` |
| **LAUNCH** | executes the written material — `child_process` `spawn/exec/execFile(Sync)`; `process.dlopen`/native `require` **only** when it references the materialized output (ordinary native `require()` is not equivalent) |

### Confidence model — correlation, not co-occurrence

- **Critical requires bounded local dataflow correlation** linking
  *packaged input → decoded material → written output path → that same output
  path is launched*. The rule follows **aliases and simple variable assignments**
  to connect the values/paths. A large build tool that reads, decompresses,
  writes, and spawns in one file **without** this link is **not** critical.
- If the values/paths **cannot be connected**, the finding **caps at high**.
- **Boosters** (enumerated as evidence; strengthen confidence, never substitute
  for the dataflow link): content-mismatch on the read file (consumed from
  extraction observations — Deliverable C), temp/hidden output path
  (`os.tmpdir()`, `/tmp`, dotfile), `chmod` +x on the written path, detached
  spawn / `stdio:'ignore'` / `unref()`, and **module-load execution** (chain in
  top-level/IIFE code reachable from `main`/`bin`).
- **Module-load reachability is a booster, not a prerequisite** — a callable
  malicious loader is still dangerous when activation happens later.
- **Partial chain** (e.g. READ+LAUNCH, no DECODE; or no dataflow link) →
  high/medium.

### Entry-point awareness

Resolve `package.json` `main`, `bin`, and **practical `exports` shapes**
(string, `.`/`"./"` conditional maps) **without full Node resolution**, to know
which files execute on import/CLI-run. Used only as the module-load booster.

### Cross-file readiness

v1 correlates **per-file** for precision. The detector's internal representation
is a per-file primitive map **keyed for aggregation**, so a later change can
union primitives across a tightly-connected entry-point-reachable module set
(bundler-split loaders) without reworking the rule.

### Parse-failure behavior (invariant #6, explicit)

acorn parses **JavaScript only** — TypeScript and JSX will throw. On any parse
failure (caught inside the rule's try/catch), fall back to a **regex
co-occurrence scan** of the same primitives, **capped below critical** (≤high).
Rationale: a working loader is valid JS, so "unparseable" must not read as
"safe"; but a mangled file must not hard-block. The **regex fallback detects
signals independently and must never claim dataflow correlation.** The rule never
crashes the audit.

### Evidence

The finding enumerates *which* primitives combined, each with file+line evidence
(e.g. "reads packaged `dist/intro.js`; gunzip-decompresses; writes to
`os.tmpdir()`; `chmod 0o755`; spawns detached with `unref()`"), satisfying the
"explain what caused the verdict" requirement.

### Redundancy with install-scripts

**No score-time waiver.** When both the loader-chain finding and an install-
script critical cite the same file, both stand as distinct facts (the file runs
at install **and** is a materialization chain). The verdict is already `block`;
the score floor is 0. Presentation-level dedup, if ever needed, is a separate
design.

## 5. Deliverable C — Extraction → rule data path

Rules currently receive `meta`, text `files`, `mode`, `releaseContext`,
`advisories`, `vulnerabilities`. Extraction observations (content mismatch) are
discovered in `extractTarball` but `buildAudit` runs rules **before** the old
`runAudit` synthesis site — so the loader rule cannot use mismatch evidence
unless it is threaded in.

- Add a typed, **policy-independent** `extractionObservations` field to
  `AuditInput`:
  ```ts
  interface ExtractionObservations {
    contentMismatch: ContentMismatchEntry[];        // capped evidence
    contentMismatchTotals: { count: number; byKind: Record<string, number> };
    unscannedTotals: { count: number; native: number; bytes: number };
  }
  ```
- `runAudit` passes the `ExtractResult`-derived observations into `buildAudit` →
  `AuditInput`. The loader rule **consumes** mismatch facts as a booster rather
  than re-sniffing raw bytes. Keeps the byte-level facts in one place
  (extraction) and the rule pure.

## 6. Deliverable D — New-release cooldown (serve-time overlay)

Policy gains optional `releaseCooldown?: { hours: number; exempt?: string[] }`.

- **Enforced only in the proxy at serve time**, using the **same immutable-
  overlay pattern as quarantine**: the cached `Audit`/score is never mutated, and
  **no wall-clock enters the engine**. Cooldown gets its **own finding/reason**
  (not represented as a runtime violation).
- At serve time, compare the version's packument publish-time to request-time
  (injectable clock for tests). If the version is younger than `hours` and the
  package is not exempt, overlay the served verdict to `block`.
- **Enforcement semantics (explicit):**
  - Cooldown overlays the served verdict to `block`.
  - `SENTINEL_POLICY=block` → 403.
  - Observe mode reports the overlaid `block` but still serves.
- **Metadata failure = fail closed.** For a matching (non-exempt) package,
  **absent or malformed publish time ⇒ block** (cooldown is an explicitly enabled
  security gate). Exempt packages bypass.
- **`hours` validation:** finite, positive, reasonably bounded (parsed fail-
  closed at startup like every other policy field; malformed ⇒ FATAL).
- **Exemption matching uses the existing anchored `matchPackage()`** semantics,
  not ad-hoc glob handling. Documented: exemptions weaken a time-based control
  and should be narrow.
- Off by default (`undefined` ⇒ no behavior change). New ADR.

## 7. Deliverable E — `sentinel exec` (scoped runtime containment)

A single, explicit interface — **not** a package-bin resolver in v1:

```text
sentinel exec -- <command> [args...]
```

Runs `<command>` under `createSandbox()`, reusing the existing
Seatbelt/bubblewrap backends, approved-capability model, scrubbed env, and
violation telemetry that enforced installs use. Requirements:

- **No shell** unless explicitly requested; **preserve argument boundaries**
  (`execFile`-style, args after `--` passed verbatim).
- Uses the **existing capability-approval mechanism**.
- **Scrubs the environment identically to enforced installs.**
- **Sets project root and working directory explicitly.**
- If `npx`/package-manager commands are ever supported, they **must not silently
  bypass the configured Sentinel registry** — out of scope for v1's direct-
  command interface, noted as a constraint for any future resolver.

**Scope, stated plainly in README/`--help`:** protects **Sentinel-mediated runs
only**. It **cannot contain ordinary Node imports performed outside the
command** — `npx jscrambler` or a raw `require()` outside Sentinel stays exposed.
This is defense-in-depth behind the registry-gate static detection, which is the
primary and independently-sufficient control. Kept **separate from the core
prevention acceptance criteria**. New ADR.

## 8. Fixtures (synthetic, inert)

All carry a `SYNTHETIC FIXTURE` header, use RFC-5737 documentation IPs, are
scored as text / never executed, and are regenerated via `npm run fixtures`.

- `malicious/payload-loader-preinstall` (Gen-1) — used **first** to confirm
  install-scripts already blocks it.
- `malicious/payload-loader-entry` (Gen-2, `main` entry, no install script).
- `malicious/payload-loader-bin` (Gen-2, CLI `bin` entry).
- **Disguised-content fixtures contain the *exact* signature bytes** required to
  exercise the classifier (real ELF/Mach-O/gzip header bytes — harmless on their
  own — followed by inert synthetic data), behind a text-looking extension. They
  cannot execute and are clearly marked. Not "fake magic": they genuinely match
  the detector.
- Benign controls for false-positive proof: a build tool that
  reads+decompresses+writes+spawns **without** the dataflow link; a
  `child_process`-only CLI; a gzip-only util; a genuine native-binary package; a
  large generated bundle.

**Signature coverage split:** test **each signature family at the classifier-
unit level**; only a **representative subset** needs full tarball fixtures.

## 9. Tests (map to the 10 acceptance criteria + guards)

1. Gen-1 `preinstall` loader → blocked.
2. Loader in `main` entry, no lifecycle script → blocked.
3. Loader in declared `bin` entry → blocked.
4. Binary/container behind a text extension → recognized as mismatch/unscanned.
5. Extract → write → chmod → detached-spawn chain → actionable enumerated
   evidence.
6. Diff-mode recognizes the newly-introduced dangerous behavior vs a benign
   predecessor.
7. Benign packages (child_process, compression, native assets, large bundles,
   CLIs) → **no false critical**.
8. Rules remain deterministic, pure, fail-open without crashing the audit.
9. Malicious synthetic fixture rejected by the proxy under enforcement mode.
10. Observe mode reports the block verdict without enforcing.

Plus guards: **dataflow-correlation-required** (disconnected primitives cap at
high); **full-mode critical** (no baseline); **regex fallback on TS/JSX syntax
caps below critical**; content-mismatch on ≤2 MB and >2 MB; cooldown overlay with
injected clock (blocks fresh / exempt passes / **cached score untouched** /
absent-time fails closed); **benign-verdict-invariance** — no existing benign
fixture's verdict moves; the `scoring is deterministic across runs` pin stays
green.

## 10. Documentation

- **CLAUDE.md**: subsystem paragraphs (new rule → rule count, extraction
  observations, cooldown overlay, `sentinel exec`), the new non-negotiable
  invariant (§1), policy + env additions.
- **ARCHITECTURE.md**: loader-chain detection, extraction-observation channel,
  cooldown overlay, exec.
- **README.md**: observe-vs-block distinction, cooldown config + narrow-exemption
  caveat, `sentinel exec` usage and its scope limit.
- **ADRs**: (a) loader-chain detection + extraction-observation channel;
  (b) cooldown serve-time overlay; (c) sandboxed exec. Addendum to ADR-0041 for
  magic-byte sniffing. No Accepted ADR is rewritten to reverse it.

## 11. Sequencing (each independently green before the next)

1. Extraction magic-byte classification + `ExtractionObservations` channel.
2. `native-payload-loader` rule + fixtures + tests (**the part that closes the
   zero-day; independently sufficient**).
3. Cooldown serve-time overlay.
4. `sentinel exec`.

## 12. Verification

`npm run fixtures` (fixtures changed) → `npm run build` → `npm test`. Report:
root cause + detection gap, implemented behavior, correlated signals + rationale,
false-positive controls, exact tests added, build/test results, and remaining
limitations (execution outside Sentinel-mediated install/CLI paths).
