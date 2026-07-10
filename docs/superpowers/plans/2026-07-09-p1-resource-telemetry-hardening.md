# P1 Resource & Telemetry Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two P1 security gaps — bound tarball decompression against zip/tar bombs (#7), and stop a forged/anonymous violation report from quarantining any package (#9).

**Architecture:** #7 adds unpacked-byte/file-count caps to the pure `extractTarball` in `@sentinel/core` (chunked feed so a breach halts decompression mid-stream), surfaced as a critical `resource-abuse` finding by `runAudit`, wired from two new fail-closed proxy env vars. #9 splits sensing from enforcement: `ViolationStore.record` takes an injected `autoQuarantine` flag instead of deriving it from client `confidence`; the server only sets it when `SENTINEL_AUTO_QUARANTINE=1` **and** auth is enabled.

**Tech Stack:** Node + TypeScript, npm workspaces (`core`, `proxy`), `tar` 7, `node:test` + `tsx`, Express 5.

## Global Constraints

- **Determinism (invariant #1):** same input + same policy ⇒ same score. No wall-clock in the extraction cap or the finding — caps are byte/count only.
- **Rules fail open, the audit never crashes (invariant #6):** over-cap extraction returns `truncated: true`; it does **not** throw. Throwing stays reserved for a malformed tar.
- **Cap defaults live in `@sentinel/core`** (`maxUnpackedBytes` = `1024*1024*1024` (1 GiB), `maxFileCount` = `100000`) so the offline CLI/action are protected without env config.
- **New env vars parse fail-closed at startup** (malformed ⇒ `console.error("FATAL: …")` + `process.exit(1)`), same posture as the existing `SENTINEL_MAX_*` family.
- `SENTINEL_AUTO_QUARANTINE`: **`"1"` = on, unset/anything-else = off** (matches `SENTINEL_ENFORCE="1"`). On **requires** `SENTINEL_AUTH_PUBKEY` — FATAL otherwise.
- **Never edit an Accepted ADR to reverse it — supersede it.** #7 ⇒ new ADR-0039 (extends ADR-0037). #9 ⇒ new ADR-0040 (supersedes ADR-0023).
- **Malicious fixture stays blocked** after every change; `npm run build` clean, `npm test` green.
- **Delivery: two independent PRs.** Tasks A1–A4 = PR-A (closes #7). Tasks B1–B3 = PR-B (closes #9). Branch `p1-extract-caps` for PR-A, `p1-violation-split` for PR-B, both off `main`.

---

# PART A — #7: Bounded tarball extraction (PR-A, branch `p1-extract-caps`)

### Task A1: Extraction caps in `@sentinel/core`

**Files:**
- Modify: `packages/core/src/types.ts` (add `"resource"` to the `Category` union)
- Modify: `packages/core/src/extract.ts` (caps + `truncated` + chunked feed)
- Test: `packages/core/test/extract.test.ts` (new file)

**Interfaces:**
- Produces: `extractTarball(tgz, baseline?, opts?: { maxUnpackedBytes?: number; maxFileCount?: number }): Promise<ExtractResult>` where `ExtractResult` gains `truncated: boolean`. Constants `DEFAULT_MAX_UNPACKED_BYTES`, `DEFAULT_MAX_FILE_COUNT`. Category union includes `"resource"`.

- [ ] **Step 1: Create the branch**

```bash
git checkout main && git pull --ff-only && git checkout -b p1-extract-caps
```

- [ ] **Step 2: Write the failing test** — create `packages/core/test/extract.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { gzipSync } from "node:zlib";
import { create } from "tar";
import { extractTarball } from "../src/extract.js";

// Build an in-memory .tgz from a { path -> contents } map, npm-style (package/ prefix).
async function makeTgz(files: Record<string, string>): Promise<Buffer> {
  const { mkdtempSync, writeFileSync, mkdirSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join, dirname } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "sentinel-extract-"));
  try {
    for (const [p, c] of Object.entries(files)) {
      const full = join(dir, p);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, c);
    }
    const chunks: Buffer[] = [];
    const stream = create({ cwd: dir, gzip: true }, Object.keys(files));
    for await (const ch of stream) chunks.push(Buffer.from(ch));
    return Buffer.concat(chunks);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("extractTarball caps", () => {
  test("a benign small tarball is not truncated and yields its text files", async () => {
    const tgz = await makeTgz({ "package/package.json": '{"name":"x","version":"1.0.0"}', "package/index.js": "module.exports=1;\n" });
    const r = await extractTarball(tgz);
    assert.equal(r.truncated, false);
    assert.ok(r.files.some((f) => f.path === "package/package.json"));
    assert.ok(r.fileCount >= 2);
  });

  test("exceeding maxFileCount truncates and stops adding files", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 50; i++) files[`package/f${i}.js`] = "x";
    const tgz = await makeTgz(files);
    const r = await extractTarball(tgz, undefined, { maxFileCount: 10 });
    assert.equal(r.truncated, true);
    assert.ok(r.files.length <= 10, `expected <=10 retained, got ${r.files.length}`);
  });

  test("exceeding maxUnpackedBytes truncates without buffering the whole payload", async () => {
    // ~4 MB of highly compressible text → tiny compressed, large unpacked.
    const big = "A".repeat(4 * 1024 * 1024);
    const tgz = await makeTgz({ "package/big.txt": big });
    const r = await extractTarball(tgz, undefined, { maxUnpackedBytes: 1024 * 1024 });
    assert.equal(r.truncated, true);
  });

  test("default caps allow a normal package (no truncation)", async () => {
    const tgz = await makeTgz({ "package/index.js": "console.log(1)\n" });
    const r = await extractTarball(tgz);
    assert.equal(r.truncated, false);
  });
});
```

- [ ] **Step 3: Run it — expect FAIL** (`truncated`/opts don't exist yet)

Run: `node --import tsx --test packages/core/test/extract.test.ts`
Expected: FAIL (type error or `r.truncated` undefined).

- [ ] **Step 4: Add `"resource"` to the Category union** in `packages/core/src/types.ts`:

```ts
export type Category =
  | "obfuscation"
  | "network"
  | "secret-exfil"
  | "install-script"
  | "metadata"
  | "provenance"
  | "vulnerability"
  | "resource";
```

- [ ] **Step 5: Rewrite `extractTarball`** in `packages/core/src/extract.ts`. Replace the current constants + `ExtractResult` + `extractTarball` with:

```ts
const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip very large files from text scanning
const TEXT_EXT = /\.(c?js|mjs|cjs|ts|mts|cts|jsx|tsx|json|map|sh|txt|md|yml|yaml)$/i;

/** Decompression-bomb guards (ADR-0039). Defaults never hit a legitimate package. */
export const DEFAULT_MAX_UNPACKED_BYTES = 1024 * 1024 * 1024; // 1 GiB total decompressed
export const DEFAULT_MAX_FILE_COUNT = 100_000;

export interface ExtractResult {
  files: PackageFile[];
  unpackedSize: number;
  fileCount: number;
  /** True when a cap was hit and extraction was aborted early (ADR-0039). */
  truncated: boolean;
}

/**
 * Extract a `.tgz` npm tarball (gzip+tar) in memory and return its text files.
 * Binary and oversized entries are counted toward size/count but not scanned.
 * Guards against decompression bombs: caps total unpacked bytes and entry count,
 * feeding the parser in slices so a breach halts decompression mid-stream. On a
 * breach it returns `truncated: true` (never throws — throwing is reserved for a
 * malformed tar). `baseline` marks changed files for the diff multiplier.
 */
export async function extractTarball(
  tgz: Buffer,
  baseline?: Map<string, string>,
  opts: { maxUnpackedBytes?: number; maxFileCount?: number } = {},
): Promise<ExtractResult> {
  const maxUnpacked = opts.maxUnpackedBytes ?? DEFAULT_MAX_UNPACKED_BYTES;
  const maxFiles = opts.maxFileCount ?? DEFAULT_MAX_FILE_COUNT;
  const files: PackageFile[] = [];
  let unpackedSize = 0;
  let fileCount = 0;
  let truncated = false;
  let failure: Error | null = null;

  const parser = new tar.Parser();
  parser.on("entry", (entry: tar.ReadEntry) => {
    if (truncated || entry.type !== "File") {
      entry.resume();
      return;
    }
    fileCount += 1;
    if (fileCount > maxFiles) {
      truncated = true;
      entry.resume();
      return;
    }
    const chunks: Buffer[] = [];
    let bytes = 0;
    entry.on("data", (c: Buffer) => {
      unpackedSize += c.length;
      if (unpackedSize > maxUnpacked) truncated = true;
      bytes += c.length;
      if (!truncated && bytes <= MAX_FILE_BYTES) chunks.push(c);
    });
    entry.on("end", () => {
      if (truncated) return;
      const path = normalize(entry.path);
      if (bytes <= MAX_FILE_BYTES && TEXT_EXT.test(path)) {
        const content = Buffer.concat(chunks).toString("utf8");
        const prev = baseline?.get(path);
        files.push({ path, content, size: bytes, changed: baseline ? prev !== content : false });
      }
    });
    entry.on("error", (e: Error) => { failure = e; });
  });
  parser.on("error", (e: Error) => { failure = e; });

  // Feed compressed bytes in slices so a cap breach halts decompression mid-stream
  // rather than decompressing the whole bomb in one synchronous write. Yield to the
  // event loop between slices so queued entry/data handlers can set `truncated`.
  const SLICE = 256 * 1024;
  for (let off = 0; off < tgz.length && !truncated && !failure; off += SLICE) {
    parser.write(tgz.subarray(off, off + SLICE));
    await new Promise<void>((r) => setImmediate(r));
  }
  if (!truncated && !failure) {
    await new Promise<void>((resolve) => parser.end(() => resolve()));
  }
  if (failure) throw failure;
  return { files, unpackedSize, fileCount, truncated };
}
```

Leave `baselineFrom`, `integrityOf*`, and `normalize` unchanged below.

- [ ] **Step 6: Run the tests — expect PASS**

Run: `node --import tsx --test packages/core/test/extract.test.ts`
Expected: PASS (4/4).

- [ ] **Step 7: Build to confirm the Category change type-checks**

Run: `npm run build`
Expected: clean (no unhandled `"resource"` category switch elsewhere; weighting is by severity, not category).

- [ ] **Step 8: Commit**

```bash
git add packages/core/src/types.ts packages/core/src/extract.ts packages/core/test/extract.test.ts
git commit -m "feat(core): cap tarball extraction (unpacked bytes + file count) against decompression bombs"
```

---

### Task A2: `runAudit` threads caps and surfaces a critical `resource-abuse` finding

**Files:**
- Modify: `packages/core/src/audit.ts` (`AuditTarballInput` gains `extractLimits`; pass to both `extractTarball` calls; synthesize the finding on current-tarball truncation)
- Test: `packages/core/test/audit.test.ts` (add cases)

**Interfaces:**
- Consumes: `extractTarball(tgz, baseline?, { maxUnpackedBytes, maxFileCount })`, `ExtractResult.truncated` (Task A1).
- Produces: `AuditTarballInput.extractLimits?: { maxUnpackedBytes?: number; maxFileCount?: number }`. A truncated current tarball adds a finding `{ ruleId: "resource-abuse", category: "resource", severity: "critical", … }` (critical ⇒ hard block, no policy change needed since `hardBlockSeverity` is `critical`).

- [ ] **Step 1: Write the failing test** — add to `packages/core/test/audit.test.ts` (imports at top may already exist; add what's missing):

```ts
import { auditTarball } from "../src/audit.js";
// helper makeTgz: reuse the one from extract.test or inline a minimal copy here.

// meta uses the same full shape the existing audit.test.ts cases use.
const metaFor = (name: string) => ({ name, version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false });

test("a decompression-bomb tarball blocks with a critical resource-abuse finding", async () => {
  const big = "A".repeat(4 * 1024 * 1024);
  const tgz = await makeTgz({ "package/package.json": '{"name":"bomb","version":"1.0.0"}', "package/big.txt": big });
  const report = await auditTarball({
    meta: metaFor("bomb"),
    tarball: tgz,
    extractLimits: { maxUnpackedBytes: 1024 * 1024 },
  });
  assert.equal(report.verdict, "block");
  assert.ok(report.findings.some((f) => f.ruleId === "resource-abuse" && f.severity === "critical"));
});

test("a benign tarball produces no resource-abuse finding", async () => {
  const tgz = await makeTgz({ "package/package.json": '{"name":"ok","version":"1.0.0"}', "package/index.js": "module.exports=1\n" });
  const report = await auditTarball({ meta: metaFor("ok"), tarball: tgz });
  assert.ok(!report.findings.some((f) => f.ruleId === "resource-abuse"));
});
```

(If `makeTgz` isn't shared, copy the helper from `extract.test.ts` into `audit.test.ts`.)

- [ ] **Step 2: Run — expect FAIL**

Run: `node --import tsx --test packages/core/test/audit.test.ts`
Expected: FAIL (`extractLimits` unknown / no `resource-abuse` finding).

- [ ] **Step 3: Add `extractLimits` to `AuditTarballInput`** in `packages/core/src/audit.ts` (after the `vulnerabilities?` field):

```ts
  /** Decompression-bomb caps for extraction (ADR-0039). Undefined ⇒ core defaults. */
  extractLimits?: { maxUnpackedBytes?: number; maxFileCount?: number };
```

- [ ] **Step 4: Pass caps to both `extractTarball` calls and track current truncation.** In `runAudit`, change the two calls and capture the current result:

```ts
  const limits = input.extractLimits;
  let baseline: Map<string, string> | undefined;
  let baselineCapabilities: Capability[] | undefined;
  if (input.baselineTarball) {
    const prev = await extractTarball(input.baselineTarball, undefined, limits);
    baseline = baselineFrom(prev.files);
    baselineCapabilities = extractCapabilities({ meta: input.meta as PackageMeta, files: prev.files, mode: "diff" });
  }

  const extracted = await extractTarball(input.tarball, baseline, limits);
```

- [ ] **Step 5: Synthesize the finding.** In the synthesis block (next to the `integrityMismatch` push), add:

```ts
  if (extracted.truncated) {
    audit.findings.push({
      ruleId: "resource-abuse", category: "resource", severity: "critical",
      message: "tarball exceeded extraction limits (unpacked size or file count) — possible decompression bomb; audit truncated",
      onChangedFile: false, evidence: [],
    });
  }
```

- [ ] **Step 6: Run — expect PASS**

Run: `node --import tsx --test packages/core/test/audit.test.ts`
Expected: PASS. Also run `node --import tsx --test packages/core/test/extract.test.ts` to confirm still green.

- [ ] **Step 7: Commit**

```bash
git add packages/core/src/audit.ts packages/core/test/audit.test.ts
git commit -m "feat(core): runAudit blocks a truncated (bomb) tarball with a critical resource-abuse finding"
```

---

### Task A3: Proxy env wiring for the extraction caps

**Files:**
- Modify: `packages/proxy/src/server.ts` (`ServerOptions.extractLimits`; consume; pass to both `runAudit` calls at ~225 and ~637)
- Modify: `packages/proxy/src/index.ts` (resolve two env vars; pass to `createServer`; startup log line)
- Test: `packages/proxy/test/limits-startup.test.ts` (add the two new vars to the FATAL checks)

**Interfaces:**
- Consumes: `AuditTarballInput.extractLimits` (Task A2).
- Produces: `ServerOptions.extractLimits?: { maxUnpackedBytes?: number; maxFileCount?: number }`; env vars `SENTINEL_MAX_UNPACKED_BYTES`, `SENTINEL_MAX_FILE_COUNT`.

- [ ] **Step 1: Add `extractLimits` to `ServerOptions`** in `server.ts` (after `rateLimiter?`):

```ts
  /** Decompression-bomb extraction caps (ADR-0039). Undefined ⇒ core defaults. */
  extractLimits?: { maxUnpackedBytes?: number; maxFileCount?: number };
```

- [ ] **Step 2: Bind it inside `createServer`** near the other `const … = opts.…` lines (after `const maxTreePackages = …`):

```ts
  const extractLimits = opts.extractLimits;
```

- [ ] **Step 3: Pass it to both `runAudit` calls.** At the line-225 call, add `extractLimits,` to the input object. At the line-637 publish-path call, change to:

```ts
      const audit = await runAudit({ meta, tarball: parsed.tarball, signatures: null, hasProvenance: false, attestations: null, signingKeys, extractLimits });
```

- [ ] **Step 4: Resolve env vars in `index.ts`** — add beside the other `resolvePositiveInt` calls in `main()`:

```ts
  const maxUnpackedBytes = resolvePositiveInt("SENTINEL_MAX_UNPACKED_BYTES");
  const maxFileCount = resolvePositiveInt("SENTINEL_MAX_FILE_COUNT");
  const extractLimits = (maxUnpackedBytes !== undefined || maxFileCount !== undefined)
    ? { maxUnpackedBytes, maxFileCount }
    : undefined;
```

- [ ] **Step 5: Pass `extractLimits` into the `createServer({ … })` call** in `index.ts` (add `extractLimits` to the options object).

- [ ] **Step 6: Extend the startup `limits` log line** in `index.ts` to mention the new caps:

```ts
    console.log(`  limits   : tree ${maxTreePackages ?? 5000} pkgs, tarball ${(maxTarballBytes ?? 256 * 1024 * 1024)} B, packument ${(maxPackumentBytes ?? 128 * 1024 * 1024)} B, unpacked ${(maxUnpackedBytes ?? 1024 * 1024 * 1024)} B, files ${(maxFileCount ?? 100000)}`);
```

- [ ] **Step 7: Add FATAL-on-malformed cases** to `packages/proxy/test/limits-startup.test.ts` — extend the `VARS` array and add two tests mirroring the existing pattern:

```ts
// add to VARS:
"SENTINEL_MAX_UNPACKED_BYTES", "SENTINEL_MAX_FILE_COUNT",
```

```ts
  test("non-integer unpacked cap → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_MAX_UNPACKED_BYTES: "big" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("zero file-count cap → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_MAX_FILE_COUNT: "0" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });
```

- [ ] **Step 8: Build + run the affected tests**

Run: `npm run build && node --import tsx --test packages/proxy/test/limits-startup.test.ts`
Expected: build clean; startup tests pass (new vars FATAL on malformed).

- [ ] **Step 9: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/src/index.ts packages/proxy/test/limits-startup.test.ts
git commit -m "feat(proxy): wire SENTINEL_MAX_UNPACKED_BYTES / SENTINEL_MAX_FILE_COUNT (fail-closed) into the audit path"
```

---

### Task A4: Docs, ADR-0039, and PR-A

**Files:**
- Create: `docs/adr/0039-bounded-tarball-extraction.md`
- Modify: `CLAUDE.md`, `ARCHITECTURE.md`, `README.md` (env-var docs)

- [ ] **Step 1: Write ADR-0039** — create `docs/adr/0039-bounded-tarball-extraction.md` following the format of `docs/adr/0037-resource-robustness.md` (read it first for structure). Content must cover: **Context** (fetch caps bound compressed bytes only; decompression was unbounded — #7); **Decision** (unpacked-byte + file-count caps in core with 1 GiB / 100k defaults; chunked feed halts mid-stream; over-cap ⇒ `truncated` ⇒ critical `resource-abuse` finding ⇒ BLOCK, never a throw; no wall-time cap to preserve determinism; two fail-closed `SENTINEL_MAX_*` vars); **Consequences** (bombs block with a clear verdict; extends ADR-0037, does not supersede it; diff mode caps both extractions but only the current one blocks).

- [ ] **Step 2: Update `CLAUDE.md`** — add a Phase 26 (Part A) paragraph to the phase log and add `SENTINEL_MAX_UNPACKED_BYTES`/`SENTINEL_MAX_FILE_COUNT` to the env-var list in the "Stack & versions" section (beside the other `SENTINEL_MAX_*`).

- [ ] **Step 3: Update `ARCHITECTURE.md`** — in the resource-robustness section (near the ADR-0037 rate-limit/limits bullets, ~line 924+), add a bullet describing the extraction caps and the `resource-abuse` critical finding, citing ADR-0039.

- [ ] **Step 4: Update `README.md`** — add the two env vars to the proxy env-var reference (wherever `SENTINEL_MAX_TARBALL_BYTES` is documented).

- [ ] **Step 5: Full build + test**

Run: `npm run build && npm test 2>&1 | grep -E "^ℹ (tests|pass|fail|skipped)"`
Expected: build clean; `fail 0`; count is prior total + the new tests; **confirm the malicious fixture still blocks** (the demo/e2e suites stay green).

- [ ] **Step 6: Commit and open PR-A**

```bash
git add docs/adr/0039-bounded-tarball-extraction.md CLAUDE.md ARCHITECTURE.md README.md
git commit -m "docs: ADR-0039 + env docs for bounded tarball extraction (#7)"
git push -u origin p1-extract-caps
gh pr create --base main --title "Bounded tarball extraction — decompression-bomb DoS guard (closes #7)" --body "Closes #7. Caps unpacked bytes (1 GiB) + file count (100k) in @sentinel/core extractTarball; a breach halts decompression mid-stream and surfaces a critical resource-abuse finding → BLOCK (never a throw). Two fail-closed env vars: SENTINEL_MAX_UNPACKED_BYTES / SENTINEL_MAX_FILE_COUNT. ADR-0039 (extends ADR-0037). https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf"
```

---

# PART B — #9: Sensing ≠ enforcement for violations (PR-B, branch `p1-violation-split`)

### Task B1: `ViolationStore.record` takes an injected `autoQuarantine` flag

**Files:**
- Modify: `packages/proxy/src/violations.ts` (`record` signature + quarantine logic + sticky)
- Test: `packages/proxy/test/violations-store.test.ts` (update + add cases)

**Interfaces:**
- Produces: `record(v: ViolationInput, opts?: { autoQuarantine?: boolean }, now?: string): ViolationRecord`. `quarantined` is `autoQuarantine || (existing already quarantined)` — never derived from client `confidence`.

- [ ] **Step 1: Create the branch** (off `main`, independent of PR-A)

```bash
git checkout main && git pull --ff-only && git checkout -b p1-violation-split
```

- [ ] **Step 2: Write/adjust the failing tests** in `packages/proxy/test/violations-store.test.ts`. Add these cases (and update any existing case that assumed `confirmed ⇒ quarantined`):

```ts
test("a confirmed report does NOT quarantine when autoQuarantine is off (default)", () => {
  const s = new ViolationStore();
  const rec = s.record(base); // base.confidence === "confirmed"
  assert.equal(rec.quarantined, false);
  assert.equal(s.isQuarantined(base.integrity), false);
});

test("a confirmed report quarantines when autoQuarantine is on", () => {
  const s = new ViolationStore();
  const rec = s.record(base, { autoQuarantine: true });
  assert.equal(rec.quarantined, true);
  assert.equal(s.isQuarantined(base.integrity), true);
});

test("an existing quarantine is sticky across a later off-flag report", () => {
  const s = new ViolationStore();
  s.record(base, { autoQuarantine: true });
  const later = s.record({ ...base, kind: "network", target: null, deniedResource: null }); // autoQuarantine off
  assert.equal(later.quarantined, true, "must not un-quarantine");
});
```

(Inspect the existing tests at the top of the file for the `base` fixture shape; if a prior test asserted `rec.quarantined === true` from a plain `record(base)`, change it to pass `{ autoQuarantine: true }` or assert `false`, matching the new default.)

- [ ] **Step 3: Run — expect FAIL**

Run: `node --import tsx --test packages/proxy/test/violations-store.test.ts`
Expected: FAIL (option arg unknown; default now off).

- [ ] **Step 4: Change `record`** in `packages/proxy/src/violations.ts`:

```ts
  record(v: ViolationInput, opts: { autoQuarantine?: boolean } = {}, now = new Date().toISOString()): ViolationRecord {
    const existing = this.byIntegrity.get(v.integrity);
    // Quarantine is sticky: only clear() (operator override) may lift it. A later,
    // lower-confidence report must not evict a confirmed quarantine record.
    if (existing?.quarantined && v.confidence !== "confirmed") return existing;
    if (existing && existing.kind === v.kind && existing.target === v.target) return existing;
    // Sensing ≠ enforcement (ADR-0040): quarantine only when the SERVER opts in via
    // autoQuarantine — never from the client's own `confidence`. Once quarantined,
    // stays quarantined until clear().
    const quarantined = Boolean(opts.autoQuarantine) || Boolean(existing?.quarantined);
    const rec: ViolationRecord = { ...v, quarantined, reportedAt: now };
    this.index(rec);
    this.persist();
    try {
      this.history?.recordViolation(rec);
    } catch {
      /* best-effort telemetry — never break a violation record (invariant #6) */
    }
    return rec;
  }
```

Update the class doc comment on line 20 from "Confirmed violations quarantine the build." to "Quarantine is a server-gated enforcement decision (ADR-0040), not derived from client confidence."

- [ ] **Step 5: Run — expect PASS**

Run: `node --import tsx --test packages/proxy/test/violations-store.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/proxy/src/violations.ts packages/proxy/test/violations-store.test.ts
git commit -m "feat(proxy): ViolationStore quarantine is server-gated, not derived from client confidence"
```

---

### Task B2: Server computes the flag; startup requires auth for auto-quarantine

**Files:**
- Modify: `packages/proxy/src/server.ts` (`ServerOptions.autoQuarantine`; compute per-request flag; pass to `record`)
- Modify: `packages/proxy/src/index.ts` (resolve `SENTINEL_AUTO_QUARANTINE`; FATAL without auth; pass to `createServer`; startup log)
- Test: `packages/proxy/test/violations-e2e.test.ts` (add default-vs-flag cases), `packages/proxy/test/violations-startup.test.ts` (new; FATAL-without-auth)

**Interfaces:**
- Consumes: `record(v, { autoQuarantine }, now?)` (Task B1); `authz.enabled` (already on the authz object).
- Produces: `ServerOptions.autoQuarantine?: boolean`; env var `SENTINEL_AUTO_QUARANTINE`.

- [ ] **Step 1: Add `autoQuarantine` to `ServerOptions`** in `server.ts` (after `extractLimits?` if PR-A merged first, else after `rateLimiter?`):

```ts
  /** Opt-in auto-quarantine on confirmed violations (ADR-0040). Requires auth. Default off. */
  autoQuarantine?: boolean;
```

- [ ] **Step 2: Compute the effective flag** inside `createServer` near the other option bindings:

```ts
  // Auto-quarantine only when the operator opted in AND auth is enabled (so every
  // quarantine is attributable to a verified token). Open mode never quarantines.
  const autoQuarantineEnabled = Boolean(opts.autoQuarantine) && authz.enabled;
```

- [ ] **Step 3: Pass the per-request flag to `record`** in the `POST /-/violations` handler (replace the `violations.record({ … })` call and keep the revoke gate):

```ts
    const rec = violations.record(
      {
        name: v.name, version: v.version, integrity: v.integrity, kind: v.kind,
        target: v.target ?? null, confidence: v.confidence, deniedResource: v.deniedResource ?? null,
        evidence: { exitCode: v.evidence?.exitCode ?? 0, stderrExcerpt: String(v.evidence?.stderrExcerpt ?? "").slice(0, 200) },
      },
      { autoQuarantine: autoQuarantineEnabled && v.confidence === "confirmed" },
    );
    if (rec.quarantined) {
      approvals.remove(v.integrity); // revoke any standing approval for a quarantined build
      console.log(`[violation] quarantined ${v.name}@${v.version} (${rec.kind} → ${rec.target ?? rec.deniedResource})`);
    }
    res.json({ recorded: rec });
```

- [ ] **Step 4: Resolve `SENTINEL_AUTO_QUARANTINE` in `index.ts`** — add a resolver near the other `resolve…` functions:

```ts
function resolveAutoQuarantine(authEnabled: boolean): boolean {
  const on = process.env.SENTINEL_AUTO_QUARANTINE === "1";
  if (on && !authEnabled) {
    console.error("FATAL: SENTINEL_AUTO_QUARANTINE=1 requires SENTINEL_AUTH_PUBKEY (auto-quarantine must be attributable to a verified token)");
    process.exit(1);
  }
  return on;
}
```

- [ ] **Step 5: Call it in `main()`** after `authPublicKey` is resolved, and pass to `createServer`:

```ts
  const autoQuarantine = resolveAutoQuarantine(Boolean(authPublicKey));
```

Add `autoQuarantine` to the `createServer({ … })` options object.

- [ ] **Step 6: Add a startup log line** in `index.ts` (near the `auth` / `violations` lines):

```ts
    console.log(`  auto-quarantine: ${autoQuarantine ? "on (confirmed violations quarantine; auth-gated)" : "off (violations record-only)"}`);
```

- [ ] **Step 7: Add the e2e cases** to `packages/proxy/test/violations-e2e.test.ts`. Read the file's `boot`/helper shape first, then add (matching its style): (a) default boot (no `autoQuarantine`, no auth) — a `confirmed` `POST /-/violations` returns `recorded.quarantined === false` and the tarball still serves (not 403); (b) boot with `createServer({ …, authPublicKey: <test pubkey>, autoQuarantine: true })` and an operator/agent token — a `confirmed` report returns `quarantined === true` and the serve is 403. Use the existing test's token-minting/auth helpers.

- [ ] **Step 8: Create `packages/proxy/test/violations-startup.test.ts`** modeled on `limits-startup.test.ts` (child-process boot). One test: booting with `SENTINEL_AUTO_QUARANTINE=1` and **no** `SENTINEL_AUTH_PUBKEY` exits non-zero with `FATAL`. A second: `SENTINEL_AUTO_QUARANTINE=1` **with** a valid `SENTINEL_AUTH_PUBKEY` boots cleanly (exit 0 under `SENTINEL_BOOT_EXIT=1`). Reuse `ensureFixtures`, `bootWith` from that file's pattern; set `SENTINEL_UPSTREAM: "fixtures"`, `SENTINEL_BOOT_EXIT: "1"`, `SENTINEL_PORT: "0"`.

- [ ] **Step 9: Build + run the affected tests**

Run: `npm run build && node --import tsx --test packages/proxy/test/violations-store.test.ts packages/proxy/test/violations-e2e.test.ts packages/proxy/test/violations-startup.test.ts`
Expected: build clean; all pass.

- [ ] **Step 10: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/src/index.ts packages/proxy/test/violations-e2e.test.ts packages/proxy/test/violations-startup.test.ts
git commit -m "feat(proxy): auto-quarantine is opt-in (SENTINEL_AUTO_QUARANTINE) and auth-gated; default record-only"
```

---

### Task B3: Docs, ADR-0040, and PR-B

**Files:**
- Create: `docs/adr/0040-violation-sensing-vs-enforcement.md`
- Modify: `docs/adr/0023-runtime-violation-telemetry.md` (mark Superseded-by 0040 in its status line — do NOT rewrite its body)
- Modify: `CLAUDE.md`, `ARCHITECTURE.md`, `README.md`

- [ ] **Step 1: Write ADR-0040** — `docs/adr/0040-violation-sensing-vs-enforcement.md`, format per the ADR directory. **Context:** `POST /-/violations` derived quarantine from client `confidence`, so a forged/anonymous `confirmed` report could quarantine any audited integrity (#9). **Decision:** telemetry (recording) is always allowed; quarantine (enforcement) is a server decision — opt-in via `SENTINEL_AUTO_QUARANTINE=1`, effective only when auth is enabled (FATAL otherwise), so every quarantine is attributable; open mode never quarantines; default is record-only. **Consequences:** supersedes ADR-0023's auto-quarantine default; ADR-0023's containment claims (a swallowed denial is still contained) are unchanged; server-verifiable evidence remains out of scope (trust stays in the reporter credential).

- [ ] **Step 2: Mark ADR-0023 superseded** — edit only its status line (e.g. `Status: Accepted` → `Status: Accepted (superseded by ADR-0040 for the auto-quarantine default)`). Do not alter its body.

- [ ] **Step 3: Update `CLAUDE.md`** — Phase 26 (Part B) paragraph in the phase log; document `SENTINEL_AUTO_QUARANTINE` in the env-var list (note: requires `SENTINEL_AUTH_PUBKEY`, default off/record-only).

- [ ] **Step 4: Update `ARCHITECTURE.md`** — in the runtime-violation/quarantine section (Phase 10 / ADR-0023 area), add that quarantine is now opt-in + auth-gated per ADR-0040, default record-only.

- [ ] **Step 5: Update `README.md`** — document `SENTINEL_AUTO_QUARANTINE` in the proxy env-var reference.

- [ ] **Step 6: Full build + test**

Run: `npm run build && npm test 2>&1 | grep -E "^ℹ (tests|pass|fail|skipped)"`
Expected: build clean; `fail 0`; malicious fixture still blocks; any pre-existing violation-e2e test that assumed auto-quarantine now passes under the new default (updated in Task B2).

- [ ] **Step 7: Commit and open PR-B**

```bash
git add docs/adr/0040-violation-sensing-vs-enforcement.md docs/adr/0023-runtime-violation-telemetry.md CLAUDE.md ARCHITECTURE.md README.md
git commit -m "docs: ADR-0040 (supersedes 0023) + env docs for opt-in auth-gated auto-quarantine (#9)"
git push -u origin p1-violation-split
gh pr create --base main --title "Violation sensing ≠ enforcement — no forged/anonymous quarantine (closes #9)" --body "Closes #9. POST /-/violations no longer quarantines from client-supplied confidence. Quarantine is opt-in via SENTINEL_AUTO_QUARANTINE=1 and only fires when auth is enabled (FATAL otherwise) — default is record-only, so no forged or anonymous report can quarantine. ADR-0040 supersedes ADR-0023's auto-quarantine default. https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf"
```

---

## Notes for the executor

- PR-A and PR-B are independent and can be built in either order. If PR-B is built before PR-A merges, the `ServerOptions` insertion point in Task B2 Step 1 is "after `rateLimiter?`"; if after, "after `extractLimits?`". Either is fine.
- Category weighting is by **severity**, not category, so adding `"resource"` needs no policy edit — a `critical` finding hard-blocks via the existing `hardBlockSeverity: "critical"`.
- The `resource-abuse` finding is synthesized in `runAudit` (like `integrity-mismatch`), **not** a `Rule` — it needs the extraction metadata, not `AuditInput`. Do not register it in `rules/index.ts`.
