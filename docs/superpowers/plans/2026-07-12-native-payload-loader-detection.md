# Native-payload loader-chain detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Sentinel critically flag a dataflow-correlated packaged-payload materialization-and-execution chain (Jscrambler-class) in any scanned package code, and separately expose raw-content/extension mismatches for every file — then add a serve-time release-cooldown overlay and a scoped `sentinel exec` sandbox runner.

**Architecture:** Three layered deliverables. **A** adds raw-byte magic classification to the extractor and threads the results into rules via a policy-independent `ExtractionObservations` channel. **B** adds an acorn-based `native-payload-loader` rule that correlates READ→DECODE→WRITE→LAUNCH with bounded local dataflow and escalates to critical only when the launched target is taint-reachable from a packaged read. **D** overlays a cooldown block at serve time (no wall-clock in the engine). **E** adds `sentinel exec -- <cmd>` running under the existing sandbox. A+B are the first independently shippable milestone; they close the zero-day.

**Tech Stack:** Node 24 + TypeScript, npm workspaces (`core`, `proxy`, `sandbox`, `cli`), Express 5, `tar` 7, `acorn` + `acorn-walk` (new — `@sentinel/core`'s first parser deps), tests on `node:test` + `tsx`.

## Global Constraints

- **ESM only** (`"type": "module"`); internal imports use `.js` specifiers (NodeNext) even from `.ts` sources — copy verbatim.
- **Scoring is deterministic given a policy** (invariant #1). Same input + same policy ⇒ same score. The `scoring is deterministic across runs` test must stay green.
- **The LLM never sets the score** (#2). New findings come only from pure rules / synthesis.
- **Inline gate is sync + cheap** (#3): no network/LLM on the request path. Extraction and rules are static over in-memory bytes.
- **Cache key = integrity hash** (#4).
- **Proxy is transparent** (#5): packuments pass through, only `dist.tarball` is rewritten.
- **Rules fail open individually** (#6): `runRules` wraps each rule in try/catch; a buggy/throwing rule returns `[]`, never crashes the audit.
- **No wall-clock in the engine or any rule.** The cooldown gate compares publish-time to request-time **only** in the proxy at serve time.
- **No score-time auto-waiver.** `waived` keeps its sole meaning (explicit policy exemption + hard-block exclusion).
- **Fixtures:** malicious fixtures are synthetic + inert; loader **source** files carry a `SYNTHETIC FIXTURE` header and are scored as text; **exact-signature assets** are inert raw data marked out-of-band via an adjacent `SYNTHETIC-FIXTURE.txt` manifest. RFC-5737 IPs (`198.51.100.0/24`, `203.0.113.0/24`). Never executed. Regenerate via `npm run fixtures`.
- **Build/test:** `npm run build` clean, then `npm test` green. Never plan arithmetic on a written test count — run `npm test` and use what it prints.
- **Sandbox quirk:** the working tree may EPERM on `rm` of build artifacts; use `npx tsc --build --force <pkg>` rather than deleting `dist/`.

Spec: [`docs/superpowers/specs/2026-07-12-native-payload-loader-detection-design.md`](../specs/2026-07-12-native-payload-loader-detection-design.md).

---

## File Structure

**Deliverable A — extraction + observations**
- Create: `packages/core/src/detect/magic.ts` — raw-byte signature classifier (bounded 512-byte prefix).
- Create: `packages/core/test/magic.test.ts` — per-signature-family unit tests.
- Modify: `packages/core/src/extract.ts` — sniff raw bytes; add `contentMismatch`/`contentMismatchTotals`; never retain non-text as `PackageFile`.
- Modify: `packages/core/src/types.ts` — add `ContentMismatchEntry`, `ExtractionObservations`; extend `AuditInput`.
- Modify: `packages/core/src/audit.ts` — thread observations into `buildAudit`→`AuditInput`; synthesize the extraction finding.
- Modify: `packages/core/test/extract.test.ts`, `packages/core/test/audit.test.ts` — new cases.

**Deliverable B — loader rule**
- Create: `packages/core/src/detect/loader-chain.ts` — acorn parse + primitive detection + bounded dataflow correlation + entry-point resolution.
- Create: `packages/core/src/rules/native-payload-loader.ts` — the `Rule` wrapping the analyzer (+ regex fallback).
- Create: `packages/core/test/loader-chain.test.ts`, `packages/core/test/native-payload-loader.test.ts`.
- Modify: `packages/core/src/rules/index.ts` — register the rule.
- Modify: `packages/core/package.json` — add `acorn`, `acorn-walk`.
- Create: fixture dirs under `fixtures/malicious/…` and `fixtures/benign/…`; modify `fixtures/index.json`, `scripts/make-fixtures.ts`.
- Create: `packages/proxy/test/payload-loader-e2e.test.ts`.

**Deliverable D — cooldown overlay**
- Modify: `packages/core/src/policy.ts` — `releaseCooldown` field + parse/validate.
- Create: `packages/proxy/src/cooldown.ts` — pure overlay + publish-time resolution.
- Create: `packages/proxy/test/cooldown.test.ts` (unit) + `packages/proxy/test/cooldown-e2e.test.ts`.
- Modify: `packages/proxy/src/server.ts` — apply overlay in `gateAndSend` + report-returning routes; inject clock.

**Deliverable E — sentinel exec**
- Modify: `packages/sandbox/src/types.ts`, `seatbelt.ts`, `bubblewrap.ts` — add `runArgv`.
- Modify: `packages/cli/src/index.ts` — `exec` command.
- Create: `packages/sandbox/test/run-argv.test.ts`, `packages/cli`/proxy e2e as noted.

**Docs / ADRs (alongside behavior)**
- Create: `docs/adr/0049-native-payload-loader-detection.md` (extends ADR-0041), `docs/adr/0050-release-cooldown-overlay.md`, `docs/adr/0051-sandboxed-exec.md`.
- Modify: `docs/adr/0041-review-hardening.md` (one-line pointer only), `docs/adr/README.md`, `ARCHITECTURE.md`, `CLAUDE.md`, `README.md`.

---

# MILESTONE 1 — Deliverables A + B (closes the zero-day)

## Task 1: Raw-byte magic classifier

**Files:**
- Create: `packages/core/src/detect/magic.ts`
- Test: `packages/core/test/magic.test.ts`

**Interfaces:**
- Produces:
  - `type DetectedKind = "elf" | "macho" | "pe" | "mz" | "wasm" | "gzip" | "xz" | "zstd" | "bzip2" | "zip" | "cafebabe" | "text"`
  - `type DetectedClass = "executable" | "compressed" | "archive" | "ambiguous" | "text"`
  - `interface Classification { kind: DetectedKind; class: DetectedClass }`
  - `function classifyContent(prefix: Buffer): Classification` — sniffs a bounded prefix (caller passes ≤512 bytes actually read).
  - `const MAGIC_PREFIX_BYTES = 512`

- [ ] **Step 1: Write the failing test**

```ts
// packages/core/test/magic.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { Buffer } from "node:buffer";
import { classifyContent, MAGIC_PREFIX_BYTES } from "../src/detect/magic.js";

const buf = (...bytes: number[]): Buffer => Buffer.from(bytes);

describe("classifyContent", () => {
  test("ELF → executable", () => {
    assert.deepEqual(classifyContent(buf(0x7f, 0x45, 0x4c, 0x46, 1, 1, 1)), { kind: "elf", class: "executable" });
  });
  test("Mach-O 32/64 + byte-reversed → executable", () => {
    for (const m of [[0xfe,0xed,0xfa,0xce],[0xfe,0xed,0xfa,0xcf],[0xce,0xfa,0xed,0xfe],[0xcf,0xfa,0xed,0xfe]]) {
      assert.equal(classifyContent(buf(...m)).class, "executable");
      assert.equal(classifyContent(buf(...m)).kind, "macho");
    }
  });
  test("CA FE BA BE → ambiguous (fat Mach-O vs Java class)", () => {
    assert.deepEqual(classifyContent(buf(0xca,0xfe,0xba,0xbe, 0,0,0,2)), { kind: "cafebabe", class: "ambiguous" });
  });
  test("WASM → executable", () => {
    assert.deepEqual(classifyContent(buf(0x00,0x61,0x73,0x6d,1,0,0,0)), { kind: "wasm", class: "executable" });
  });
  test("gzip / xz / zstd / bzip2 → compressed", () => {
    assert.deepEqual(classifyContent(buf(0x1f,0x8b,0x08)), { kind: "gzip", class: "compressed" });
    assert.deepEqual(classifyContent(buf(0xfd,0x37,0x7a,0x58,0x5a,0x00)), { kind: "xz", class: "compressed" });
    assert.deepEqual(classifyContent(buf(0x28,0xb5,0x2f,0xfd)), { kind: "zstd", class: "compressed" });
    assert.deepEqual(classifyContent(buf(0x42,0x5a,0x68)), { kind: "bzip2", class: "compressed" });
  });
  test("ZIP requires the full 4-byte local-file-header signature, not bare PK", () => {
    assert.deepEqual(classifyContent(buf(0x50,0x4b,0x03,0x04)), { kind: "zip", class: "archive" });
    assert.deepEqual(classifyContent(buf(0x50,0x4b,0x05,0x06)), { kind: "zip", class: "archive" });
    // bare PK followed by non-signature bytes is NOT zip
    assert.equal(classifyContent(buf(0x50,0x4b,0x21,0x21)).class, "text");
  });
  test("PE: MZ + e_lfanew pointing to PE\\0\\0 within prefix → pe/executable", () => {
    const b = Buffer.alloc(0x48, 0x00);
    b[0] = 0x4d; b[1] = 0x5a;              // MZ
    b.writeUInt32LE(0x40, 0x3c);           // e_lfanew = 0x40
    b[0x40] = 0x50; b[0x41] = 0x45; b[0x42] = 0x00; b[0x43] = 0x00; // PE\0\0
    assert.deepEqual(classifyContent(b), { kind: "pe", class: "executable" });
  });
  test("PE: MZ but e_lfanew points beyond the actual prefix → mz/ambiguous (no OOB read)", () => {
    const b = Buffer.alloc(0x40, 0x00);    // only 0x40 bytes actually available
    b[0] = 0x4d; b[1] = 0x5a;
    b.writeUInt32LE(0x1000, 0x3c);         // e_lfanew far beyond buffer
    assert.deepEqual(classifyContent(b), { kind: "mz", class: "ambiguous" });
  });
  test("PE: MZ with e_lfanew+4 exactly at buffer end is in-bounds; +1 over is not", () => {
    const inb = Buffer.alloc(0x44, 0x00); inb[0]=0x4d; inb[1]=0x5a; inb.writeUInt32LE(0x40,0x3c);
    inb[0x40]=0x50; inb[0x41]=0x45; inb[0x42]=0; inb[0x43]=0;
    assert.equal(classifyContent(inb).kind, "pe");
    const oob = Buffer.alloc(0x43, 0x00); oob[0]=0x4d; oob[1]=0x5a; oob.writeUInt32LE(0x40,0x3c);
    assert.equal(classifyContent(oob).kind, "mz"); // e_lfanew+4 = 0x44 > length 0x43
  });
  test("plain JS source → text", () => {
    assert.deepEqual(classifyContent(Buffer.from("module.exports = 1;\n")), { kind: "text", class: "text" });
  });
  test("MAGIC_PREFIX_BYTES is 512", () => assert.equal(MAGIC_PREFIX_BYTES, 512));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/core/test/magic.test.ts`
Expected: FAIL — cannot find module `../src/detect/magic.js`.

- [ ] **Step 3: Write minimal implementation**

```ts
// packages/core/src/detect/magic.ts
import { Buffer } from "node:buffer";

export const MAGIC_PREFIX_BYTES = 512;

export type DetectedKind =
  | "elf" | "macho" | "pe" | "mz" | "wasm"
  | "gzip" | "xz" | "zstd" | "bzip2" | "zip" | "cafebabe" | "text";
export type DetectedClass = "executable" | "compressed" | "archive" | "ambiguous" | "text";
export interface Classification { kind: DetectedKind; class: DetectedClass }

const TEXT: Classification = { kind: "text", class: "text" };

function starts(b: Buffer, ...sig: number[]): boolean {
  if (b.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[i] !== sig[i]) return false;
  return true;
}

/**
 * Classify a file by a BOUNDED prefix of its raw bytes (the caller reads at most
 * MAGIC_PREFIX_BYTES). Validation only reaches as far as the bytes actually
 * present — never an out-of-bounds read. `text` means no binary signature
 * matched (the normal case).
 */
export function classifyContent(prefix: Buffer): Classification {
  if (starts(prefix, 0x7f, 0x45, 0x4c, 0x46)) return { kind: "elf", class: "executable" };
  if (starts(prefix, 0x00, 0x61, 0x73, 0x6d)) return { kind: "wasm", class: "executable" };
  if (starts(prefix, 0xfe, 0xed, 0xfa, 0xce) || starts(prefix, 0xfe, 0xed, 0xfa, 0xcf) ||
      starts(prefix, 0xce, 0xfa, 0xed, 0xfe) || starts(prefix, 0xcf, 0xfa, 0xed, 0xfe)) {
    return { kind: "macho", class: "executable" };
  }
  // Fat Mach-O and Java .class share CA FE BA BE — cannot disambiguate from the header alone.
  if (starts(prefix, 0xca, 0xfe, 0xba, 0xbe)) return { kind: "cafebabe", class: "ambiguous" };
  if (starts(prefix, 0x1f, 0x8b)) return { kind: "gzip", class: "compressed" };
  if (starts(prefix, 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)) return { kind: "xz", class: "compressed" };
  if (starts(prefix, 0x28, 0xb5, 0x2f, 0xfd)) return { kind: "zstd", class: "compressed" };
  if (starts(prefix, 0x42, 0x5a, 0x68)) return { kind: "bzip2", class: "compressed" };
  if (starts(prefix, 0x50, 0x4b, 0x03, 0x04) || starts(prefix, 0x50, 0x4b, 0x05, 0x06) ||
      starts(prefix, 0x50, 0x4b, 0x07, 0x08)) {
    return { kind: "zip", class: "archive" };
  }
  // PE: MZ stub at 0, then validate PE\0\0 at e_lfanew ONLY when fully in-bounds.
  if (starts(prefix, 0x4d, 0x5a)) {
    if (prefix.length >= 0x40) {
      const eLfanew = prefix.readUInt32LE(0x3c);
      if (eLfanew >= 0 && eLfanew + 4 <= prefix.length &&
          prefix[eLfanew] === 0x50 && prefix[eLfanew + 1] === 0x45 &&
          prefix[eLfanew + 2] === 0x00 && prefix[eLfanew + 3] === 0x00) {
        return { kind: "pe", class: "executable" };
      }
    }
    return { kind: "mz", class: "ambiguous" };
  }
  return TEXT;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx --test packages/core/test/magic.test.ts`
Expected: PASS (all cases).

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/detect/magic.ts packages/core/test/magic.test.ts
git commit -m "feat(core): raw-byte magic-signature classifier (bounded prefix)"
```

---

## Task 2: Extraction sniffs raw bytes and records content mismatch

**Files:**
- Modify: `packages/core/src/types.ts` (add `ContentMismatchEntry`)
- Modify: `packages/core/src/extract.ts:7-42` (constants + `ExtractResult`) and the entry handler `:99-134`
- Test: `packages/core/test/extract.test.ts`

**Interfaces:**
- Consumes: `classifyContent`, `MAGIC_PREFIX_BYTES` (Task 1).
- Produces (added to `ExtractResult`):
  - `contentMismatch: ContentMismatchEntry[]` — capped at `MAX_UNSCANNED` (100).
  - `contentMismatchTotals: { count: number; byKind: Record<string, number> }` — complete, never capped.
  - `interface ContentMismatchEntry { path: string; declaredExt: string; detectedKind: string; size: number }` (exported from `types.ts`).

- [ ] **Step 1: Write the failing test**

```ts
// append to packages/core/test/extract.test.ts (inside a new describe)
import { classifyContent } from "../src/detect/magic.js"; // ensure import exists at top if needed

describe("content/extension mismatch", () => {
  test("gzip bytes behind .js → mismatch (compressed), not retained as text", async () => {
    const gz = gzipSync(Buffer.from("x".repeat(50)));
    // makeTgzBinary lets a file hold raw bytes; see helper below.
    const tgz = await makeTgzBinary({ "package/dist/intro.js": gz, "package/index.js": Buffer.from("module.exports=1\n") });
    const r = await extractTarball(tgz);
    assert.equal(r.files.find((f) => f.path === "package/dist/intro.js"), undefined, "disguised binary must NOT be retained as text");
    assert.equal(r.contentMismatchTotals.count, 1);
    assert.equal(r.contentMismatchTotals.byKind.gzip, 1);
    const entry = r.contentMismatch.find((e) => e.path === "package/dist/intro.js");
    assert.ok(entry && entry.detectedKind === "gzip" && entry.declaredExt === ".js");
  });

  test("ELF bytes behind .js under 2 MB → mismatch (executable), not retained as text", async () => {
    const elf = Buffer.concat([Buffer.from([0x7f,0x45,0x4c,0x46]), Buffer.alloc(1000, 0x00)]);
    const tgz = await makeTgzBinary({ "package/dist/setup.js": elf });
    const r = await extractTarball(tgz);
    assert.equal(r.files.length, 0);
    assert.equal(r.contentMismatchTotals.byKind.elf, 1);
  });

  test("correctly-declared .node native binary → no mismatch (unchanged accounting)", async () => {
    const elf = Buffer.concat([Buffer.from([0x7f,0x45,0x4c,0x46]), Buffer.alloc(1000, 0x00)]);
    const tgz = await makeTgzBinary({ "package/build/Release/addon.node": elf });
    const r = await extractTarball(tgz);
    assert.equal(r.contentMismatchTotals.count, 0, "correctly-declared native binary is not a mismatch");
    assert.equal(r.unscannedTotals.native, 1);
  });

  test("ordinary JS is still retained and scanned", async () => {
    const tgz = await makeTgzBinary({ "package/index.js": Buffer.from("const x = require('fs')\n") });
    const r = await extractTarball(tgz);
    assert.ok(r.files.find((f) => f.path === "package/index.js"));
    assert.equal(r.contentMismatchTotals.count, 0);
  });

  test("mismatch is detected for an OVERSIZED (>2 MB) disguised file too", async () => {
    // 3 MB: gzip magic prefix + filler, behind .js — sniff runs on the bounded prefix regardless of size.
    const big = Buffer.concat([Buffer.from([0x1f, 0x8b, 0x08]), Buffer.alloc(3 * 1024 * 1024, 0x00)]);
    const tgz = await makeTgzBinary({ "package/dist/huge.js": big });
    const r = await extractTarball(tgz);
    assert.equal(r.files.find((f) => f.path === "package/dist/huge.js"), undefined, "oversized binary not retained as text");
    assert.equal(r.contentMismatchTotals.byKind.gzip, 1, "oversized disguised file still recorded as a mismatch");
  });
});
```

Add this binary-capable helper near `makeTgz` at the top of the file:

```ts
// Build an in-memory .tgz from a { path -> Buffer } map (binary-safe).
async function makeTgzBinary(files: Record<string, Buffer>): Promise<Buffer> {
  const { mkdtempSync, writeFileSync, mkdirSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join, dirname } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "sentinel-extract-bin-"));
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/core/test/extract.test.ts`
Expected: FAIL — `contentMismatchTotals` undefined.

- [ ] **Step 3: Add the type**

In `packages/core/src/types.ts`, after the `PackageFile` interface (around line 160), add:

```ts
/** A file whose raw-byte signature disagrees with its text-looking extension (ADR-0049). */
export interface ContentMismatchEntry {
  path: string;
  /** The declared extension including the dot, lowercased, e.g. ".js". */
  declaredExt: string;
  /** The sniffed DetectedKind (e.g. "gzip", "elf", "pe", "mz", "cafebabe"). */
  detectedKind: string;
  size: number;
}
```

- [ ] **Step 4: Wire sniffing into `extract.ts`**

In `packages/core/src/extract.ts`:

(a) Add the import at the top:
```ts
import { classifyContent, MAGIC_PREFIX_BYTES } from "./detect/magic.js";
```

(b) Extend `ExtractResult` (after `unscannedTotals`, ~line 41):
```ts
  /** Files whose raw-byte signature disagrees with a text-looking extension. Capped list. */
  contentMismatch: ContentMismatchEntry[];
  /** Complete, never-capped mismatch totals: overall count + counts by detected kind. */
  contentMismatchTotals: { count: number; byKind: Record<string, number> };
```
Add `ContentMismatchEntry` to the `types.js` import line.

(c) Add the `TEXT_EXT`-adjacent helper and accumulators. Near the other `let` accumulators (~line 79) add:
```ts
  const contentMismatch: ContentMismatchEntry[] = [];
  const contentMismatchTotals = { count: 0, byKind: {} as Record<string, number> };
```

(d) Capture a bounded raw prefix per file. In the `entry.on("data", ...)` handler (~line 103), also collect the first `MAGIC_PREFIX_BYTES` raw bytes regardless of size:
```ts
    const prefixChunks: Buffer[] = [];
    let prefixLen = 0;
    entry.on("data", (c: Buffer) => {
      if (isFile) {
        bytes += c.length;
        if (prefixLen < MAGIC_PREFIX_BYTES) {
          const need = MAGIC_PREFIX_BYTES - prefixLen;
          prefixChunks.push(c.subarray(0, need));
          prefixLen += Math.min(need, c.length);
        }
        if (!truncated && bytes <= MAX_FILE_BYTES) chunks.push(c);
      }
    });
```

(e) At the top of `entry.on("end", ...)` (~line 109), after computing `path`, classify and short-circuit mismatches BEFORE the text-retention branch:
```ts
    entry.on("end", () => {
      if (truncated || !isFile) return;
      const path = normalize(entry.path);
      const cls = classifyContent(Buffer.concat(prefixChunks));
      const declaredExt = extOf(path);
      const textLooking = TEXT_EXT.test(path);
      if (cls.class !== "text" && textLooking) {
        // Binary/compressed/archive/ambiguous signature hiding behind a text-looking
        // extension → mismatch. Never retained as text; tracked only here.
        contentMismatchTotals.count += 1;
        contentMismatchTotals.byKind[cls.kind] = (contentMismatchTotals.byKind[cls.kind] ?? 0) + 1;
        if (contentMismatch.length < MAX_UNSCANNED) {
          contentMismatch.push({ path, declaredExt, detectedKind: cls.kind, size: bytes });
        }
        return;
      }
      if (bytes <= MAX_FILE_BYTES && TEXT_EXT.test(path)) {
        const content = Buffer.concat(chunks).toString("utf8");
        const prev = baseline?.get(path);
        files.push({ path, content, size: bytes, changed: baseline ? prev !== content : false });
        return;
      }
      const isLargeCode = bytes > MAX_FILE_BYTES && CODE_EXT.test(path);
      const isNative = NATIVE_EXT.test(path);
      if (isLargeCode || isNative) {
        unscannedTotals.count += 1;
        unscannedTotals.bytes += bytes;
        if (isNative) unscannedTotals.native += 1;
        if (unscanned.length < MAX_UNSCANNED) {
          unscanned.push({ path, size: bytes, kind: isLargeCode ? "large-code" : "native" });
        }
      }
    });
```

(f) Add the `extOf` helper near `normalize` (~line 215):
```ts
function extOf(p: string): string {
  const m = /(\.[a-z0-9]+)$/i.exec(p);
  return m ? m[1]!.toLowerCase() : "";
}
```

(g) Add both new fields to the returned object (~line 193):
```ts
  return { files, unpackedSize, fileCount, truncated, unscanned, unscannedTotals, contentMismatch, contentMismatchTotals };
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx tsx --test packages/core/test/extract.test.ts`
Expected: PASS. Then `npm run build` (from repo root) must be clean — TypeScript will force any other `ExtractResult` consumer (audit.ts) to be handled in Task 3; if build errors there, proceed to Task 3 before committing the milestone, but this task's test passes now.

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/types.ts packages/core/src/extract.ts packages/core/test/extract.test.ts
git commit -m "feat(core): sniff raw bytes in extraction, record content/extension mismatch"
```

---

## Task 3: ExtractionObservations channel + synthesized extraction finding

**Files:**
- Modify: `packages/core/src/types.ts` (add `ExtractionObservations`; extend `AuditInput`)
- Modify: `packages/core/src/audit.ts` (thread observations into `buildAudit`/`AuditInput`; synthesize the finding)
- Test: `packages/core/test/audit.test.ts`

**Interfaces:**
- Consumes: `ExtractResult.contentMismatch(+Totals)`, `unscannedTotals` (Task 2).
- Produces:
  - `interface ExtractionObservations { contentMismatch: ContentMismatchEntry[]; contentMismatchTotals: { count: number; byKind: Record<string, number> }; unscannedTotals: { count: number; native: number; bytes: number } }`
  - `AuditInput.extractionObservations?: ExtractionObservations`
  - A synthesized finding `ruleId: "content-mismatch"`, `category: "metadata"`, severity **medium** for executable kinds (`elf`/`macho`/`pe`/`wasm`), else **low** (`gzip`/`xz`/`zstd`/`bzip2`/`zip`/`cafebabe`/`mz`).

- [ ] **Step 1: Write the failing test**

```ts
// append to packages/core/test/audit.test.ts
describe("content-mismatch extraction finding", () => {
  test("executable magic behind .js → medium content-mismatch finding", async () => {
    const elf = Buffer.concat([Buffer.from([0x7f,0x45,0x4c,0x46]), Buffer.alloc(1000)]);
    const tgz = await makeTgzBinary({
      "package/package.json": Buffer.from(JSON.stringify({ name: "x", version: "1.0.0", main: "index.js" })),
      "package/index.js": Buffer.from("module.exports=1\n"),
      "package/dist/payload.js": elf,
    });
    const audit = await runAudit({ meta: baseMeta("x", "1.0.0"), tarball: tgz });
    const f = audit.findings.find((x) => x.ruleId === "content-mismatch");
    assert.ok(f, "expected a content-mismatch finding");
    assert.equal(f!.severity, "medium");
  });

  test("gzip-only behind .js → low content-mismatch finding", async () => {
    const gz = gzipSync(Buffer.from("y".repeat(80)));
    const tgz = await makeTgzBinary({
      "package/package.json": Buffer.from(JSON.stringify({ name: "y", version: "1.0.0" })),
      "package/asset.js": gz,
    });
    const audit = await runAudit({ meta: baseMeta("y", "1.0.0"), tarball: tgz });
    const f = audit.findings.find((x) => x.ruleId === "content-mismatch");
    assert.equal(f!.severity, "low");
  });
});
```

If `makeTgzBinary` / `baseMeta` are not already in `audit.test.ts`, add `makeTgzBinary` (copy from Task 2) and a `baseMeta` helper:
```ts
function baseMeta(name: string, version: string) {
  return { name, version, author: null, maintainers: [], license: null, hasInstallScripts: false, integrity: null };
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/core/test/audit.test.ts`
Expected: FAIL — no `content-mismatch` finding.

- [ ] **Step 3: Add the type + extend AuditInput**

In `types.ts`, add after `ContentMismatchEntry`:
```ts
/** Policy-independent facts observed during extraction, passed to rules (ADR-0049). */
export interface ExtractionObservations {
  contentMismatch: ContentMismatchEntry[];
  contentMismatchTotals: { count: number; byKind: Record<string, number> };
  unscannedTotals: { count: number; native: number; bytes: number };
}
```
In `AuditInput` (around line 178), add:
```ts
  /** Facts from the extractor (content mismatch, unscanned totals) — ADR-0049. Absent ⇒ rules see none. */
  extractionObservations?: ExtractionObservations;
```

- [ ] **Step 4: Thread + synthesize in `audit.ts`**

(a) Extend `buildAudit`'s `opts` (line 41) with `extractionObservations?: ExtractionObservations;` and pass it into the `input` object (line 50):
```ts
  const input: AuditInput = { meta, files, mode: opts.mode, releaseContext: opts.releaseContext, advisories: opts.advisories, vulnerabilities: opts.vulnerabilities, extractionObservations: opts.extractionObservations };
```
Import `ExtractionObservations` in the type import block.

(b) In `runAudit`, build the observations object from `extracted` and pass to `buildAudit` (line 145):
```ts
  const extractionObservations = {
    contentMismatch: extracted.contentMismatch,
    contentMismatchTotals: extracted.contentMismatchTotals,
    unscannedTotals: extracted.unscannedTotals,
  };
  const audit = buildAudit(meta, extracted.files, { mode, durationMs: Date.now() - started, baselineCapabilities, releaseContext: input.releaseContext, advisories: input.advisories, vulnerabilities: input.vulnerabilities, extractionObservations });
```

(c) Synthesize the finding after the `unscanned-content` block (~line 176), before `if (prov.rootStale)`:
```ts
  if (extracted.contentMismatchTotals.count > 0) {
    const EXEC = new Set(["elf", "macho", "pe", "wasm"]);
    const kinds = Object.keys(extracted.contentMismatchTotals.byKind);
    const anyExec = kinds.some((k) => EXEC.has(k));
    const sample = extracted.contentMismatch.slice(0, 3).map((e) => ({ file: e.path, snippet: `${e.detectedKind} bytes behind ${e.declaredExt}` }));
    audit.findings.push({
      ruleId: "content-mismatch", category: "metadata",
      severity: anyExec ? "medium" : "low",
      message: `${extracted.contentMismatchTotals.count} file(s) have binary/compressed content behind a text-looking extension (${kinds.join(", ")}) — possible concealed payload container`,
      onChangedFile: false, evidence: sample,
    });
  }
```

- [ ] **Step 5: Run test + build**

Run: `npx tsx --test packages/core/test/audit.test.ts` → PASS.
Run (repo root): `npm run build` → clean (this resolves the ExtractResult consumer from Task 2).

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/types.ts packages/core/src/audit.ts packages/core/test/audit.test.ts
git commit -m "feat(core): ExtractionObservations channel + content-mismatch finding"
```

---

## Task 4: Loader-chain analyzer (acorn parse + primitives + bounded dataflow)

**Files:**
- Modify: `packages/core/package.json` (add `acorn`, `acorn-walk`)
- Create: `packages/core/src/detect/loader-chain.ts`
- Test: `packages/core/test/loader-chain.test.ts`

**Interfaces:**
- Produces:
  - `interface LoaderPrimitive { stage: "read" | "decode" | "write" | "launch"; line: number; snippet: string }`
  - `interface LoaderBoosters { tempOrHidden: boolean; chmod: boolean; detached: boolean; unref: boolean; moduleLoad: boolean }`
  - `interface LoaderAnalysis { primitives: LoaderPrimitive[]; correlated: boolean; boosters: LoaderBoosters; parseFailed: boolean }`
  - `function analyzeLoaderChain(source: string, opts?: { moduleLoadReachable?: boolean }): LoaderAnalysis` — `moduleLoadReachable` is the entry/bin hint from the rule; the analyzer separately confirms top-level/IIFE execution.
  - `correlated` is true only when a launched target is taint-reachable from a packaged read through decode→write (bounded local dataflow, alias-following).

- [ ] **Step 1: Write the failing test**

```ts
// packages/core/test/loader-chain.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { analyzeLoaderChain } from "../src/detect/loader-chain.js";

const LOADER = `
const fs = require('fs');
const zlib = require('zlib');
const cp = require('child_process');
const os = require('os');
const path = require('path');
(function () {
  const container = fs.readFileSync(path.join(__dirname, 'intro.js'));
  const bin = zlib.gunzipSync(container.subarray(5));
  const out = path.join(os.tmpdir(), '.' + Math.random().toString(36).slice(2));
  fs.writeFileSync(out, bin);
  fs.chmodSync(out, 0o755);
  const child = cp.spawn(out, [], { detached: true, stdio: 'ignore' });
  child.unref();
})();
`;

describe("analyzeLoaderChain", () => {
  test("full correlated chain → correlated true, all four stages, boosters set", () => {
    const a = analyzeLoaderChain(LOADER, { moduleLoadReachable: true });
    assert.equal(a.parseFailed, false);
    assert.equal(a.correlated, true);
    const stages = new Set(a.primitives.map((p) => p.stage));
    for (const s of ["read", "decode", "write", "launch"]) assert.ok(stages.has(s as any), `missing ${s}`);
    assert.equal(a.boosters.tempOrHidden, true);
    assert.equal(a.boosters.chmod, true);
    assert.equal(a.boosters.detached, true);
    assert.equal(a.boosters.unref, true);
    assert.equal(a.boosters.moduleLoad, true);
  });

  test("disconnected primitives (spawn a fixed system binary, unrelated gzip) → NOT correlated", () => {
    const src = `
      const fs = require('fs'); const zlib = require('zlib'); const cp = require('child_process');
      const data = fs.readFileSync('input.txt');
      const packed = zlib.gzipSync(data);           // compress OUTPUT, not decode a payload
      fs.writeFileSync('out.gz', packed);
      cp.execFileSync('/usr/bin/git', ['status']);   // launches a fixed binary, not the written file
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, false, "no dataflow link from read→launch");
  });

  test("child_process alone → not correlated, no false chain", () => {
    const a = analyzeLoaderChain(`const cp=require('child_process'); cp.exec('ls');`);
    assert.equal(a.correlated, false);
  });

  test("TypeScript syntax → parseFailed true (caller uses regex fallback)", () => {
    const a = analyzeLoaderChain(`const x: number = 1; export const y = x;`);
    assert.equal(a.parseFailed, true);
  });

  test("launch of the written path but WITHOUT decode → not correlated (caps below critical)", () => {
    const src = `
      const fs=require('fs'); const cp=require('child_process'); const os=require('os'); const path=require('path');
      const out = path.join(os.tmpdir(), 'x');
      fs.writeFileSync(out, fs.readFileSync(path.join(__dirname,'blob.bin')));
      cp.spawn(out);
    `;
    const a = analyzeLoaderChain(src);
    // read→write→launch present but no DECODE stage between → correlated stays false
    assert.equal(a.correlated, false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/core/test/loader-chain.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Add dependencies**

In `packages/core/package.json` `dependencies`, add (keep alphabetical where the file is):
```json
    "acorn": "^8.14.0",
    "acorn-walk": "^8.3.4",
```
Run: `npm install` (repo root) to populate the workspace.

- [ ] **Step 4: Write the analyzer**

```ts
// packages/core/src/detect/loader-chain.ts
import * as acorn from "acorn";
import * as walk from "acorn-walk";

export interface LoaderPrimitive { stage: "read" | "decode" | "write" | "launch"; line: number; snippet: string }
export interface LoaderBoosters { tempOrHidden: boolean; chmod: boolean; detached: boolean; unref: boolean; moduleLoad: boolean }
export interface LoaderAnalysis { primitives: LoaderPrimitive[]; correlated: boolean; boosters: LoaderBoosters; parseFailed: boolean }

const READ_FNS = new Set(["readFile", "readFileSync", "createReadStream"]);
const DECODE_FNS = new Set(["gunzip", "gunzipSync", "inflate", "inflateSync", "inflateRaw", "inflateRawSync", "brotliDecompress", "brotliDecompressSync", "unzip", "unzipSync"]);
const WRITE_FNS = new Set(["writeFile", "writeFileSync", "createWriteStream", "cp", "cpSync", "copyFile", "copyFileSync"]);
const LAUNCH_FNS = new Set(["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync"]);

/** Bounded, deterministic taint tags a variable can carry. */
type Tag = "read" | "decoded" | "written-path";

function calleeName(node: any): string | null {
  if (node.type === "MemberExpression" && node.property?.type === "Identifier") return node.property.name;
  if (node.type === "Identifier") return node.name;
  return null;
}
function lineOf(src: string, pos: number): number { return src.slice(0, pos).split("\n").length; }
function snip(src: string, node: any): string {
  const s = src.slice(node.start, node.end).replace(/\s+/g, " ");
  return s.length > 160 ? s.slice(0, 159) + "…" : s;
}
/** Names referenced by identifiers anywhere inside a node (bounded read of the subtree). */
function idsIn(node: any): Set<string> {
  const out = new Set<string>();
  walk.full(node, (n: any) => { if (n.type === "Identifier") out.add(n.name); });
  return out;
}

/**
 * Analyze a JS source for a packaged-payload materialization chain. `correlated`
 * requires bounded local dataflow: a launched target taint-reachable from a
 * packaged READ through DECODE then WRITE, following simple assignments/aliases.
 * Parse failure (TS/JSX/other non-JS) → parseFailed:true; the caller falls back
 * to a regex signal capped below critical.
 */
export function analyzeLoaderChain(source: string, opts: { moduleLoadReachable?: boolean } = {}): LoaderAnalysis {
  let ast: any;
  try {
    ast = acorn.parse(source, { ecmaVersion: "latest", sourceType: "module", allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, allowHashBang: true });
  } catch {
    try {
      ast = acorn.parse(source, { ecmaVersion: "latest", sourceType: "script", allowReturnOutsideFunction: true, allowHashBang: true });
    } catch {
      return { primitives: [], correlated: false, boosters: { tempOrHidden: false, chmod: false, detached: false, unref: false, moduleLoad: false }, parseFailed: true };
    }
  }

  const primitives: LoaderPrimitive[] = [];
  const taint = new Map<string, Set<Tag>>();          // var name -> tags
  const addTag = (name: string, t: Tag) => { (taint.get(name) ?? taint.set(name, new Set()).get(name)!).add(t); };
  const hasTag = (names: Set<string>, t: Tag): boolean => [...names].some((n) => taint.get(n)?.has(t));

  const boosters: LoaderBoosters = { tempOrHidden: false, chmod: false, detached: false, unref: false, moduleLoad: false };
  let sawDecode = false;
  let correlated = false;

  // Pass 1: propagate simple aliases `const a = b;` so tags flow across copies.
  // Bounded: one linear pass over declarations + assignments; the classifier
  // passes below re-read tags as they are set in source order.
  const record = (stage: LoaderPrimitive["stage"], node: any) =>
    primitives.push({ stage, line: lineOf(source, node.start), snippet: snip(source, node) });

  const isTempOrHidden = (node: any): boolean => {
    const txt = source.slice(node.start, node.end);
    return /tmpdir\s*\(\s*\)|['"`]\/tmp\b|['"`]\.[A-Za-z0-9_]/.test(txt) || /os\.tmpdir/.test(txt);
  };

  walk.ancestor(ast, {
    VariableDeclarator(node: any) {
      if (!node.id || node.id.type !== "Identifier" || !node.init) return;
      const name = node.id.name;
      // alias copy
      if (node.init.type === "Identifier") {
        for (const t of taint.get(node.init.name) ?? []) addTag(name, t);
      }
      if (node.init.type === "CallExpression") {
        const fn = calleeName(node.init.callee);
        const args = node.init.arguments ?? [];
        if (fn && READ_FNS.has(fn)) { record("read", node.init); addTag(name, "read"); }
        else if (fn && DECODE_FNS.has(fn)) {
          if (args.some((a: any) => hasTag(idsIn(a), "read"))) { record("decode", node.init); sawDecode = true; addTag(name, "decoded"); }
          else { record("decode", node.init); sawDecode = true; }
        }
      }
    },
    CallExpression(node: any) {
      const fn = calleeName(node.callee);
      if (!fn) return;
      const args = node.arguments ?? [];
      if (READ_FNS.has(fn) && node.callee.type === "MemberExpression") {
        // reads not captured into a var still count as a READ primitive
        if (!primitives.some((p) => p.stage === "read" && p.line === lineOf(source, node.start))) record("read", node);
      } else if (DECODE_FNS.has(fn)) {
        if (!primitives.some((p) => p.stage === "decode" && p.line === lineOf(source, node.start))) { record("decode", node); sawDecode = true; }
      } else if (WRITE_FNS.has(fn)) {
        // writeFile(path, data): if data is decoded (or read) AND a decode happened,
        // tag the path expression's identifiers as written-path.
        const [pathArg, dataArg] = args;
        record("write", node);
        const dataTainted = dataArg ? (hasTag(idsIn(dataArg), "decoded") || hasTag(idsIn(dataArg), "read")) : false;
        if (pathArg && sawDecode && dataTainted) {
          if (pathArg.type === "Identifier") addTag(pathArg.name, "written-path");
          for (const id of idsIn(pathArg)) addTag(id, "written-path");
        }
        if (pathArg && isTempOrHidden(pathArg)) boosters.tempOrHidden = true;
      } else if (fn === "chmod" || fn === "chmodSync") {
        boosters.chmod = true;
        record("write", node);
      } else if (LAUNCH_FNS.has(fn)) {
        record("launch", node);
        const target = args[0];
        if (target && hasTag(idsIn(target), "written-path")) correlated = true;
        // detached / ignored-stdio booster
        const optsArg = args.find((a: any) => a?.type === "ObjectExpression");
        if (optsArg) {
          for (const prop of optsArg.properties ?? []) {
            const key = prop.key?.name ?? prop.key?.value;
            if (key === "detached" && prop.value?.value === true) boosters.detached = true;
            if (key === "stdio" && prop.value?.value === "ignore") boosters.detached = true;
          }
        }
      } else if (fn === "unref") {
        boosters.unref = true;
      } else if (fn === "dlopen") {
        // process.dlopen(module, path): only a LAUNCH when path references written output.
        record("launch", node);
        const target = args[1];
        if (target && hasTag(idsIn(target), "written-path")) correlated = true;
      }
    },
  });

  // Module-load reachability booster: chain sits at Program top level or inside a
  // top-level IIFE, AND the caller says the file is entry/bin reachable.
  boosters.moduleLoad = Boolean(opts.moduleLoadReachable) && topLevelExecution(ast);

  return { primitives, correlated, boosters, parseFailed: false };
}

/** True when the program has top-level statements or a top-level IIFE (executes on import). */
function topLevelExecution(ast: any): boolean {
  for (const stmt of ast.body ?? []) {
    if (stmt.type === "ExpressionStatement") {
      const e = stmt.expression;
      if (e?.type === "CallExpression") return true;          // top-level call / IIFE
      if (e?.type === "AssignmentExpression") return true;
    }
  }
  return false;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx tsx --test packages/core/test/loader-chain.test.ts`
Expected: PASS. If the `disconnected` or `no-decode` cases fail, the taint gate (`sawDecode && dataTainted` before tagging `written-path`, and `correlated` only on `written-path` launch target) is the control — do not loosen it.

- [ ] **Step 6: Commit**

```bash
git add packages/core/package.json package-lock.json packages/core/src/detect/loader-chain.ts packages/core/test/loader-chain.test.ts
git commit -m "feat(core): acorn loader-chain analyzer with bounded dataflow correlation"
```

---

## Task 5: `native-payload-loader` rule (entry resolution, severity, regex fallback, registration)

**Files:**
- Create: `packages/core/src/rules/native-payload-loader.ts`
- Modify: `packages/core/src/rules/index.ts`
- Test: `packages/core/test/native-payload-loader.test.ts`

**Interfaces:**
- Consumes: `analyzeLoaderChain` (Task 4), `AuditInput.extractionObservations` (Task 3), `codeFiles`/`mkFinding` (`rules/util.ts`).
- Produces: `export const nativePayloadLoaderRule: Rule` (`id: "native-payload-loader"`, `category: "install-script"`). Registered in `RULES`.
- Severity contract:
  - `correlated` chain → **critical**.
  - All four stages present but not correlated, OR parse-failed regex fallback with ≥2 stages → **high** (never critical).
  - Two-or-three stages, not correlated → **medium**.

- [ ] **Step 1: Write the failing test**

```ts
// packages/core/test/native-payload-loader.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { nativePayloadLoaderRule } from "../src/rules/native-payload-loader.js";
import type { AuditInput, PackageFile } from "../src/types.js";

function input(files: Record<string, string>, pkgJson: object): AuditInput {
  const list: PackageFile[] = Object.entries(files).map(([path, content]) => ({ path, content, size: content.length, changed: false }));
  list.push({ path: "package/package.json", content: JSON.stringify(pkgJson), size: 0, changed: false });
  return { meta: { name: "p", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, signature: "unknown", provenance: "unknown", integrity: null, unpackedSize: 0, fileCount: 0 }, files: list, mode: "full" };
}

const CORRELATED = `
const fs=require('fs'),zlib=require('zlib'),cp=require('child_process'),os=require('os'),path=require('path');
(function(){
  const c=fs.readFileSync(path.join(__dirname,'intro.js'));
  const b=zlib.gunzipSync(c.subarray(5));
  const out=path.join(os.tmpdir(),'.'+Math.random().toString(36).slice(2));
  fs.writeFileSync(out,b); fs.chmodSync(out,0o755);
  const ch=cp.spawn(out,[],{detached:true,stdio:'ignore'}); ch.unref();
})();`;

describe("nativePayloadLoaderRule", () => {
  test("correlated chain in the main entry → critical", () => {
    const f = nativePayloadLoaderRule.run(input({ "package/index.js": CORRELATED }, { name: "p", version: "1.0.0", main: "index.js" }));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.severity, "critical");
    assert.match(f[0]!.message, /read|decode|write|launch/i);
  });

  test("correlated chain in a bin entry → critical", () => {
    const f = nativePayloadLoaderRule.run(input({ "package/bin/cli.js": CORRELATED }, { name: "p", version: "1.0.0", bin: { p: "bin/cli.js" } }));
    assert.equal(f[0]!.severity, "critical");
  });

  test("full mode, no baseline still critical (no diff dependency)", () => {
    const f = nativePayloadLoaderRule.run(input({ "package/index.js": CORRELATED }, { name: "p", version: "1.0.0", main: "index.js" }));
    assert.equal(f[0]!.severity, "critical");
  });

  test("benign build tool (read+gzip+write+spawn fixed binary, no link) → no critical", () => {
    const src = `const fs=require('fs'),zlib=require('zlib'),cp=require('child_process');
      const d=fs.readFileSync('in'); fs.writeFileSync('out.gz', zlib.gzipSync(d)); cp.execFileSync('/usr/bin/tar',['-c']);`;
    const f = nativePayloadLoaderRule.run(input({ "package/build.js": src }, { name: "p", version: "1.0.0" }));
    assert.ok(!f.some((x) => x.severity === "critical"), "benign build tool must not be critical");
  });

  test("TypeScript source with loader keywords → regex fallback, capped below critical", () => {
    const ts = `const out: string = tmp(); fs.writeFileSync(out, gunzipSync(fs.readFileSync(p))); spawn(out,{detached:true});`;
    const f = nativePayloadLoaderRule.run(input({ "package/index.ts": ts }, { name: "p", version: "1.0.0", main: "index.ts" }));
    assert.ok(!f.some((x) => x.severity === "critical"), "parse-failed fallback never critical");
  });

  test("throwing input never crashes (returns array)", () => {
    assert.doesNotThrow(() => nativePayloadLoaderRule.run(input({}, {})));
  });

  test("diff-mode: loader on a CHANGED file → finding flagged onChangedFile (acceptance #6)", () => {
    const inp = input({ "package/index.js": CORRELATED }, { name: "p", version: "2.0.0", main: "index.js" });
    // simulate diff-mode: the loader file is newly changed vs the benign predecessor
    for (const f of inp.files) if (f.path === "package/index.js") f.changed = true;
    inp.mode = "diff";
    const f = nativePayloadLoaderRule.run(inp);
    assert.equal(f[0]!.severity, "critical");
    assert.equal(f[0]!.onChangedFile, true, "newly-introduced loader must be recognized as changed (diff multiplier applies)");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/core/test/native-payload-loader.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the rule**

```ts
// packages/core/src/rules/native-payload-loader.ts
import type { AuditInput, ContentMismatchEntry, Evidence, Finding, PackageFile, Rule } from "../types.js";
import { codeFiles, mkFinding, truncate } from "./util.js";
import { analyzeLoaderChain } from "../detect/loader-chain.js";

/** Regex signals for the parse-failure fallback. Detect independently; NEVER claim dataflow. */
const FALLBACK = {
  read: /\b(readFileSync|readFile|createReadStream)\s*\(/,
  decode: /\b(gunzip|inflate|brotliDecompress|unzip)\w*\s*\(|Buffer\.from\([^)]*['"]base64['"]/,
  write: /\b(writeFileSync|writeFile|createWriteStream)\s*\(/,
  launch: /\b(spawn|spawnSync|exec|execSync|execFile|execFileSync)\s*\(|process\.dlopen\s*\(/,
};

/** Resolve entry-reachable file paths from package.json (main/bin/exports strings). No full Node resolution. */
function entryPaths(pkgJson: any): Set<string> {
  const out = new Set<string>();
  const add = (v: unknown) => { if (typeof v === "string") out.add(norm(v)); };
  add(pkgJson?.main);
  if (typeof pkgJson?.bin === "string") add(pkgJson.bin);
  else if (pkgJson?.bin && typeof pkgJson.bin === "object") for (const v of Object.values(pkgJson.bin)) add(v);
  const exp = pkgJson?.exports;
  const collect = (e: any) => {
    if (typeof e === "string") add(e);
    else if (e && typeof e === "object") for (const v of Object.values(e)) collect(v);
  };
  if (exp !== undefined) collect(exp);
  if (out.size === 0) out.add("index.js"); // node default
  return out;
}
function norm(p: string): string { return p.replace(/^\.\//, "").replace(/^\//, ""); }

export const nativePayloadLoaderRule: Rule = {
  id: "native-payload-loader",
  category: "install-script",
  run(input: AuditInput): Finding[] {
    let pkgJson: any = {};
    const pj = input.files.find((f) => f.path === "package/package.json");
    if (pj) { try { pkgJson = JSON.parse(pj.content); } catch { pkgJson = {}; } }
    const entries = entryPaths(pkgJson);
    const mismatchByFile = new Map<string, ContentMismatchEntry[]>();
    for (const m of input.extractionObservations?.contentMismatch ?? []) {
      (mismatchByFile.get(m.path) ?? mismatchByFile.set(m.path, []).get(m.path)!).push(m);
    }

    const findings: Finding[] = [];
    for (const file of codeFiles(input)) {
      const rel = file.path.replace(/^package\//, "");
      const reachable = [...entries].some((e) => rel === e || rel.endsWith(`/${e}`) || e.endsWith(`/${rel}`));
      const a = analyzeLoaderChain(file.content, { moduleLoadReachable: reachable });

      if (a.parseFailed) {
        // Regex fallback — independent signal only, capped below critical.
        const hits = (Object.keys(FALLBACK) as (keyof typeof FALLBACK)[]).filter((k) => FALLBACK[k].test(file.content));
        if (hits.length >= 2) {
          findings.push(mkFinding({
            ruleId: this.id, category: this.category, severity: "high",
            message: `Possible payload loader (unparsed source, regex signal only): ${hits.join(" + ")} in \`${rel}\` — dataflow not verified.`,
            evidence: [{ file: file.path, snippet: truncate(file.content.trim().split("\n")[0] ?? "", 120) }],
            files: input.files,
          }));
        }
        continue;
      }

      const stages = new Set(a.primitives.map((p) => p.stage));
      const allFour = ["read", "decode", "write", "launch"].every((s) => stages.has(s as any));
      const evidence: Evidence[] = a.primitives.slice(0, 6).map((p) => ({ file: file.path, line: p.line, snippet: p.snippet }));
      const boosterList = Object.entries(a.boosters).filter(([, v]) => v).map(([k]) => k);
      const mism = mismatchByFile.size > 0; // a disguised container anywhere in the package strengthens the chain

      if (a.correlated) {
        findings.push(mkFinding({
          ruleId: this.id, category: this.category, severity: "critical",
          message: `Native-payload loader chain in \`${rel}\`: packaged read → decode → write → launch of the written file are dataflow-linked${boosterList.length ? ` (${boosterList.join(", ")}${mism ? ", content-mismatch" : ""})` : ""}.`,
          evidence, files: input.files,
        }));
      } else if (allFour) {
        findings.push(mkFinding({
          ruleId: this.id, category: this.category, severity: "high",
          message: `\`${rel}\` contains read+decode+write+launch primitives but no verified dataflow link — possible loader.`,
          evidence, files: input.files,
        }));
      } else if (stages.size >= 2) {
        findings.push(mkFinding({
          ruleId: this.id, category: this.category, severity: "medium",
          message: `\`${rel}\` combines ${[...stages].join(" + ")} primitives — partial materialization pattern.`,
          evidence, files: input.files,
        }));
      }
    }
    return findings;
  },
};
```

- [ ] **Step 4: Register the rule**

In `packages/core/src/rules/index.ts`, import and add `nativePayloadLoaderRule` to the `RULES` array and the re-export block:
```ts
import { nativePayloadLoaderRule } from "./native-payload-loader.js";
```
Add `nativePayloadLoaderRule,` to both `export const RULES` and the `export { ... }` list.

- [ ] **Step 5: Run test + build + full suite**

Run: `npx tsx --test packages/core/test/native-payload-loader.test.ts` → PASS.
Run (repo root): `npm run build` → clean.
Run: `npm test` → green. **Watch for any benign fixture whose verdict moved** (see Task 6 — that is a false-positive bug, not a snapshot to update).

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/rules/native-payload-loader.ts packages/core/src/rules/index.ts packages/core/test/native-payload-loader.test.ts
git commit -m "feat(core): native-payload-loader rule (dataflow-correlated critical + fallback)"
```

---

## Task 6: Synthetic fixtures + generator + fixture-invariant docs

**Files:**
- Create: `fixtures/malicious/payload-loader-preinstall/1.0.0/package/{package.json,dist/setup.js}` + `SYNTHETIC-FIXTURE.txt`
- Create: `fixtures/malicious/payload-loader-entry/1.0.0/package/{package.json,index.js}` + `SYNTHETIC-FIXTURE.txt`
- Create: `fixtures/malicious/payload-loader-bin/1.0.0/package/{package.json,bin/cli.js}` + `SYNTHETIC-FIXTURE.txt`
- Create: `fixtures/benign/loader-lookalike/1.0.0/package/{package.json,build.js}` (build tool, no link)
- Create: `fixtures/malicious/payload-loader-entry/1.0.0/package/dist/intro.js.asset` (hex descriptor — see below)
- Modify: `fixtures/index.json` (register the four packages + expects)
- Modify: `scripts/make-fixtures.ts` (materialize disguised binary assets from `*.asset` hex descriptors before packing)
- Modify: `CLAUDE.md` (fixture-safety rules: out-of-band marking for signature assets)
- Test: `packages/core/test/payload-loader-fixtures.test.ts`

**Interfaces:**
- Consumes: `auditTarball` / `runAudit` from core; `tarball(name, version)` + `ensureFixtures()` from `test/helpers.ts`.
- Produces: fixture tarballs whose audits are asserted (`payload-loader-*` → block; `loader-lookalike` → allow).

- [ ] **Step 1: Write the fixtures**

`fixtures/malicious/payload-loader-preinstall/1.0.0/package/package.json`:
```json
{
  "name": "payload-loader-preinstall",
  "version": "1.0.0",
  "description": "SYNTHETIC FIXTURE — Gen-1 preinstall loader. Inert. Never executed.",
  "scripts": { "preinstall": "node dist/setup.js" },
  "license": "MIT"
}
```
`.../dist/setup.js`:
```js
// SYNTHETIC FIXTURE — inert Gen-1 loader body. Scored as text, never executed.
const fs = require('fs'), zlib = require('zlib'), cp = require('child_process'), os = require('os'), path = require('path');
const container = fs.readFileSync(path.join(__dirname, 'intro.js'));
const bin = zlib.gunzipSync(container.subarray(5));
const out = path.join(os.tmpdir(), '.' + Math.random().toString(36).slice(2));
fs.writeFileSync(out, bin);
fs.chmodSync(out, 0o755);
const child = cp.spawn(out, [], { detached: true, stdio: 'ignore' });
child.unref();
```
`payload-loader-entry/.../package.json` (`"main": "index.js"`, no scripts) and `index.js` = the same inert loader body wrapped in a top-level IIFE (`(function(){ ... })();`) with a `// SYNTHETIC FIXTURE` header.
`payload-loader-bin/.../package.json` (`"bin": { "ldr": "bin/cli.js" }`, no scripts) and `bin/cli.js` = same inert IIFE loader with header.
`benign/loader-lookalike/.../package.json` (`"main": "build.js"`) and `build.js`:
```js
// SYNTHETIC FIXTURE — benign build tool: compresses OUTPUT and runs a fixed system binary.
const fs = require('fs'), zlib = require('zlib'), cp = require('child_process');
const data = fs.readFileSync('src/index.js');
fs.writeFileSync('dist/index.js.gz', zlib.gzipSync(data));
cp.execFileSync('/usr/bin/tar', ['-czf', 'dist.tgz', 'dist']);
```

Disguised container descriptor `payload-loader-entry/1.0.0/package/dist/intro.js.asset`:
```
gzip
```
(A one-word file naming the signature family; the generator materializes `dist/intro.js` as the real magic bytes + inert filler at build time, so no raw binary is committed.)

`SYNTHETIC-FIXTURE.txt` (one per malicious fixture dir), e.g. for `payload-loader-entry`:
```
SYNTHETIC FIXTURE — inert, never executed.
dist/intro.js is generated by scripts/make-fixtures.ts from dist/intro.js.asset (family: gzip):
real magic-header bytes + inert zero filler. Contains no runnable payload.
Purpose: exercise content/extension-mismatch classification behind a .js extension.
```

- [ ] **Step 2: Teach the generator to materialize `.asset` descriptors**

In `scripts/make-fixtures.ts`, before `tar.create` (line 119), materialize any `*.asset` files in the version's `package/` tree into their real bytes:
```ts
import { classifyContent } from "../packages/core/src/detect/magic.js"; // (type-only usage not required; see below)
// Minimal magic table for fixture synthesis (kept local; deterministic).
const FAMILY_MAGIC: Record<string, number[]> = {
  gzip: [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00],
  elf: [0x7f, 0x45, 0x4c, 0x46],
  macho: [0xfe, 0xed, 0xfa, 0xcf],
};
function materializeAssets(pkgDir: string): void {
  const walk = (d: string) => {
    for (const name of readdirSync(d)) {
      const full = join(d, name);
      if (statSync(full).isDirectory()) { walk(full); continue; }
      if (!name.endsWith(".asset")) continue;
      const family = readFileSync(full, "utf8").trim();
      const magic = FAMILY_MAGIC[family];
      if (!magic) throw new Error(`unknown fixture asset family: ${family} in ${full}`);
      const target = full.replace(/\.asset$/, "");            // dist/intro.js.asset -> dist/intro.js
      writeFileSync(target, Buffer.concat([Buffer.from(magic), Buffer.alloc(2048, 0x00)]));
    }
  };
  walk(pkgDir);
}
```
Call `materializeAssets(join(versionDir, "package"))` immediately before `tar.create`. Add `dist/intro.js` and other materialized outputs to `.gitignore` under `fixtures/` (they are generated), keeping only the `.asset` descriptor + manifest in git.

Append to `fixtures/.gitignore` (create if absent):
```
# generated disguised-container assets (materialized from *.asset by make-fixtures)
**/dist/intro.js
```

- [ ] **Step 3: Register in `fixtures/index.json`**

Add under `"packages"`:
```json
    "payload-loader-preinstall": { "class": "malicious", "expect": { "1.0.0": "block" }, "versions": { "1.0.0": { "signature": "valid", "provenance": false } } },
    "payload-loader-entry": { "class": "malicious", "expect": { "1.0.0": "block" }, "versions": { "1.0.0": { "signature": "valid", "provenance": false } } },
    "payload-loader-bin": { "class": "malicious", "expect": { "1.0.0": "block" }, "versions": { "1.0.0": { "signature": "valid", "provenance": false } } },
    "loader-lookalike": { "class": "benign", "expect": { "verdict": "allow" }, "versions": { "1.0.0": { "signature": "valid", "provenance": false } } },
```

- [ ] **Step 4: Write the fixture test**

```ts
// packages/core/test/payload-loader-fixtures.test.ts
import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { auditTarball } from "../src/audit.js";
import { ensureFixtures, tarball } from "./helpers.js";

async function verdict(name: string, version: string): Promise<string> {
  const report = await auditTarball({ meta: { name, version, author: null, maintainers: [], license: null, hasInstallScripts: false, integrity: null }, tarball: tarball(name, version) });
  return report.verdict;
}

describe("payload-loader fixtures", () => {
  before(() => ensureFixtures());

  test("Gen-1 preinstall loader → block", async () => assert.equal(await verdict("payload-loader-preinstall", "1.0.0"), "block"));
  test("Gen-2 main-entry loader (no install script) → block", async () => assert.equal(await verdict("payload-loader-entry", "1.0.0"), "block"));
  test("Gen-2 bin-entry loader → block", async () => assert.equal(await verdict("payload-loader-bin", "1.0.0"), "block"));
  test("benign loader-lookalike build tool → allow (no false critical)", async () => assert.equal(await verdict("loader-lookalike", "1.0.0"), "allow"));
});
```

- [ ] **Step 5: Regenerate + run**

Run (repo root): `npm run fixtures` — rebuilds tarballs + `registry.json` (materializes `dist/intro.js`).
Run: `npx tsx --test packages/core/test/payload-loader-fixtures.test.ts` → PASS.
Run: `npm test` → green; confirm **no pre-existing benign fixture verdict moved**.

- [ ] **Step 6: Update the fixture invariant in `CLAUDE.md`**

In the `## Fixtures — safety rules` section, add a bullet:
```md
- **Signature assets** (files that must begin with real magic bytes to exercise
  content classification) cannot carry an in-band `SYNTHETIC FIXTURE` text header.
  They are inert raw data — magic header + zero filler — generated at build time
  by `scripts/make-fixtures.ts` from a committed `*.asset` family descriptor, and
  marked **out-of-band** by an adjacent `SYNTHETIC-FIXTURE.txt` manifest. The
  materialized binary (e.g. `dist/intro.js`) is gitignored; only the descriptor +
  manifest are committed. These assets contain no runnable payload.
```

- [ ] **Step 7: Commit**

```bash
git add fixtures/ scripts/make-fixtures.ts packages/core/test/payload-loader-fixtures.test.ts CLAUDE.md
git commit -m "test(core): synthetic Gen-1/Gen-2 loader fixtures + disguised asset generator + fixture-invariant update"
```

---

## Task 7: Proxy e2e — malicious fixture blocked (enforce) / reported (observe)

**Files:**
- Test: `packages/proxy/test/payload-loader-e2e.test.ts`

**Interfaces:**
- Consumes: the proxy test harness pattern used by existing e2e tests (`proxy.test.ts`), `LocalFixtureUpstream`, the fixtures from Task 6.

- [ ] **Step 1: Write the failing test**

Use the exact harness from `packages/proxy/test/proxy.test.ts` — a real `createServer(...)` listening on port 0, driven with `fetch`. The tarball URL is read from the rewritten packument (`doc.versions[v].dist.tarball`), not hand-built.

```ts
// packages/proxy/test/payload-loader-e2e.test.ts
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}
function startServer(proxyPolicy: "block" | "observe"): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, policy: proxyPolicy, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(),
  });
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }));
  });
}
async function tarballUrl(base: string, pkg: string, version: string): Promise<string> {
  const doc = await (await fetch(`${base}/${pkg}`)).json();
  return doc.versions[version].dist.tarball as string;
}

describe("payload-loader e2e", () => {
  before(() => ensureFixtures());

  test("block policy → payload-loader-entry tarball 403 with verdict block", async () => {
    const { server, base } = await startServer("block");
    try {
      const url = await tarballUrl(base, "payload-loader-entry", "1.0.0");
      const res = await fetch(url);
      assert.equal(res.status, 403);
      assert.equal((await res.json()).verdict, "block");
    } finally { server.close(); }
  });

  test("observe policy → serves 200 but header verdict is block", async () => {
    const { server, base } = await startServer("observe");
    try {
      const url = await tarballUrl(base, "payload-loader-entry", "1.0.0");
      const res = await fetch(url);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("x-sentinel-verdict"), "block");
    } finally { server.close(); }
  });
});
```

- [ ] **Step 2: Run test to verify it passes**

Run: `npx tsx --test packages/proxy/test/payload-loader-e2e.test.ts`
Expected: PASS (the rule from Task 5 produces the block; this test proves the serve path surfaces it in both modes).

- [ ] **Step 3: Run full suite**

Run (repo root): `npm test` → green.

- [ ] **Step 4: Commit**

```bash
git add packages/proxy/test/payload-loader-e2e.test.ts
git commit -m "test(proxy): payload-loader blocked in enforce, reported in observe"
```

---

## Task 8: ADR-0049 + architecture/CLAUDE/README docs for A+B

**Files:**
- Create: `docs/adr/0049-native-payload-loader-detection.md`
- Modify: `docs/adr/0041-review-hardening.md` (one-line pointer only), `docs/adr/README.md`, `ARCHITECTURE.md`, `CLAUDE.md`, `README.md`

- [ ] **Step 1: Write ADR-0049**

Create `docs/adr/0049-native-payload-loader-detection.md` following the format of a neighbor ADR (open `docs/adr/0041-review-hardening.md` for the exact heading/status structure). Status: `Accepted`. Content covers: the two-generation threat; raw-byte magic classification (bounded 512-byte prefix, PE/ZIP validation, ambiguous `cafebabe`/`mz`); the `ExtractionObservations` channel; the acorn dataflow-correlated `native-payload-loader` rule (critical only on correlation, high/medium otherwise, regex fallback capped below critical, fail-open); the new invariant (verbatim from spec §1); and an **"Extends ADR-0041"** line. State that the LLM/wall-clock invariants are untouched.

- [ ] **Step 2: Pointer in ADR-0041**

Add a single line at the end of `docs/adr/0041-review-hardening.md` (do not otherwise modify it):
```md
> Extended by [ADR-0049](0049-native-payload-loader-detection.md): raw-byte magic classification closes the disguised-container blind spot noted here.
```

- [ ] **Step 3: Index + ARCHITECTURE + CLAUDE + README**

- `docs/adr/README.md`: add the `0049` row to the index table.
- `ARCHITECTURE.md`: in the scoring/rules section, document the `native-payload-loader` rule, the extraction magic-byte classification, and the `ExtractionObservations` channel.
- `CLAUDE.md`:
  - In **Scoring & rules**, update "9 registered pure rules" → "10 registered pure rules" and add `native-payload-loader` (ADR-0049) to the list; note `content-mismatch` as a synthesized finding (like `resource-abuse`/`unscanned-content`).
  - Add the new non-negotiable invariant (spec §1 wording) to the **Non-negotiable invariants** list.
- `README.md`: add a short "Concealed native-payload detection" subsection describing what is detected and that it is static, deterministic, and needs no advisory/baseline.

- [ ] **Step 4: Build + full suite + commit**

Run: `npm run build` && `npm test` → green (docs don't affect tests, but the `scoring is deterministic` pin and rule-count references are re-verified).
```bash
git add docs/adr/0049-native-payload-loader-detection.md docs/adr/0041-review-hardening.md docs/adr/README.md ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs: ADR-0049 + architecture/CLAUDE/README for native-payload-loader detection"
```

> **Milestone 1 complete — the zero-day is closed.** A+B are independently shippable here.

---

# MILESTONE 2 — Deliverable D (release cooldown overlay)

## Task 9: Policy `releaseCooldown` field + validation

**Files:**
- Modify: `packages/core/src/policy.ts` (`EnterprisePolicy` + `parsePolicy`)
- Test: `packages/core/test/policy.test.ts`

**Interfaces:**
- Produces: `EnterprisePolicy.releaseCooldown?: { hours: number; exempt?: string[] }`.
- Validation: `hours` finite, `> 0`, `<= 8760` (one year); `exempt` (if present) an array of strings. Malformed ⇒ `parsePolicy` throws (fail-closed at startup).

- [ ] **Step 1: Write the failing test**

```ts
// append to packages/core/test/policy.test.ts
describe("releaseCooldown policy field", () => {
  const base = { schema: 1, version: "t", scoring: { severityWeight: { info:0, low:4, medium:12, high:25, critical:55 }, diffMultiplier: 1.6, thresholds: { allow: 80, warn: 50 }, hardBlockSeverity: "critical" } };
  const parse = (extra: object) => parsePolicy(Buffer.from(JSON.stringify({ ...base, ...extra })));
  test("valid cooldown parses", () => {
    const p = parse({ releaseCooldown: { hours: 72, exempt: ["@acme/*"] } });
    assert.deepEqual(p.releaseCooldown, { hours: 72, exempt: ["@acme/*"] });
  });
  test("hours must be positive", () => assert.throws(() => parse({ releaseCooldown: { hours: 0 } }), /releaseCooldown/));
  test("hours must be finite and bounded", () => assert.throws(() => parse({ releaseCooldown: { hours: 100000 } }), /releaseCooldown/));
  test("exempt must be string[]", () => assert.throws(() => parse({ releaseCooldown: { hours: 24, exempt: [1] } }), /releaseCooldown/));
  test("absent cooldown ⇒ undefined (no behavior change)", () => assert.equal(parse({}).releaseCooldown, undefined));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/core/test/policy.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

In `EnterprisePolicy` add:
```ts
  /** Serve-time new-release cooldown (ADR-0050). Absent ⇒ disabled. Enforced in the proxy only. */
  releaseCooldown?: { hours: number; exempt?: string[] };
```
In `parsePolicy`, before the final `return`, add validation:
```ts
  const rc = (p as { releaseCooldown?: unknown }).releaseCooldown;
  if (rc !== undefined) {
    if (!rc || typeof rc !== "object") throw new Error("invalid policy: releaseCooldown must be an object");
    const h = (rc as { hours?: unknown }).hours;
    if (typeof h !== "number" || !Number.isFinite(h) || h <= 0 || h > 8760) {
      throw new Error("invalid policy: releaseCooldown.hours must be a finite number in (0, 8760]");
    }
    const ex = (rc as { exempt?: unknown }).exempt;
    if (ex !== undefined && (!Array.isArray(ex) || !ex.every((x) => typeof x === "string"))) {
      throw new Error("invalid policy: releaseCooldown.exempt must be an array of strings");
    }
  }
```
And include it in the returned object:
```ts
    ...(rc !== undefined ? { releaseCooldown: rc as EnterprisePolicy["releaseCooldown"] } : {}),
```

- [ ] **Step 4: Run test + build**

Run: `npx tsx --test packages/core/test/policy.test.ts` → PASS. `npm run build` → clean.

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/policy.ts packages/core/test/policy.test.ts
git commit -m "feat(core): releaseCooldown policy field with fail-closed validation"
```

---

## Task 10: Cooldown overlay (pure) + publish-time resolution

**Files:**
- Create: `packages/proxy/src/cooldown.ts`
- Test: `packages/proxy/test/cooldown.test.ts`

**Interfaces:**
- Consumes: `EnterprisePolicy` (`releaseCooldown`), `matchPackage`, `AuditReport`.
- Produces:
  - `function resolvePublishTime(args: { isPrivate: boolean; publicTime?: string; privatePublishedAt?: string }): string | null`
  - `function cooldownDecision(args: { policy: EnterprisePolicy; name: string; publishTime: string | null; now: number }): { block: boolean; reason?: string }` — fail-closed: matching non-exempt package with `publishTime === null` (or unparseable) ⇒ `block: true`.
  - `function applyCooldown(report: AuditReport, decision: { block: boolean; reason?: string }): AuditReport` — immutable overlay; injects a `ruleId: "release-cooldown"` finding and forces `verdict: "block"` when blocking. Cached score untouched.

- [ ] **Step 1: Write the failing test**

```ts
// packages/proxy/test/cooldown.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { cooldownDecision, resolvePublishTime, applyCooldown } from "../src/cooldown.js";
import type { EnterprisePolicy, AuditReport } from "@sentinel/core";

const NOW = Date.parse("2026-07-12T00:00:00Z");
const pol = (cd?: object): EnterprisePolicy => ({ schema: 1, version: "t", scoring: { severityWeight: { info:0,low:4,medium:12,high:25,critical:55 }, diffMultiplier:1.6, thresholds:{allow:80,warn:50}, hardBlockSeverity:"critical" }, rules:{disabled:[]}, allow:[], deny:[], privateNamespaces:[], ...(cd ? { releaseCooldown: cd } : {}) } as EnterprisePolicy);

describe("cooldownDecision", () => {
  test("fresh non-exempt version → block", () => {
    const d = cooldownDecision({ policy: pol({ hours: 72 }), name: "x", publishTime: "2026-07-11T22:00:00Z", now: NOW });
    assert.equal(d.block, true);
  });
  test("version older than window → serve", () => {
    const d = cooldownDecision({ policy: pol({ hours: 72 }), name: "x", publishTime: "2026-07-01T00:00:00Z", now: NOW });
    assert.equal(d.block, false);
  });
  test("exempt package (matchPackage) bypasses even when fresh", () => {
    const d = cooldownDecision({ policy: pol({ hours: 72, exempt: ["@acme/*"] }), name: "@acme/tool", publishTime: "2026-07-11T23:00:00Z", now: NOW });
    assert.equal(d.block, false);
  });
  test("missing publish time on a matching non-exempt package → fail closed (block)", () => {
    const d = cooldownDecision({ policy: pol({ hours: 72 }), name: "x", publishTime: null, now: NOW });
    assert.equal(d.block, true);
  });
  test("no cooldown policy → never block", () => {
    assert.equal(cooldownDecision({ policy: pol(), name: "x", publishTime: null, now: NOW }).block, false);
  });
});

describe("resolvePublishTime", () => {
  test("public uses packument time", () => assert.equal(resolvePublishTime({ isPrivate: false, publicTime: "2026-01-01T00:00:00Z" }), "2026-01-01T00:00:00Z"));
  test("private uses StoredVersion.publishedAt, not packument time map", () => assert.equal(resolvePublishTime({ isPrivate: true, privatePublishedAt: "2026-02-02T00:00:00Z" }), "2026-02-02T00:00:00Z"));
  test("missing → null", () => assert.equal(resolvePublishTime({ isPrivate: false }), null));
});

describe("applyCooldown", () => {
  const rep = (): AuditReport => ({ verdict: "allow", score: 100, findings: [], meta: { integrity: "sha512-x" } } as unknown as AuditReport);
  test("block overlays verdict + finding without mutating input", () => {
    const r = rep();
    const out = applyCooldown(r, { block: true, reason: "fresh release" });
    assert.equal(out.verdict, "block");
    assert.ok(out.findings.some((f) => f.ruleId === "release-cooldown"));
    assert.equal(r.verdict, "allow", "input report must be unmutated");
  });
  test("no block → returned unchanged", () => {
    const r = rep();
    assert.equal(applyCooldown(r, { block: false }).verdict, "allow");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/proxy/test/cooldown.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```ts
// packages/proxy/src/cooldown.ts
import { matchPackage, type AuditReport, type EnterprisePolicy } from "@sentinel/core";

const HOUR_MS = 3_600_000;

/** Authoritative publish timestamp per resolution origin. Public: packument time; private: StoredVersion.publishedAt. */
export function resolvePublishTime(args: { isPrivate: boolean; publicTime?: string; privatePublishedAt?: string }): string | null {
  const t = args.isPrivate ? args.privatePublishedAt : args.publicTime;
  return t ?? null;
}

/** Decide whether the cooldown overlay blocks this version. Fail-closed on missing/unparseable time for a matching, non-exempt package. */
export function cooldownDecision(args: { policy: EnterprisePolicy; name: string; publishTime: string | null; now: number }): { block: boolean; reason?: string } {
  const cd = args.policy.releaseCooldown;
  if (!cd) return { block: false };
  if ((cd.exempt ?? []).some((p) => matchPackage(p, args.name))) return { block: false };
  const windowMs = cd.hours * HOUR_MS;
  if (args.publishTime === null) return { block: true, reason: `release-cooldown: no authoritative publish time for ${args.name}; cooldown fails closed` };
  const t = Date.parse(args.publishTime);
  if (Number.isNaN(t)) return { block: true, reason: `release-cooldown: unparseable publish time for ${args.name}; cooldown fails closed` };
  const ageMs = args.now - t;
  if (ageMs < windowMs) {
    const remainH = Math.ceil((windowMs - ageMs) / HOUR_MS);
    return { block: true, reason: `release-cooldown: version is younger than the ${cd.hours}h cooldown (~${remainH}h remaining)` };
  }
  return { block: false };
}

/** Immutable overlay: on block, prepend a release-cooldown finding and force verdict block. Cached score untouched. */
export function applyCooldown(report: AuditReport, decision: { block: boolean; reason?: string }): AuditReport {
  if (!decision.block) return report;
  const finding = {
    ruleId: "release-cooldown", category: "metadata" as const, severity: "critical" as const,
    message: decision.reason ?? "release-cooldown: held by policy", onChangedFile: false, evidence: [], weight: 0, waived: false,
  };
  return { ...report, verdict: "block", findings: [finding, ...report.findings] };
}
```

- [ ] **Step 4: Run test + build**

Run: `npx tsx --test packages/proxy/test/cooldown.test.ts` → PASS. `npm run build` → clean.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/cooldown.ts packages/proxy/test/cooldown.test.ts
git commit -m "feat(proxy): pure release-cooldown overlay + per-origin publish-time resolution"
```

---

## Task 11: Wire cooldown into all serve/report surfaces

**Files:**
- Modify: `packages/proxy/src/server.ts`
- Test: `packages/proxy/test/cooldown-e2e.test.ts`

**Interfaces:**
- Consumes: `resolvePublishTime`, `cooldownDecision`, `applyCooldown` (Task 10); the packument (`pm.time`) already fetched in `auditPublicUncached`; `privateStore.getVersion(pkg, version).publishedAt`.
- Adds a `ServerOptions.now?: () => number` injectable clock (default `Date.now`).

- [ ] **Step 1: Write the failing e2e test**

Reuse the Task 7 harness verbatim (imports + `ensureFixtures`), but give `startServer` two extra params — the enterprise policy and the injected clock — so the test drives the decision deterministically:

```ts
// packages/proxy/test/cooldown-e2e.test.ts
// (same imports + ensureFixtures + tarballUrl as payload-loader-e2e.test.ts)
import { parsePolicy } from "@sentinel/core";

// leftpad-lite@1.0.1 carries a fixed `time` in the fixture registry (Step 2 adds it if absent).
const PUBLISHED = "2026-07-10T00:00:00Z";
const cooldownPolicy = (exempt?: string[]) => parsePolicy(Buffer.from(JSON.stringify({
  schema: 1, version: "cd",
  scoring: { severityWeight: { info:0,low:4,medium:12,high:25,critical:55 }, diffMultiplier:1.6, thresholds:{allow:80,warn:50}, hardBlockSeverity:"critical" },
  releaseCooldown: { hours: 72, ...(exempt ? { exempt } : {}) },
})));

function startServer(opts: { policy: "block" | "observe"; enterprisePolicy: any; now: () => number }): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: opts.enterprisePolicy, policy: opts.policy, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(), now: opts.now,
  });
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }));
  });
}
const inWindow = () => Date.parse("2026-07-11T00:00:00Z");   // 24h after publish, < 72h cooldown
const pastWindow = () => Date.parse("2026-07-20T00:00:00Z"); // 10 days after publish

describe("release-cooldown e2e", () => {
  before(() => ensureFixtures());

  test("block policy + fresh version → 403 block with release-cooldown finding", async () => {
    const { server, base } = await startServer({ policy: "block", enterprisePolicy: cooldownPolicy(), now: inWindow });
    try {
      const res = await fetch(await tarballUrl(base, "leftpad-lite", "1.0.1"));
      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.verdict, "block");
      assert.ok(body.findings.some((f: any) => f.ruleId === "release-cooldown"));
    } finally { server.close(); }
  });

  test("observe policy + fresh → 200 served, header verdict block", async () => {
    const { server, base } = await startServer({ policy: "observe", enterprisePolicy: cooldownPolicy(), now: inWindow });
    try {
      const res = await fetch(await tarballUrl(base, "leftpad-lite", "1.0.1"));
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("x-sentinel-verdict"), "block");
    } finally { server.close(); }
  });

  test("preflight /-/audit matches the gate (no allow when tarball will block)", async () => {
    const { server, base } = await startServer({ policy: "block", enterprisePolicy: cooldownPolicy(), now: inWindow });
    try {
      const rep = await (await fetch(`${base}/-/audit/leftpad-lite/1.0.1`)).json();
      assert.equal(rep.verdict, "block");
    } finally { server.close(); }
  });

  test("past the window → served allow, no cooldown finding (cached score untouched)", async () => {
    const { server, base } = await startServer({ policy: "block", enterprisePolicy: cooldownPolicy(), now: pastWindow });
    try {
      const res = await fetch(await tarballUrl(base, "leftpad-lite", "1.0.1"));
      assert.equal(res.status, 200);
    } finally { server.close(); }
  });

  test("exempt pattern bypasses even when fresh", async () => {
    const { server, base } = await startServer({ policy: "block", enterprisePolicy: cooldownPolicy(["leftpad-lite"]), now: inWindow });
    try {
      const res = await fetch(await tarballUrl(base, "leftpad-lite", "1.0.1"));
      assert.equal(res.status, 200);
    } finally { server.close(); }
  });
});
```

In `fixtures/index.json`, ensure `leftpad-lite`'s `1.0.1` version carries `"time": "2026-07-10T00:00:00Z"` (add the `time` field to that version object if absent). Re-run `npm run fixtures` after editing. The injected clock — never real wall-clock — drives every assertion.

- [ ] **Step 2: Add the clock option + overlay in `gateAndSend` and report routes**

(a) In `ServerOptions` add:
```ts
  /** Injectable clock (ms) for the release-cooldown overlay. Default Date.now. */
  now?: () => number;
```
Destructure near the top of the server factory: `const now = opts.now ?? Date.now;` and import the cooldown helpers.

(b) Add a helper that computes the decision for a coordinate. Because the publish time source differs by origin, resolve it where the packument/private meta is known. Add to the server scope:
```ts
  async function cooldownFor(pkg: string, version: string): Promise<{ block: boolean; reason?: string }> {
    if (!enterprisePolicy.releaseCooldown) return { block: false };
    let publishTime: string | null = null;
    if (isClaimed(pkg, enterprisePolicy)) {
      publishTime = resolvePublishTime({ isPrivate: true, privatePublishedAt: privateStore.getVersion(pkg, version)?.publishedAt });
    } else {
      try {
        const pm = await upstream.getPackument(pkg);
        publishTime = resolvePublishTime({ isPrivate: false, publicTime: pm.time?.[version] });
      } catch { publishTime = null; }
    }
    return cooldownDecision({ policy: enterprisePolicy, name: pkg, publishTime, now: now() });
  }
```

(c) In `gateAndSend`, apply the overlay right after `applyQuarantine` — but `gateAndSend` is sync and `cooldownFor` is async. Resolve the decision at each call site and pass it in. Change `gateAndSend`'s signature to accept a precomputed `cooldown` decision:
```ts
  function gateAndSend(res: Response, pkg: string, version: string, report: AuditReport, tarball: Buffer, isPrivate: boolean, cooldown: { block: boolean; reason?: string }): Response | void {
    report = applyCooldown(applyQuarantine(report), cooldown);
    // ... rest unchanged (headers, block 403, send bytes) ...
  }
```
At the tarball route (line ~685), compute the decision before calling:
```ts
        const cd = await cooldownFor(pkg, version);
        return gateAndSend(res, pkg, version, report, tarball, priv, cd);
```

(d) Apply to report-returning routes:
- `/-/audit` route: `const cd = await cooldownFor(pkg, version); res.json(applyCooldown(report, cd));`
- `/-/explain` route: overlay the `report` before `remediate(report)` so remediation reflects the block: `const cd = await cooldownFor(pkg, version); const overlaid = applyCooldown(report, cd); const remediation = remediate(overlaid); ... res.json({ report: overlaid, remediation, lastKnownGood });`
- `/-/audit-tree`: after `const report = applyQuarantine(audited);` add `const cd = await cooldownFor(co.name, co.version); const overlaidReport = applyCooldown(report, cd);` and use `overlaidReport` for the row verdict/score.

- [ ] **Step 3: Run tests + full suite**

Run: `npx tsx --test packages/proxy/test/cooldown-e2e.test.ts` → PASS.
Run (repo root): `npm test` → green. Confirm no non-cooldown e2e regressed (cooldown is `undefined` by default, so existing tests are unaffected).

- [ ] **Step 4: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/cooldown-e2e.test.ts fixtures/index.json
git commit -m "feat(proxy): apply release-cooldown overlay across tarball/audit/explain/tree/private surfaces"
```

---

## Task 12: ADR-0050 + cooldown docs

**Files:**
- Create: `docs/adr/0050-release-cooldown-overlay.md`
- Modify: `docs/adr/README.md`, `ARCHITECTURE.md`, `CLAUDE.md`, `README.md`

- [ ] **Step 1: Write ADR-0050**

Status `Accepted`. Document: rationale (all five malicious jscrambler versions published within hours; a cooldown holds fresh releases); the serve-time overlay pattern (no wall-clock in the engine; cached score untouched); per-origin publish-time source (public packument `time` vs private `StoredVersion.publishedAt`); fail-closed on missing/unparseable time; `matchPackage` exemptions and the caveat that exemptions weaken a time-based control; surfaces covered; `SENTINEL_POLICY=block` → 403 vs observe reports. Reference the injectable clock for determinism.

- [ ] **Step 2: Index + docs**

- `docs/adr/README.md`: add the `0050` row.
- `ARCHITECTURE.md`: document the cooldown overlay alongside the quarantine overlay.
- `CLAUDE.md`: in the **Proxy** subsystem paragraph, note the `releaseCooldown` policy field + serve-time overlay; add it to the policy-fields description; note the injectable clock. In the policy/env table area, note it is policy data (not an env var).
- `README.md`: add a "Release cooldown" subsection (config example, observe-vs-block behavior, narrow-exemption caveat).

- [ ] **Step 3: Build + suite + commit**

Run: `npm run build` && `npm test` → green.
```bash
git add docs/adr/0050-release-cooldown-overlay.md docs/adr/README.md ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs: ADR-0050 + docs for release-cooldown overlay"
```

---

# MILESTONE 3 — Deliverable E (scoped `sentinel exec`)

## Task 13: Sandbox `runArgv` (no-shell, arg-boundary-preserving)

**Files:**
- Modify: `packages/sandbox/src/types.ts`, `packages/sandbox/src/seatbelt.ts`, `packages/sandbox/src/bubblewrap.ts`
- Test: `packages/sandbox/test/run-argv.test.ts`

**Interfaces:**
- Produces: `Sandbox.runArgv(file: string, args: string[], opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv; projectRoot?: string }): SandboxResult` — runs `file` with `args` **without** a shell (no `sh -c`), preserving argument boundaries; same profile + deny-set + violation classification as `run`.

- [ ] **Step 1: Write the failing test (darwin-gated, mirrors existing seatbelt effect tests)**

```ts
// packages/sandbox/test/run-argv.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { createSandbox } from "../src/index.js";

const darwin = process.platform === "darwin";
describe("Sandbox.runArgv", { skip: !darwin }, () => {
  test("runs a binary with preserved argument boundaries, no shell interpolation", () => {
    const sb = createSandbox();
    // /bin/echo receives a single arg containing a space + $(...) that a shell would expand.
    const r = sb.runArgv("/bin/echo", ["a b $(whoami)"], { cwd: process.cwd(), approved: [], homeDir: process.env.HOME! });
    assert.equal(r.exitCode, 0);
    assert.equal(r.stdout.trim(), "a b $(whoami)", "no shell expansion; boundaries preserved");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/sandbox/test/run-argv.test.ts`
Expected (darwin): FAIL — `runArgv` not a function. (On Linux the describe is skipped.)

- [ ] **Step 3: Extend the interface + implementations**

In `types.ts`, add to `Sandbox`:
```ts
  /** Run `file` with `args` under the sandbox WITHOUT a shell (execFile-style; boundaries preserved). */
  runArgv(file: string, args: string[], opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv; projectRoot?: string }): SandboxResult;
```
In `seatbelt.ts`, add `runArgv` mirroring `run`, but spawn the file directly (no `/bin/sh -c`):
```ts
  runArgv(file: string, args: string[], opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv; projectRoot?: string }): SandboxResult {
    if (process.platform !== "darwin") throw new Error(`sandbox enforcement unavailable on ${process.platform} (macOS Seatbelt required)`);
    const profile = generateProfile(opts.approved, { homeDir: opts.homeDir, cwd: opts.cwd, tmpDir: tmpdir(), nodePrefix: nodeInstallPrefix(process.execPath), projectRoot: opts.projectRoot ?? opts.cwd });
    const dir = mkdtempSync(join(tmpdir(), "sentinel-sb-"));
    const profileFile = join(dir, "profile.sb");
    writeFileSync(profileFile, profile);
    try {
      const res = spawnSync("/usr/bin/sandbox-exec", ["-f", profileFile, file, ...args], { cwd: opts.cwd, env: opts.env ?? process.env, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
      if (res.error) return { exitCode: 127, stdout: "", stderr: res.error.message };
      const result: SandboxResult = { exitCode: res.status ?? (res.signal ? 1 : 0), stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
      const denySet = computeDenySet(opts.approved, { homeDir: opts.homeDir, platform: "darwin", nodePrefix: nodeInstallPrefix(process.execPath), projectRoot: opts.projectRoot ?? opts.cwd, cwd: opts.cwd, tmpDir: tmpdir() });
      const violation = classifyViolation(result, denySet);
      return violation ? { ...result, violation } : result;
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
```
In `bubblewrap.ts`, add the analogous `runArgv` that invokes the bwrap command with `file` + `args` in place of the `sh -c cmd` tail (mirror the existing `run` there; keep the same mount/deny logic). Follow the exact bwrap argv assembly already in that file.

- [ ] **Step 4: Run test + build**

Run (darwin): `npx tsx --test packages/sandbox/test/run-argv.test.ts` → PASS. `npm run build` → clean.

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/types.ts packages/sandbox/src/seatbelt.ts packages/sandbox/src/bubblewrap.ts packages/sandbox/test/run-argv.test.ts
git commit -m "feat(sandbox): runArgv — no-shell, argument-boundary-preserving sandbox execution"
```

---

## Task 14: `sentinel exec -- <command> [args...]`

**Files:**
- Modify: `packages/cli/src/index.ts`
- Test: `packages/cli` e2e — add `packages/cli/test/exec-e2e.test.ts` (create the `test/` dir if absent; follow the async `execFile` idiom from CLAUDE.md — never `execFileSync`).

**Interfaces:**
- Consumes: `createSandbox`, `Sandbox.runArgv` (Task 13), `scrubEnv` (via `runLifecycleScripts` pattern — but here call `runArgv` directly with a scrubbed env), `homedir`.
- Behavior: `sentinel exec [--approve cap...] -- <file> [args...]` — no shell; args after `--` verbatim; env scrubbed identically to enforced installs; `cwd` and `projectRoot` set to `process.cwd()`.

- [ ] **Step 1: Write the failing e2e test**

```ts
// packages/cli/test/exec-e2e.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const pexec = promisify(execFile);
const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");
const darwin = process.platform === "darwin";

describe("sentinel exec", { skip: !darwin }, () => {
  test("runs a command under the sandbox with preserved arg boundaries", async () => {
    const { stdout } = await pexec("node", [CLI, "exec", "--", "/bin/echo", "a b $(whoami)"]);
    assert.match(stdout, /a b \$\(whoami\)/);
  });
  test("exits non-zero when the sandboxed command fails", async () => {
    await assert.rejects(pexec("node", [CLI, "exec", "--", "/usr/bin/false"]));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run (build CLI first): `npm run build` then `npx tsx --test packages/cli/test/exec-e2e.test.ts`
Expected (darwin): FAIL — unknown command `exec`.

- [ ] **Step 3: Implement the command**

In `packages/cli/src/index.ts`, add `scrubEnv` to the existing sandbox import (it is already exported from `packages/sandbox/src/index.ts` — no export change needed):
```ts
import { createSandbox, runLifecycleScripts, scrubEnv } from "@sentinel/sandbox";
```
Register the command (near the `run-scripts` command):
```ts
program
  .command("exec")
  .description("Run a command under the Sentinel sandbox (no shell; args after -- are passed verbatim). Protects Sentinel-mediated execution only.")
  .option("--approve <cap...>", "capabilities to approve for the command (kind:target)", [])
  .argument("<command>", "the executable to run")
  .argument("[args...]", "arguments passed verbatim to the command")
  .action((command: string, args: string[], opts: { approve: string[] }) => {
    let sandbox;
    try { sandbox = createSandbox(); } catch (e) {
      console.error(`\x1b[31msentinel: exec unavailable: ${(e as Error).message}\x1b[0m`);
      process.exit(2);
    }
    const approved = parseApprovals(opts.approve); // existing helper in index.ts (used by the run-scripts command, ~line 481)
    const env = scrubEnv(process.env, approved);
    const cwd = process.cwd();
    const r = sandbox.runArgv(command, args, { cwd, approved, homeDir: homedir(), env, projectRoot: cwd });
    if (r.stdout) process.stdout.write(r.stdout);
    if (r.stderr) process.stderr.write(r.stderr);
    process.exit(r.exitCode);
  });
```
`parseApprovals(list: string[]): Capability[]` already exists in `index.ts` (the `run-scripts` command calls it at ~line 481) — reuse it directly; do not duplicate the parsing logic.

> **Scope note to include in `--description` and README:** `exec` protects only Sentinel-mediated runs. Ordinary `require()`/import performed outside this command, and `npx foo` run directly, remain uncontained.

- [ ] **Step 4: Run test + build**

Run: `npm run build` then `npx tsx --test packages/cli/test/exec-e2e.test.ts` → PASS (darwin).
Run (repo root): `npm test` → green.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/index.ts packages/cli/test/exec-e2e.test.ts
git commit -m "feat(cli): sentinel exec — run a command under the sandbox (no shell, scoped)"
```

---

## Task 15: ADR-0051 + exec docs (with scope limits)

**Files:**
- Create: `docs/adr/0051-sandboxed-exec.md`
- Modify: `docs/adr/README.md`, `CLAUDE.md`, `README.md`

- [ ] **Step 1: Write ADR-0051**

Status `Accepted`. Document: the residual runtime gap (lifecycle scripts are sandboxed; imports/CLI runs are not); the single explicit `sentinel exec -- <cmd>` interface (no package-bin resolver in v1); no-shell + arg-boundary preservation; reuse of the approved-capability model, scrubbed env, and violation telemetry; explicit project-root/cwd; and the **scope limitation** stated plainly — it protects Sentinel-mediated runs only, `npx foo`/raw `require()` stay exposed, and this is defense-in-depth behind the registry-gate static detection (the primary, independently-sufficient control). Note the future-resolver constraint: any `npx`/package-manager support must not silently bypass the configured Sentinel registry.

- [ ] **Step 2: Index + docs**

- `docs/adr/README.md`: add the `0051` row.
- `CLAUDE.md`: in the **CLI / CI / MCP** paragraph, add `exec` to the `sentinel` command list; in the **Sandbox** paragraph, note that `runArgv`/`exec` extends containment to Sentinel-mediated command execution (imports outside it remain uncontained).
- `README.md`: add a "sentinel exec" subsection with usage, the capability-approval flag, and the scope-limitation caveat verbatim.

- [ ] **Step 3: Build + suite + commit**

Run: `npm run build` && `npm test` → green.
```bash
git add docs/adr/0051-sandboxed-exec.md docs/adr/README.md CLAUDE.md README.md
git commit -m "docs: ADR-0051 + docs for scoped sentinel exec"
```

---

## Final verification (whole feature)

- [ ] **Step 1:** `npm run fixtures` (fixtures changed) → succeeds, `registry.json` regenerated.
- [ ] **Step 2:** `npm run build` → clean.
- [ ] **Step 3:** `npm test` → green; confirm the `scoring is deterministic across runs` test passes and **no pre-existing benign fixture verdict moved**.
- [ ] **Step 4:** Confirm the four detection acceptance checks with a quick manual audit if desired (`sentinel scan` on each fixture tarball), then stop — do not commit or push beyond the task commits already made unless the user asks.
