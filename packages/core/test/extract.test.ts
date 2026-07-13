import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { gzipSync } from "node:zlib";
import { create } from "tar";
import { extractTarball } from "../src/extract.js";
import { classifyContent } from "../src/detect/magic.js";

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

// Build an in-memory .tgz containing only directory entries (no files) — a
// header-only "bomb" shape (near-zero bytes per entry, huge compression ratio).
async function makeDirTgz(dirCount: number): Promise<Buffer> {
  const { mkdtempSync, mkdirSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "sentinel-extract-dirs-"));
  try {
    const names: string[] = [];
    for (let i = 0; i < dirCount; i++) {
      const p = `package/d${i}`;
      mkdirSync(join(dir, p), { recursive: true });
      names.push(p);
    }
    const chunks: Buffer[] = [];
    const stream = create({ cwd: dir, gzip: true }, names);
    for await (const ch of stream) chunks.push(Buffer.from(ch));
    return Buffer.concat(chunks);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Hand-build a single-entry .tgz whose entry is tar type '7' (ContiguousFile),
// which node-tar streams full-body data for but which the pre-fix extractor
// only measured `unpackedSize` for `entry.type === "File"` (type '0'). Built
// manually (not via `tar.create`, which has no ergonomic ContiguousFile knob)
// per the POSIX ustar header layout.
function buildContiguousFileTgz(entryPath: string, size: number): Buffer {
  const header = Buffer.alloc(512);
  header.write(entryPath, 0, "utf8");
  header.write("0000644\0", 100, "ascii"); // mode
  header.write("0000000\0", 108, "ascii"); // uid
  header.write("0000000\0", 116, "ascii"); // gid
  header.write(`${size.toString(8).padStart(11, "0")} `, 124, "ascii"); // size
  header.write("00000000000 ", 136, "ascii"); // mtime
  header.write("        ", 148, "ascii"); // chksum placeholder (8 spaces)
  header.write("7", 156, "ascii"); // typeflag: ContiguousFile
  header.write("ustar\0", 257, "ascii");
  header.write("00", 263, "ascii");
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i];
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");

  const body = Buffer.alloc(size, 0x41);
  const pad = (512 - (size % 512)) % 512;
  const tarBuf = Buffer.concat([header, body, Buffer.alloc(pad), Buffer.alloc(1024)]);
  return gzipSync(tarBuf);
}

// Hand-build a gzipped tar made entirely of pax meta ('x') header blocks with
// oversized (2 MiB) bodies. node-tar DECOMPRESSES these bytes but — because each
// body exceeds its meta-entry size cap — never surfaces them as an `entry` event.
// A per-entry byte counter is therefore blind to them: the pre-fix extractor
// unpacked 200 MiB under a 1 MiB cap with `truncated:false, unpackedSize:0`. The
// fix counts at the decompression boundary, so the cap trips regardless of tar
// semantics. Ported from scripts/probe-meta.ts.
function metaTarHeader(entryPath: string, size: number, typeflag: string): Buffer {
  const header = Buffer.alloc(512);
  header.write(entryPath, 0, "utf8");
  header.write("0000644\0", 100, "ascii");
  header.write("0000000\0", 108, "ascii");
  header.write("0000000\0", 116, "ascii");
  header.write(`${size.toString(8).padStart(11, "0")} `, 124, "ascii");
  header.write("00000000000 ", 136, "ascii");
  header.write("        ", 148, "ascii");
  header.write(typeflag, 156, "ascii");
  header.write("ustar\0", 257, "ascii");
  header.write("00", 263, "ascii");
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i];
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  return header;
}
function metaEntryBlock(entryPath: string, size: number, typeflag: string): Buffer {
  const header = metaTarHeader(entryPath, size, typeflag);
  const body = Buffer.alloc(size, 0x00);
  const pad = (512 - (size % 512)) % 512;
  return Buffer.concat([header, body, Buffer.alloc(pad)]);
}
function buildMetaHeaderBombTgz(entryCount: number, perBytes: number): Buffer {
  const blocks: Buffer[] = [];
  for (let i = 0; i < entryCount; i++) blocks.push(metaEntryBlock("pax_global_header", perBytes, "x"));
  blocks.push(Buffer.alloc(1024)); // two zero blocks: end-of-archive marker
  return gzipSync(Buffer.concat(blocks));
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

  test("a many-entry tarball is fully extracted (regression: 'finish' fires before parser 'end')", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 200; i++) files[`package/f${i}.js`] = `module.exports = ${i};\n`;
    const tgz = await makeTgz(files);
    const r = await extractTarball(tgz);
    assert.equal(r.truncated, false);
    assert.equal(r.files.length, 200, `expected all 200 files present, got ${r.files.length}`);
  });

  test("a tarball made entirely of directory entries is truncated against maxFileCount (header-bomb bypass)", async () => {
    const tgz = await makeDirTgz(50);
    const r = await extractTarball(tgz, undefined, { maxFileCount: 10 });
    assert.equal(r.truncated, true);
  });

  test("a tarball of oversized pax meta ('x') headers is truncated at the decompression boundary (per-entry-blind bomb bypass)", async () => {
    // 100 x 2 MiB meta bodies = 200 MiB decompressed, ~205 KiB compressed. None
    // surface as an `entry`, so a per-entry counter never sees them. Must trip
    // the 1 MiB cap on the decompressed byte stream.
    const tgz = buildMetaHeaderBombTgz(100, 2 * 1024 * 1024);
    const r = await extractTarball(tgz, undefined, { maxUnpackedBytes: 1024 * 1024, maxFileCount: 5 });
    assert.equal(r.truncated, true, "meta-header bomb must trip the unpacked-bytes cap");
    assert.ok(r.unpackedSize > 1024 * 1024, `expected unpackedSize to reflect decompressed meta bytes, got ${r.unpackedSize}`);
    assert.equal(r.files.length, 0, "no text files should be retained from a meta-header bomb");
  });

  test("a ContiguousFile (tar type '7') entry's body counts toward maxUnpackedBytes (byte-cap bypass)", async () => {
    // 8 MiB of a repeated byte, gzip-compresses to a few KB.
    const tgz = buildContiguousFileTgz("package/big.bin", 8 * 1024 * 1024);
    const r = await extractTarball(tgz, undefined, { maxUnpackedBytes: 1024 * 1024 });
    assert.equal(r.truncated, true);
    assert.ok(r.unpackedSize > 1024 * 1024, `expected unpackedSize to reflect the streamed body, got ${r.unpackedSize}`);
  });

  test("a large code file (>2MB .js) is tracked as unscanned large-code", async () => {
    const big = "x".repeat(3 * 1024 * 1024);
    const tgz = await makeTgz({ "package/index.js": "ok\n", "package/bundle.js": big });
    const r = await extractTarball(tgz);
    assert.equal(r.truncated, false);
    const u = r.unscanned.find((e) => e.path === "package/bundle.js");
    assert.ok(u && u.kind === "large-code", "large .js should be tracked as large-code");
    assert.ok(u.size >= 3 * 1024 * 1024);
  });

  test("a native binary is tracked as unscanned native", async () => {
    const tgz = await makeTgz({ "package/index.js": "ok\n", "package/addon.node": "\0\0binary" });
    const r = await extractTarball(tgz);
    const u = r.unscanned.find((e) => e.path === "package/addon.node");
    assert.ok(u && u.kind === "native", "*.node should be tracked as native");
  });

  test("a benign small package has no unscanned entries", async () => {
    const tgz = await makeTgz({ "package/index.js": "module.exports=1\n", "package/readme.md": "hi" });
    const r = await extractTarball(tgz);
    assert.deepEqual(r.unscanned, []);
  });

  test("a large non-executable file (>2MB .json) is NOT tracked", async () => {
    const bigJson = '{"a":"' + "x".repeat(3 * 1024 * 1024) + '"}';
    const tgz = await makeTgz({ "package/data.json": bigJson });
    const r = await extractTarball(tgz);
    assert.equal(r.unscanned.length, 0, "large .json is skipped but not executable-looking");
  });

  test("unscannedTotals stays complete when the unscanned list is capped (native entry after the cap is still counted)", async () => {
    // 150 tiny native files: the `unscanned` list caps at MAX_UNSCANNED (100),
    // so a naive count/nativeCount derived from that list would read 100/100 —
    // undercounting, and (worse) blind to any native entry that lands after the
    // cap on a list built from a *different* kind. Here every entry is native
    // and tiny, so this is cheap while still proving the totals are complete.
    const files: Record<string, string> = {};
    const total = 150;
    for (let i = 0; i < total; i++) files[`package/addon${i}.node`] = "\0\0binary";
    const tgz = await makeTgz(files);
    const r = await extractTarball(tgz);
    assert.equal(r.truncated, false);
    assert.equal(r.unscanned.length, 100, "the detail list stays capped at MAX_UNSCANNED");
    assert.equal(r.unscannedTotals.count, total, "totals.count must reflect every unscanned entry, not just the capped list");
    assert.equal(r.unscannedTotals.native, total, "totals.native must count every native entry, including those beyond the cap");
    assert.ok(r.unscannedTotals.count > r.unscanned.length, "totals must exceed the capped list length to prove completeness");
  });

  test("a native entry that would land after the cap on a mixed large-code+native tarball is still counted in totals", async () => {
    // 100 large-code files fill the capped list first; a native file after them
    // must still be reflected in unscannedTotals.native even though it never
    // makes it into the `unscanned` list itself.
    const files: Record<string, string> = {};
    const big = "x".repeat(3 * 1024 * 1024);
    for (let i = 0; i < 100; i++) files[`package/bundle${i}.js`] = big;
    files["package/addon.node"] = "\0\0binary";
    const tgz = await makeTgz(files);
    const r = await extractTarball(tgz);
    assert.equal(r.truncated, false);
    assert.equal(r.unscanned.length, 100, "detail list capped at 100 large-code entries");
    assert.ok(!r.unscanned.some((u) => u.kind === "native"), "the native entry landed after the cap and is absent from the detail list");
    assert.equal(r.unscannedTotals.native, 1, "totals.native must still count the native entry dropped from the capped list");
    assert.equal(r.unscannedTotals.count, 101, "totals.count must include the entry dropped from the capped list");
  });
});

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
