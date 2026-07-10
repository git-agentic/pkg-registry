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
});
