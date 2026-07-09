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

  test("a ContiguousFile (tar type '7') entry's body counts toward maxUnpackedBytes (byte-cap bypass)", async () => {
    // 8 MiB of a repeated byte, gzip-compresses to a few KB.
    const tgz = buildContiguousFileTgz("package/big.bin", 8 * 1024 * 1024);
    const r = await extractTarball(tgz, undefined, { maxUnpackedBytes: 1024 * 1024 });
    assert.equal(r.truncated, true);
    assert.ok(r.unpackedSize > 1024 * 1024, `expected unpackedSize to reflect the streamed body, got ${r.unpackedSize}`);
  });
});
