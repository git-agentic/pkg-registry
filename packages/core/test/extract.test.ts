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

  test("a many-entry tarball is fully extracted (regression: 'finish' fires before parser 'end')", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 200; i++) files[`package/f${i}.js`] = `module.exports = ${i};\n`;
    const tgz = await makeTgz(files);
    const r = await extractTarball(tgz);
    assert.equal(r.truncated, false);
    assert.equal(r.files.length, 200, `expected all 200 files present, got ${r.files.length}`);
  });
});
