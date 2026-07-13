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
