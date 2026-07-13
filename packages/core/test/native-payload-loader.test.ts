import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { nativePayloadLoaderRule } from "../src/rules/native-payload-loader.js";
import type { AuditInput, ContentMismatchEntry, PackageFile } from "../src/types.js";

function input(files: Record<string, string>, pkgJson: object, contentMismatch: ContentMismatchEntry[] = []): AuditInput {
  const list: PackageFile[] = Object.entries(files).map(([path, content]) => ({ path, content, size: content.length, changed: false }));
  list.push({ path: "package/package.json", content: JSON.stringify(pkgJson), size: 0, changed: false });
  return {
    meta: { name: "p", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, signature: "unknown", provenance: "unknown", integrity: null, unpackedSize: 0, fileCount: 0 },
    files: list,
    mode: "full",
    extractionObservations: contentMismatch.length
      ? { contentMismatch, contentMismatchTotals: { count: contentMismatch.length, byKind: {} }, unscannedTotals: { count: 0, native: 0, bytes: 0 } }
      : undefined,
  };
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

describe("nativePayloadLoaderRule", () => {
  test("correlated chain in the main entry → critical", () => {
    const f = nativePayloadLoaderRule.run(input({ "package/index.js": CORRELATED }, { name: "p", version: "1.0.0", main: "index.js" }));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.severity, "critical");
    assert.match(f[0]!.message, /read|decode|write|launch/i);
  });

  test("correlated chain in a bin entry → critical", () => {
    const f = nativePayloadLoaderRule.run(input({ "package/bin/cli.js": CORRELATED }, { name: "p", version: "1.0.0", bin: { p: "bin/cli.js" } }));
    assert.equal(f[0]!.severity, "critical");
  });

  test("full mode, no baseline still critical (no diff dependency)", () => {
    const f = nativePayloadLoaderRule.run(input({ "package/index.js": CORRELATED }, { name: "p", version: "1.0.0", main: "index.js" }));
    assert.equal(f[0]!.severity, "critical");
  });

  test("benign build tool (read+gzip+write+spawn fixed binary, no link) → no critical", () => {
    const src = `const fs=require('fs'),zlib=require('zlib'),cp=require('child_process');
      const d=fs.readFileSync('in'); fs.writeFileSync('out.gz', zlib.gzipSync(d)); cp.execFileSync('/usr/bin/tar',['-c']);`;
    const f = nativePayloadLoaderRule.run(input({ "package/build.js": src }, { name: "p", version: "1.0.0" }));
    assert.ok(!f.some((x) => x.severity === "critical"), "benign build tool must not be critical");
  });

  test("TypeScript source (acorn can't parse) → NO loader finding (parse-failure expected, not a signal)", () => {
    const ts = `const out: string = tmp(); fs.writeFileSync(out, gunzipSync(fs.readFileSync(p))); spawn(out,{detached:true});`;
    const f = nativePayloadLoaderRule.run(input({ "package/index.ts": ts }, { name: "p", version: "1.0.0", main: "index.ts" }));
    assert.equal(f.length, 0, "a .ts file acorn can't parse must not produce a regex-fallback loader finding");
  });

  test("`.d.ts` type declarations with read/write/decode tokens → NO finding (never executes; the @types/node false-positive)", () => {
    // Shape mirrors real @types/node: type signatures mentioning readFile/write/gunzip.
    const dts = `export function readFileSync(p: string): Buffer;
export function writeFileSync(p: string, d: Buffer): void;
export function gunzipSync(b: Buffer): Buffer;`;
    const f = nativePayloadLoaderRule.run(input({ "package/index.d.ts": dts }, { name: "types-pkg", version: "1.0.0" }));
    assert.equal(f.length, 0, "a .d.ts declaration file must never be flagged as a loader");
  });

  test("genuinely-anomalous JS that acorn cannot parse → regex fallback still fires (its intended use), capped below critical", () => {
    // A .js file with a hard syntax error so acorn fails, carrying ≥2 loader tokens.
    const brokenJs = `@@@ not valid js @@@ fs.readFileSync(x); fs.writeFileSync(y, gunzipSync(z));`;
    const f = nativePayloadLoaderRule.run(input({ "package/index.js": brokenJs }, { name: "p", version: "1.0.0", main: "index.js" }));
    assert.ok(f.length >= 1 && f.every((x) => x.severity !== "critical"), "JS fallback fires but is never critical");
  });

  test("throwing input never crashes (returns array)", () => {
    assert.doesNotThrow(() => nativePayloadLoaderRule.run(input({}, {})));
  });

  test("Spec6: content-mismatch on an UNRELATED file does not strengthen the finding", () => {
    const f = nativePayloadLoaderRule.run(input(
      { "package/index.js": CORRELATED },
      { name: "p", version: "1.0.0", main: "index.js" },
      [{ path: "package/dist/b.js", declaredExt: ".js", detectedKind: "gzip", size: 100 }],
    ));
    assert.equal(f[0]!.severity, "critical");
    assert.doesNotMatch(f[0]!.message, /content-mismatch/, "unrelated mismatch must not be claimed as correlated evidence");
  });

  test("Spec6: content-mismatch on the loader's OWN read target strengthens the finding", () => {
    const f = nativePayloadLoaderRule.run(input(
      { "package/index.js": CORRELATED },
      { name: "p", version: "1.0.0", main: "index.js" },
      [{ path: "package/intro.js", declaredExt: ".js", detectedKind: "gzip", size: 100 }],
    ));
    assert.equal(f[0]!.severity, "critical");
    assert.match(f[0]!.message, /content-mismatch/, "mismatch on the actual read target must be claimed as correlated evidence");
  });

  test("diff-mode: loader on a CHANGED file → finding flagged onChangedFile (acceptance #6)", () => {
    const inp = input({ "package/index.js": CORRELATED }, { name: "p", version: "2.0.0", main: "index.js" });
    // simulate diff-mode: the loader file is newly changed vs the benign predecessor
    for (const f of inp.files) if (f.path === "package/index.js") f.changed = true;
    inp.mode = "diff";
    const f = nativePayloadLoaderRule.run(inp);
    assert.equal(f[0]!.severity, "critical");
    assert.equal(f[0]!.onChangedFile, true, "newly-introduced loader must be recognized as changed (diff multiplier applies)");
  });
});
