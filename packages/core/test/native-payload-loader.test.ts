import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { nativePayloadLoaderRule } from "../src/rules/native-payload-loader.js";
import type { AuditInput, PackageFile } from "../src/types.js";

function input(files: Record<string, string>, pkgJson: object): AuditInput {
  const list: PackageFile[] = Object.entries(files).map(([path, content]) => ({ path, content, size: content.length, changed: false }));
  list.push({ path: "package/package.json", content: JSON.stringify(pkgJson), size: 0, changed: false });
  return { meta: { name: "p", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, signature: "unknown", provenance: "unknown", integrity: null, unpackedSize: 0, fileCount: 0 }, files: list, mode: "full" };
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

  test("TypeScript source with loader keywords → regex fallback, capped below critical", () => {
    const ts = `const out: string = tmp(); fs.writeFileSync(out, gunzipSync(fs.readFileSync(p))); spawn(out,{detached:true});`;
    const f = nativePayloadLoaderRule.run(input({ "package/index.ts": ts }, { name: "p", version: "1.0.0", main: "index.ts" }));
    assert.ok(!f.some((x) => x.severity === "critical"), "parse-failed fallback never critical");
  });

  test("throwing input never crashes (returns array)", () => {
    assert.doesNotThrow(() => nativePayloadLoaderRule.run(input({}, {})));
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
