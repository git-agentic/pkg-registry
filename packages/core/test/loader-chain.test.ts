import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { analyzeLoaderChain } from "../src/detect/loader-chain.js";

const LOADER = `
const fs = require('fs');
const zlib = require('zlib');
const cp = require('child_process');
const os = require('os');
const path = require('path');
(function () {
  const container = fs.readFileSync(path.join(__dirname, 'intro.js'));
  const bin = zlib.gunzipSync(container.subarray(5));
  const out = path.join(os.tmpdir(), '.' + Math.random().toString(36).slice(2));
  fs.writeFileSync(out, bin);
  fs.chmodSync(out, 0o755);
  const child = cp.spawn(out, [], { detached: true, stdio: 'ignore' });
  child.unref();
})();
`;

describe("analyzeLoaderChain", () => {
  // ---- existing 8 (pinned) ----

  test("full correlated chain → correlated true, all four stages, boosters set", () => {
    const a = analyzeLoaderChain(LOADER, { moduleLoadReachable: true });
    assert.equal(a.parseFailed, false);
    assert.equal(a.correlated, true);
    const stages = new Set(a.primitives.map((p) => p.stage));
    for (const s of ["read", "decode", "write", "launch"]) assert.ok(stages.has(s as any), `missing ${s}`);
    assert.equal(a.boosters.tempOrHidden, true);
    assert.equal(a.boosters.chmod, true);
    assert.equal(a.boosters.detached, true);
    assert.equal(a.boosters.unref, true);
    assert.equal(a.boosters.moduleLoad, true);
  });

  test("disconnected primitives (spawn a fixed system binary, unrelated gzip) → NOT correlated", () => {
    const src = `
      const fs = require('fs'); const zlib = require('zlib'); const cp = require('child_process');
      const data = fs.readFileSync('input.txt');
      const packed = zlib.gzipSync(data);           // compress OUTPUT, not decode a payload
      fs.writeFileSync('out.gz', packed);
      cp.execFileSync('/usr/bin/git', ['status']);   // launches a fixed binary, not the written file
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, false, "no dataflow link from read→launch");
  });

  test("child_process alone → not correlated, no false chain", () => {
    const a = analyzeLoaderChain(`const cp=require('child_process'); cp.exec('ls');`);
    assert.equal(a.correlated, false);
  });

  test("TypeScript syntax → parseFailed true (caller uses regex fallback)", () => {
    const a = analyzeLoaderChain(`const x: number = 1; export const y = x;`);
    assert.equal(a.parseFailed, true);
  });

  test("launch of the written path but WITHOUT decode → not correlated (caps below critical)", () => {
    const src = `
      const fs=require('fs'); const cp=require('child_process'); const os=require('os'); const path=require('path');
      const out = path.join(os.tmpdir(), 'x');
      fs.writeFileSync(out, fs.readFileSync(path.join(__dirname,'blob.bin')));
      cp.spawn(out);
    `;
    const a = analyzeLoaderChain(src);
    // read→write→launch present but no DECODE stage between → correlated stays false
    assert.equal(a.correlated, false);
  });

  test("F1: reassignment (let bin; bin = gunzipSync(...)) still tracks taint → correlated true", () => {
    const src = `
      const fs=require('fs'); const zlib=require('zlib'); const cp=require('child_process');
      const os=require('os'); const path=require('path');
      const container = fs.readFileSync(path.join(__dirname,'x'));
      let bin;
      bin = zlib.gunzipSync(container);
      const out = path.join(os.tmpdir(),'x');
      fs.writeFileSync(out, bin);
      fs.chmodSync(out, 0o755);
      cp.spawn(out, [], { detached: true });
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, true);
  });

  test("F2: write path built inline from a directory identifier does not taint the directory → correlated false", () => {
    const src = `
      const fs=require('fs'); const zlib=require('zlib'); const cp=require('child_process'); const path=require('path');
      const dir = '/tmp/somedir';
      const p = 'input.bin';
      const raw = fs.readFileSync(p);
      const bin = zlib.gunzipSync(raw);
      fs.writeFileSync(path.join(dir,'payload'), bin);
      cp.spawn(dir);
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, false, "dir is only a path component, not the written file itself");
  });

  test("F3: read captured into a variable is recorded only once (no duplicate primitives)", () => {
    const a = analyzeLoaderChain(LOADER, { moduleLoadReachable: true });
    assert.equal(a.primitives.filter((p) => p.stage === "read").length, 1);
  });

  // ---- S1: binding tracking ----

  test("S1 FP: custom object methods (not Node module bindings) are not primitives → correlated false", () => {
    const src = `
      const o = makeThing();
      const c = o.readFileSync(p);
      const b = o.gunzipSync(c);
      o.writeFileSync(out, b);
      o.spawn(out);
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, false, "obj is not a tracked Node module binding");
    assert.equal(a.primitives.length, 0, "no primitives should be recognized from an untracked object");
  });

  test("S1 TP: destructured `const { readFileSync } = require('fs')` still detected in a real chain", () => {
    const src = `
      const { readFileSync, writeFileSync, chmodSync } = require('fs');
      const { gunzipSync } = require('zlib');
      const { spawn } = require('child_process');
      const { tmpdir } = require('os');
      const path = require('path');
      const container = readFileSync(path.join(__dirname, 'x'));
      const bin = gunzipSync(container);
      const out = path.join(tmpdir(), 'x');
      writeFileSync(out, bin);
      chmodSync(out, 0o755);
      spawn(out);
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, true);
  });

  // ---- S2: lexical scope + kill-on-reassign ----

  test("S2 kill-on-reassign: reassigning to an untainted, non-package-relative read drops decoded taint → correlated false", () => {
    const src = `
      const fs=require('fs'); const zlib=require('zlib'); const cp=require('child_process'); const path=require('path');
      let b = zlib.gunzipSync(fs.readFileSync(path.join(__dirname,'x')));
      b = fs.readFileSync('/tmp/unrelated');
      fs.writeFileSync('out', b);
      cp.spawn('out');
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, false, "b lost decoded taint on reassignment; the second read is not package-relative");
  });

  test("S2 scope isolation: a same-named tainted var in a different function does not correlate a sibling function's launch", () => {
    const src = `
      const fs=require('fs'); const zlib=require('zlib'); const cp=require('child_process'); const path=require('path');
      function loader() {
        const out = path.join(__dirname, 'x');
        const bin = zlib.gunzipSync(fs.readFileSync(out));
        fs.writeFileSync(out, bin);
      }
      function other() {
        const out = 'unrelated-value';
        cp.spawn(out);
      }
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, false, "the 'out' in other() is a distinct binding, not the tainted one from loader()");
  });

  // ---- Spec1: package-relative READ origin (the keystone) ----

  test("Spec1 FP: external-file read (absolute path) → decompress → write → spawn → correlated false", () => {
    const src = `
      const fs=require('fs'); const zlib=require('zlib'); const cp=require('child_process'); const path=require('path');
      const container = fs.readFileSync('/etc/hosts');
      const bin = zlib.gunzipSync(container);
      const out = path.join('/tmp', 'x');
      fs.writeFileSync(out, bin);
      cp.spawn(out);
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, false, "read of an absolute external path must not originate packaged-payload taint");
  });

  test("Spec1 TP: package-relative read via path.join(__dirname, ...) → real chain → correlated true", () => {
    const src = `
      const fs=require('fs'); const zlib=require('zlib'); const cp=require('child_process'); const os=require('os'); const path=require('path');
      const container = fs.readFileSync(path.join(__dirname, 'blob'));
      const bin = zlib.gunzipSync(container);
      const out = path.join(os.tmpdir(), 'x');
      fs.writeFileSync(out, bin);
      cp.spawn(out);
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, true);
  });

  // ---- S3: structural write-path <-> launch matching ----

  test("S3 TP inline-repeat: literal/path.join write-path repeated at the launch site (no shared identifier) → correlated true", () => {
    const src = `
      const fs=require('fs'); const zlib=require('zlib'); const cp=require('child_process'); const os=require('os'); const path=require('path');
      fs.writeFileSync(path.join(os.tmpdir(),'x'), zlib.gunzipSync(fs.readFileSync(path.join(__dirname,'p'))));
      cp.spawn(path.join(os.tmpdir(),'x'));
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, true);
  });

  // ---- Spec2: additional forms ----

  test("Spec2 base64 TP: Buffer.from(read, 'base64') → write → chmod → spawn → correlated true", () => {
    const src = `
      const fs=require('fs'); const cp=require('child_process'); const os=require('os'); const path=require('path');
      const b = Buffer.from(fs.readFileSync(path.join(__dirname,'p')).toString(), 'base64');
      const out = path.join(os.tmpdir(),'x');
      fs.writeFileSync(out,b);
      fs.chmodSync(out,0o755);
      cp.spawn(out);
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, true);
  });

  test("Spec2 native-require TP: writes a .node asset then require()s the written path → correlated true", () => {
    const src = `
      const fs=require('fs'); const zlib=require('zlib'); const os=require('os'); const path=require('path');
      const out = path.join(os.tmpdir(),'x.node');
      fs.writeFileSync(out, zlib.gunzipSync(fs.readFileSync(path.join(__dirname,'p'))));
      require(out);
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, true);
  });

  test("Spec2 promisified decode TP: promisify(zlib.gunzip) + await, then write+launch → correlated true", () => {
    const src = `
      const fs=require('fs'); const zlib=require('zlib'); const cp=require('child_process'); const os=require('os'); const path=require('path');
      const { promisify } = require('util');
      const gunzip = promisify(zlib.gunzip);
      (async () => {
        const container = fs.readFileSync(path.join(__dirname, 'p'));
        const b = await gunzip(container);
        const out = path.join(os.tmpdir(), 'x');
        fs.writeFileSync(out, b);
        cp.spawn(out);
      })();
    `;
    const a = analyzeLoaderChain(src);
    assert.equal(a.correlated, true);
  });
});
