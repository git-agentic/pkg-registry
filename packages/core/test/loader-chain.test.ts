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
});
