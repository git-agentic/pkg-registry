import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";
import * as acorn from "acorn";
import * as walk from "acorn-walk";
import { runRules } from "../src/index.js";
import * as loaderChain from "../src/detect/loader-chain.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// The loader-chain walk is iterative: a deep expression costs time, not a stack overflow, so the full dataflow
// analysis runs and the regex fallback is only for genuine parse failures and the node bound.

const PAD = (n: number) => `try { x${".b".repeat(n)}; } catch (e) {}\n`;

/** A correlated chain in a form only the dataflow analysis recognises: renamed bindings, a decode (`atob`) the regex
 *  fallback has no pattern for, and the chain routed through a helper function. */
const CHAIN = `
const { readFileSync: rd, writeFileSync: wr } = require("fs");
const { spawnSync: go } = require("child_process");
const p = require("path");
function stage() {
  const blob = rd(p.join(__dirname, "intro.js"));
  const raw = atob(blob.toString());
  const dst = p.join(require("os").tmpdir(), ".cache-x");
  wr(dst, raw);
  go(dst);
}
stage();
`;
/** Mentions all four primitive names, in places that are not a chain. */
const BENIGN = `
const api = { readFileSync() {}, gunzipSync() {}, writeFileSync() {}, spawn() {} };
console.log("readFileSync gunzipSync writeFileSync spawn");
function unrelated(x) { return x.readFileSync + x.gunzipSync + x.writeFileSync + x.spawn; }
`;

function file(path: string, content: string): PackageFile {
  return { path, content, size: Buffer.byteLength(content), changed: false };
}
function input(js: string): AuditInput {
  const files = [file("package/package.json", '{"name":"probe","version":"1.0.0"}'), file("package/index.js", js)];
  return {
    meta: {
      name: "probe", version: "1.0.0", author: null, maintainers: [], license: null,
      hasInstallScripts: false, signature: "unknown", provenance: "unknown", integrity: null,
      unpackedSize: 0, fileCount: files.length,
    },
    files,
    mode: "full",
  };
}
const loaderSeverities = (js: string) => runRules(input(js)).filter((f) => f.ruleId === "native-payload-loader").map((f) => f.severity);

describe("a deep expression no longer defeats the dataflow analysis", () => {
  test("the unpadded chain is correlated (baseline)", () => {
    const a = loaderChain.analyzeLoaderChain(CHAIN);
    assert.equal(a.correlated, true);
    assert.deepEqual(loaderSeverities(CHAIN), ["critical"]);
  });

  test("a 60k-member pad does not stop the full analysis: still critical, walkOverflow false", () => {
    const src = PAD(60000) + CHAIN;
    const a = loaderChain.analyzeLoaderChain(src);
    assert.equal(a.parseFailed, false);
    assert.equal(a.walkOverflow, undefined);
    assert.equal(a.correlated, true);
    assert.deepEqual(loaderSeverities(src), ["critical"]);
  });

  test("the pad may come after the chain, or sit inside a function", () => {
    assert.deepEqual(loaderSeverities(CHAIN + PAD(60000)), ["critical"]);
    assert.deepEqual(loaderSeverities(`function pad() {\n${PAD(60000)}}\n${CHAIN}`), ["critical"]);
  });

  test("other deep shapes the parser accepts: chained calls and index chains", () => {
    for (const pad of [`f${"()".repeat(60000)};\n`, `a${"[0]".repeat(60000)};\n`]) {
      const a = loaderChain.analyzeLoaderChain(pad + CHAIN);
      assert.equal(a.walkOverflow, undefined, pad.slice(0, 12));
      assert.equal(a.correlated, true, pad.slice(0, 12));
    }
  });

  test("deeply nested parens, arrays and binary chains overflow acorn's parser, not the walk", () => {
    // acorn raises a SyntaxError ("Not enough stack space") for these, so they take the parse-failure path.
    for (const pad of [`${"(".repeat(60000)}x${")".repeat(60000)};\n`, `${"[".repeat(60000)}${"]".repeat(60000)};\n`, `1${"+1".repeat(60000)};\n`]) {
      assert.equal(loaderChain.analyzeLoaderChain(pad + CHAIN).parseFailed, true, pad.slice(0, 12));
    }
  });

  test("a padded benign file that only mentions the four names is not critical", () => {
    assert.equal(loaderSeverities(PAD(60000) + BENIGN).includes("critical"), false);
    assert.deepEqual(loaderSeverities(PAD(60000) + BENIGN), []);
    assert.equal(loaderChain.analyzeLoaderChain(PAD(60000) + BENIGN).walkOverflow, undefined);
  });

  test("a 2 MiB padded file finishes within a generous bound", () => {
    const src = PAD(1_050_000) + CHAIN;
    assert.ok(src.length > 2 * 1024 * 1024 - 1024);
    const t0 = performance.now();
    const a = loaderChain.analyzeLoaderChain(src);
    const ms = performance.now() - t0;
    assert.equal(a.correlated, true);
    assert.ok(ms < 20_000, `took ${ms} ms`);
  });

  test("the node bound is deterministic and still maps to the overflow path", () => {
    const src = `var a = [${"0,".repeat(2_100_000)}];\n${CHAIN}`;
    const a = loaderChain.analyzeLoaderChain(src);
    assert.equal(a.parseFailed, true);
    assert.equal(a.walkOverflow, true);
  });

  test("genuine parse failures still use the parse-failure path", () => {
    const a = loaderChain.analyzeLoaderChain("const = ;");
    assert.equal(a.parseFailed, true);
    assert.notEqual(a.walkOverflow, true);
  });
});

describe("the iterative walk visits what acorn-walk's ancestor visits", () => {
  const SAMPLE = `
    import fs, { a as b } from "fs"; export const q = 1; export default function () {}
    class A extends B { static #x = 1; get y() { return super.y } static { init() } constructor(...r) { super(...r) } }
    async function* g(a = 1, { b, ...c }, [d, , e]) { for await (const z of a) yield* z; label: for (;;) { break label } }
    const t = tag\`a\${1}b\`, o = { a, [b]: c, ...d, get e() { return 1 }, f() {} }, r = /x/g, n = 10n;
    try { a?.b?.[c]?.(d) } catch { } finally { import.meta; } function nt() { return new.target; }
    switch (x) { case 1: y(); default: z(); } do { w() } while (v); if (a) b; else c;
    for (var i in o) ; for (const k of o) ; with_ = (a, b) => a ?? b; x ||= 1; delete a.b; void 0; typeof a;
    (function () { "use strict"; return this })(); a = b ? c : d; throw new Error(\`e\`);
  `;
  const trace = (run: (visitors: Record<string, any>) => void) => {
    const out: string[] = [];
    const types = ["Program", "Identifier", "Literal", "CallExpression", "MemberExpression", "VariableDeclarator", "AssignmentExpression",
      "FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression", "ClassBody", "PropertyDefinition", "TemplateLiteral", "ImportDeclaration",
      "ForOfStatement", "TryStatement", "SwitchStatement", "ObjectExpression", "ArrayPattern", "ObjectPattern", "BinaryExpression", "ChainExpression",
      "ExpressionStatement", "ReturnStatement", "StaticBlock", "MetaProperty", "NewExpression", "Property", "SpreadElement", "RestElement", "AssignmentPattern"];
    const v: Record<string, any> = {};
    for (const ty of types) v[ty] = (n: any, _st: any, anc: any[]) => out.push(`${ty}@${n.start}-${n.end}/${anc.map((a) => a.type).join(">")}`);
    run(v);
    return out;
  };
  const sources: [string, string, "module" | "script"][] = [["inline sample", SAMPLE, "module"]];
  for (const rel of ["../../../node_modules/acorn/dist/acorn.js", "../../../node_modules/acorn-walk/dist/walk.js"]) {
    try { sources.push([rel.split("/").pop()!, readFileSync(new URL(rel, import.meta.url), "utf8"), "script"]); } catch { /* optional corpus file */ }
  }
  for (const [label, src, sourceType] of sources) {
    test(`same visits, order and ancestors: ${label}`, () => {
      const ast = acorn.parse(src, { ecmaVersion: "latest", sourceType, allowHashBang: true, allowReturnOutsideFunction: true });
      const expected = trace((v) => walk.ancestor(ast, v));
      const actual = trace((v) => (loaderChain as any).walkAncestor(ast, v));
      assert.ok(expected.length > 50);
      assert.deepEqual(actual, expected);
    });
  }
});
