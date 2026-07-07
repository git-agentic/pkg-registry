import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { parseAnyLockfile } from "../src/lockfile.js";

const NPM = JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "root" }, "node_modules/lodash": { version: "4.17.21", integrity: "sha512-N==" } } });
const YARN_V1 = `# yarn lockfile v1\n\nlodash@^4.17.0:\n  version "4.17.21"\n  integrity sha512-Y==\n`;
const PNPM = `lockfileVersion: '9.0'\npackages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-P==}\n`;

describe("parseAnyLockfile", () => {
  test("detects npm by filename", () => {
    assert.equal(parseAnyLockfile(NPM, { filename: "package-lock.json" })[0]!.name, "lodash");
  });
  test("detects yarn by filename", () => {
    assert.equal(parseAnyLockfile(YARN_V1, { filename: "yarn.lock" })[0]!.integrity, "sha512-Y==");
  });
  test("detects pnpm by filename", () => {
    assert.equal(parseAnyLockfile(PNPM, { filename: "pnpm-lock.yaml" })[0]!.integrity, "sha512-P==");
  });
  test("content-sniff fallback: yarn v1 header", () => {
    assert.equal(parseAnyLockfile(YARN_V1)[0]!.name, "lodash");
  });
  test("content-sniff fallback: npm JSON", () => {
    assert.equal(parseAnyLockfile(NPM)[0]!.name, "lodash");
  });
  test("an unrecognizable file throws a clear error", () => {
    assert.throws(() => parseAnyLockfile("just some text\nnot a lockfile"), /unrecognized|unsupported/i);
  });
});
