import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { parseLockfile, parsePnpmLock, parseYarnLock } from "../src/lockfile.js";

const npm = (packages: Record<string, unknown>) => JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "root" }, ...packages } });
const get = (raw: string, name: string) => parseLockfile(raw).find((c) => c.name === name)!;

describe("registry-shaped URL needs an integrity pin (review round 1, item 1)", () => {
  test("npm: a registry-shaped URL with no integrity is non-registry", () => {
    const c = get(npm({ "node_modules/x": { version: "1.0.0", resolved: "https://attacker.example/-/x.tgz" } }), "x");
    assert.equal(c.nonRegistry, "https://attacker.example/-/x.tgz");
  });

  test("npm: an unknown-algorithm integrity is not a pin", () => {
    const c = get(npm({ "node_modules/x": { version: "1.0.0", resolved: "https://r.example/x/-/x-1.0.0.tgz", integrity: "md5-AAAA" } }), "x");
    assert.ok(c.nonRegistry);
  });

  test("npm: sha1, sha256 and sha512 pins make a registry coordinate", () => {
    for (const integrity of ["sha1-AAAA", "sha256-AAAA", "sha512-AAAA"]) {
      const c = get(npm({ "node_modules/x": { version: "1.0.0", resolved: "https://r.example/x/-/x-1.0.0.tgz", integrity } }), "x");
      assert.equal(c.nonRegistry, undefined, integrity);
    }
  });

  test("npm: GitLab-style /-/@scope/name-1.0.0.tgz with a pin is a registry coordinate", () => {
    const resolved = "https://gitlab.example/api/v4/packages/npm/@scope/name/-/@scope/name-1.0.0.tgz";
    assert.equal(get(npm({ "node_modules/@scope/name": { version: "1.0.0", resolved, integrity: "sha512-AAAA" } }), "@scope/name").nonRegistry, undefined);
  });

  test("npm: http(s) URLs without /-/ or .tgz are non-registry even with a pin", () => {
    for (const resolved of ["https://r.example/x/x-1.0.0.tgz", "https://r.example/x/-/x-1.0.0.zip", "ftp://r.example/x/-/x-1.0.0.tgz"]) {
      const c = get(npm({ "node_modules/x": { version: "1.0.0", resolved, integrity: "sha512-AAAA" } }), "x");
      assert.equal(c.nonRegistry, resolved);
    }
  });

  test("npm: duplicate name@version with conflicting pins becomes non-registry", () => {
    const base = { version: "1.0.0", resolved: "https://r.example/x/-/x-1.0.0.tgz" };
    const c = get(npm({
      "node_modules/x": { ...base, integrity: "sha512-AAAA" },
      "node_modules/a/node_modules/x": { ...base, integrity: "sha512-BBBB" },
    }), "x");
    assert.match(c.nonRegistry ?? "", /conflicting integrity pins/);
  });

  test("npm: duplicates with the same pin stay registry", () => {
    const e = { version: "1.0.0", resolved: "https://r.example/x/-/x-1.0.0.tgz", integrity: "sha512-AAAA" };
    assert.equal(get(npm({ "node_modules/x": e, "node_modules/a/node_modules/x": e }), "x").nonRegistry, undefined);
  });

  test("yarn v1: a 40-hex #fragment on resolved is a sha1 pin and becomes the SRI integrity", () => {
    const hex = "0123456789abcdef0123456789abcdef01234567";
    const raw = `# yarn lockfile v1\n\nx@^1.0.0:\n  version "1.0.0"\n  resolved "https://registry.yarnpkg.com/x/-/x-1.0.0.tgz#${hex}"\n`;
    const c = parseYarnLock(raw)[0]!;
    assert.equal(c.nonRegistry, undefined);
    assert.equal(c.integrity, "sha1-" + Buffer.from(hex, "hex").toString("base64"));
  });

  test("yarn v1: a registry-shaped URL with neither an integrity line nor a sha1 fragment is non-registry", () => {
    const raw = `# yarn lockfile v1\n\nx@^1.0.0:\n  version "1.0.0"\n  resolved "https://attacker.example/-/x.tgz#notahash"\n`;
    assert.ok(parseYarnLock(raw)[0]!.nonRegistry);
  });

  test("pnpm: a file: tarball is skipped like npm and yarn file: entries", () => {
    const raw = `lockfileVersion: '9.0'\n\npackages:\n\n  localtar@1.0.0:\n    resolution: {tarball: file:../localtar-1.0.0.tgz}\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-L==}\n`;
    assert.deepEqual(parsePnpmLock(raw).map((c) => c.name), ["lodash"]);
  });

  test("pnpm: a registry-shaped tarball without an integrity is non-registry", () => {
    const raw = `lockfileVersion: '9.0'\n\npackages:\n\n  x@1.0.0:\n    resolution: {tarball: 'https://attacker.example/x/-/x-1.0.0.tgz'}\n`;
    assert.ok(parsePnpmLock(raw)[0]!.nonRegistry);
  });
});
