import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { parseAnyLockfile, parseLockfile, parsePnpmLock, parseYarnLock } from "../src/lockfile.js";

const npm = (packages: Record<string, unknown>) => JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "root" }, ...packages } });

describe("F19: non-registry lockfile sources are flagged, not audited as registry packages", () => {
  test("npm: git, github shorthand and off-shape tarball URLs get nonRegistry; registry shapes do not", () => {
    const coords = parseLockfile(npm({
      "node_modules/gitdep": { version: "1.0.0", resolved: "git+ssh://git@github.com/evil/gitdep.git#abc123" },
      "node_modules/ghdep": { version: "1.0.0", resolved: "github:evil/ghdep#abc123" },
      "node_modules/gitsdep": { version: "1.0.0", resolved: "git+https://github.com/evil/gitsdep.git#abc123" },
      "node_modules/tardep": { version: "1.0.0", resolved: "https://codeload.github.com/evil/tardep/tar.gz/abc123" },
      "node_modules/ftpdep": { version: "1.0.0", resolved: "ftp://evil.example/-/ftpdep-1.0.0.tgz" },
      "node_modules/lodash": { version: "4.17.21", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", integrity: "sha512-L" },
      "node_modules/@scope/pkg": { version: "1.2.3", resolved: "https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz" },
    }));
    const by = Object.fromEntries(coords.map((c) => [c.name, c]));
    assert.equal(by["gitdep"]!.nonRegistry, "git+ssh://git@github.com/evil/gitdep.git#abc123");
    assert.equal(by["ghdep"]!.nonRegistry, "github:evil/ghdep#abc123");
    assert.equal(by["gitsdep"]!.nonRegistry, "git+https://github.com/evil/gitsdep.git#abc123");
    assert.equal(by["tardep"]!.nonRegistry, "https://codeload.github.com/evil/tardep/tar.gz/abc123");
    assert.equal(by["ftpdep"]!.nonRegistry, "ftp://evil.example/-/ftpdep-1.0.0.tgz");
    assert.equal(by["lodash"]!.nonRegistry, undefined);
    assert.equal(by["@scope/pkg"]!.nonRegistry, undefined);
    assert.ok(!("nonRegistry" in by["lodash"]!), "registry coordinates must not carry the key at all");
  });

  test("npm: nonRegistry is sticky across duplicate name@version entries, in either order", () => {
    const reg = { version: "1.0.0", resolved: "https://registry.npmjs.org/dup/-/dup-1.0.0.tgz" };
    const git = { version: "1.0.0", resolved: "git+ssh://git@github.com/evil/dup.git#abc" };
    for (const packages of [
      { "node_modules/dup": git, "node_modules/a/node_modules/dup": reg },
      { "node_modules/dup": reg, "node_modules/a/node_modules/dup": git },
    ]) {
      const coords = parseLockfile(npm(packages));
      assert.equal(coords.length, 1);
      assert.equal(coords[0]!.nonRegistry, git.resolved);
    }
  });

  test("yarn v1: git and codeload resolutions are flagged", () => {
    const raw = `# yarn lockfile v1

"gitdep@github:evil/gitdep":
  version "1.0.0"
  resolved "git+ssh://git@github.com/evil/gitdep.git#abc123"

tardep@https://example.com/tardep.tgz:
  version "2.0.0"
  resolved "https://example.com/tardep.tgz#deadbeef"

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#def"
  integrity sha512-LODASHHASH==
`;
    const by = Object.fromEntries(parseYarnLock(raw).map((c) => [c.name, c]));
    assert.equal(by["gitdep"]!.nonRegistry, "git+ssh://git@github.com/evil/gitdep.git#abc123");
    assert.equal(by["tardep"]!.nonRegistry, "https://example.com/tardep.tgz#deadbeef");
    assert.equal(by["lodash"]!.nonRegistry, undefined);
  });

  test("yarn berry: non-npm resolutions are flagged; workspace/patch/link/file entries are skipped", () => {
    const raw = `__metadata:
  version: 6

"gitdep@https://github.com/evil/gitdep.git#commit=abc":
  version: 1.0.0
  resolution: "gitdep@https://github.com/evil/gitdep.git#commit=abc"
  languageName: node
  linkType: hard

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  languageName: node
  linkType: hard

"root@workspace:.":
  version: 0.0.0-use.local
  resolution: "root@workspace:."
  languageName: unknown
  linkType: soft

"typescript@patch:typescript@npm%3A5.0.0#~builtin<compat/typescript>":
  version: 5.0.0
  resolution: "typescript@patch:typescript@npm%3A5.0.0#~builtin<compat/typescript>::version=5.0.0&hash=abc"
  languageName: node
  linkType: hard
`;
    const coords = parseYarnLock(raw);
    assert.deepEqual(coords.map((c) => c.name), ["gitdep", "lodash"]);
    assert.equal(coords[0]!.nonRegistry, "gitdep@https://github.com/evil/gitdep.git#commit=abc");
    assert.equal(coords[1]!.nonRegistry, undefined);
  });

  test("yarn berry: a URL that merely contains @npm: or @file: is still non-registry", () => {
    const raw = `__metadata:
  version: 6

"evil@https://203.0.113.5/@npm:/evil.tgz":
  version: 1.0.0
  resolution: "evil@https://203.0.113.5/@npm:/evil.tgz"
  languageName: node
  linkType: hard

"sneaky@https://203.0.113.5/@file:/sneaky.tgz":
  version: 1.0.0
  resolution: "sneaky@https://203.0.113.5/@file:/sneaky.tgz"
  languageName: node
  linkType: hard

"@scope/ok@npm:^1.0.0":
  version: 1.2.3
  resolution: "@scope/ok@npm:1.2.3"
  languageName: node
  linkType: hard
`;
    const by = Object.fromEntries(parseYarnLock(raw).map((c) => [c.name, c]));
    assert.equal(by["evil"]?.nonRegistry, "evil@https://203.0.113.5/@npm:/evil.tgz");
    assert.equal(by["sneaky"]?.nonRegistry, "sneaky@https://203.0.113.5/@file:/sneaky.tgz");
    assert.equal(by["@scope/ok"]?.nonRegistry, undefined);
  });

  test("pnpm: git and tarball resolutions are flagged, directory entries are skipped, registry stays clean", () => {
    const raw = `lockfileVersion: '9.0'

packages:

  gitdep@https://codeload.github.com/evil/gitdep/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/evil/gitdep/tar.gz/abc}
    version: 1.0.0

  gitdep2@1.0.0:
    resolution: {type: git, repo: 'https://github.com/evil/gitdep2.git', commit: abc}

  localdep@1.0.0:
    resolution: {directory: ../localdep, type: directory}

  lodash@4.17.21:
    resolution: {integrity: sha512-LODASH==}

  custom@2.0.0:
    resolution: {integrity: sha512-C==, tarball: 'https://mirror.example/custom/-/custom-2.0.0.tgz'}
`;
    const coords = parsePnpmLock(raw);
    const by = Object.fromEntries(coords.map((c) => [c.name, c]));
    assert.equal(by["localdep"], undefined);
    assert.ok(by["gitdep2"]!.nonRegistry?.includes("https://github.com/evil/gitdep2.git"));
    assert.equal(by["lodash"]!.nonRegistry, undefined);
    assert.equal(by["custom"]!.nonRegistry, undefined);
    const tar = coords.find((c) => c.nonRegistry === "https://codeload.github.com/evil/gitdep/tar.gz/abc");
    assert.ok(tar, "tarball-resolved pnpm entry must be flagged");
  });

  test("parseAnyLockfile passes the flag through", () => {
    const coords = parseAnyLockfile(npm({ "node_modules/g": { version: "1.0.0", resolved: "git+ssh://git@x/g.git#a" } }), { filename: "package-lock.json" });
    assert.equal(coords[0]!.nonRegistry, "git+ssh://git@x/g.git#a");
  });
});
