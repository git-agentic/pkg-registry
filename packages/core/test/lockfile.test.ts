import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { parseLockfile } from "../src/lockfile.js";

const LOCK = JSON.stringify({
  name: "root", version: "1.0.0", lockfileVersion: 3,
  packages: {
    "": { name: "root", version: "1.0.0" },
    "node_modules/leftpad-lite": { version: "1.0.0", resolved: "https://r/leftpad-lite/-/leftpad-lite-1.0.0.tgz", integrity: "sha512-A" },
    "node_modules/net-fetch-lite": { version: "1.0.0", resolved: "https://r/net-fetch-lite/-/x.tgz", integrity: "sha512-B" },
    "node_modules/@scope/pkg": { version: "2.0.0", resolved: "https://r/@scope/pkg/-/x.tgz" },
    "node_modules/tap": { version: "9.9.9", dev: true, resolved: "https://r/tap/-/x.tgz" },
    "node_modules/localdep": { version: "1.0.0", resolved: "file:../localdep" },
    "node_modules/linked": { version: "1.0.0", link: true },
    // duplicate coordinate at a nested path — must dedupe
    "node_modules/a/node_modules/leftpad-lite": { version: "1.0.0", resolved: "https://r/leftpad-lite/-/leftpad-lite-1.0.0.tgz", integrity: "sha512-A" },
  },
});

describe("parseLockfile", () => {
  test("extracts registry coordinates, deduped and sorted, skipping root/link/file", () => {
    const coords = parseLockfile(LOCK);
    assert.deepEqual(coords.map((c) => `${c.name}@${c.version}`), [
      "@scope/pkg@2.0.0", "leftpad-lite@1.0.0", "net-fetch-lite@1.0.0", "tap@9.9.9",
    ]);
    assert.equal(coords.find((c) => c.name === "leftpad-lite")?.integrity, "sha512-A");
  });

  test("omitDev drops dev-marked entries", () => {
    const coords = parseLockfile(LOCK, { omitDev: true });
    assert.equal(coords.find((c) => c.name === "tap"), undefined);
  });

  test("derives scoped names from the install path when name is absent", () => {
    const coords = parseLockfile(LOCK);
    assert.ok(coords.some((c) => c.name === "@scope/pkg" && c.version === "2.0.0"));
  });

  test("rejects a lockfile with no packages map", () => {
    assert.throws(() => parseLockfile(JSON.stringify({ dependencies: {} })), /packages/);
  });

  test("skips workspace source entries (paths outside node_modules)", () => {
    // npm workspaces: the workspace project appears twice — as its source path
    // ("packages/api", no link flag, no resolved) and as a node_modules link
    // entry. Neither is a registry coordinate; auditing it upstream can only 404.
    const lock = JSON.stringify({
      name: "root", version: "1.0.0", lockfileVersion: 3,
      packages: {
        "": { name: "root", version: "1.0.0" },
        "packages/api": { name: "@acme/api", version: "0.1.0" },
        "node_modules/@acme/api": { resolved: "packages/api", link: true },
        "node_modules/leftpad-lite": { version: "1.0.0", resolved: "https://r/leftpad-lite/-/leftpad-lite-1.0.0.tgz" },
      },
    });
    const coords = parseLockfile(lock);
    assert.deepEqual(coords.map((c) => `${c.name}@${c.version}`), ["leftpad-lite@1.0.0"]);
  });
});
