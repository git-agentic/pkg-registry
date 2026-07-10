import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, "..", "scripts", "build-native.mjs");

describe("build-native.mjs", () => {
  test("exits 0 and does not throw when run (no-op on non-Linux/no-cc)", () => {
    const r = spawnSync(process.execPath, [script], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    // On darwin it must print a skip notice, never error out.
    if (process.platform !== "linux") assert.match(r.stdout + r.stderr, /skip|not linux|no cc/i);
  });
});
