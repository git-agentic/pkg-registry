import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { packageCoordinateFromTarball } from "../src/scan-coordinate.js";
import { makeTarball } from "./helpers/make-tarball.js";

describe("sentinel scan coordinate", () => {
  test("reads the name and version from the manifest, not the filename", async () => {
    // npm pack names tarballs <name>-<version>.tgz, so a filename-derived
    // name is version-suffixed and never equals the real package name.
    const tarball = await makeTarball({ name: "lodash", version: "4.17.21" });
    const dir = mkdtempSync(join(tmpdir(), "scan-"));
    try {
      const path = join(dir, "lodash-4.17.21.tgz");
      writeFileSync(path, tarball);

      const coordinate = await packageCoordinateFromTarball(readFileSync(path));

      assert.equal(coordinate.name, "lodash");
      assert.equal(coordinate.version, "4.17.21");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("refuses a tarball with no readable manifest rather than guessing", async () => {
    const tarball = await makeTarball({ omitManifest: true });

    await assert.rejects(
      () => packageCoordinateFromTarball(tarball),
      /missing readable package\/package\.json/,
    );
  });
});
