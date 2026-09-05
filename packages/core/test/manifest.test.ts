import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { readPackageManifest } from "../src/manifest.js";
import type { ExtractResult } from "../src/extract.js";
import type { PackageFile } from "../src/types.js";

/**
 * Build a minimal, well-formed ExtractResult around a set of files —
 * readPackageManifest only reads `files` and `packageManifestEntryCount`, so
 * every other field is a fixed, unexercised default.
 */
function fakeExtracted(files: PackageFile[], packageManifestEntryCount: number): ExtractResult {
  return {
    files,
    packageManifestEntryCount,
    unpackedSize: 0,
    fileCount: files.length,
    truncated: false,
    unscanned: [],
    unscannedTotals: { count: 0, native: 0, bytes: 0 },
    contentMismatch: [],
    contentMismatchTotals: { count: 0, byKind: {} },
  };
}

function manifestFile(content: string): PackageFile {
  return { path: "package/package.json", content, size: content.length, changed: true };
}

describe("readPackageManifest", () => {
  test("reads name and version from a well-formed manifest", () => {
    const extracted = fakeExtracted(
      [manifestFile(JSON.stringify({ name: "lodash", version: "4.17.21" }))],
      1,
    );
    const coordinate = readPackageManifest(extracted);
    assert.deepEqual(coordinate, { name: "lodash", version: "4.17.21" });
  });

  test("rejects duplicate package/package.json entries", () => {
    // packageManifestEntryCount is the tar-entry count, tracked independently
    // of the deduplicated `files` list — this is the shape a tarball with two
    // manifest entries produces.
    const extracted = fakeExtracted(
      [manifestFile(JSON.stringify({ name: "lodash", version: "4.17.21" }))],
      2,
    );
    assert.throws(
      () => readPackageManifest(extracted),
      /malformed npm tarball: duplicate package\/package\.json entries/,
    );
  });

  test("rejects a tarball with no readable manifest", () => {
    const extracted = fakeExtracted([], 0);
    assert.throws(
      () => readPackageManifest(extracted),
      /malformed npm tarball: missing readable package\/package\.json/,
    );
  });

  test("rejects a manifest that is not valid JSON", () => {
    const extracted = fakeExtracted([manifestFile("{ not json")], 1);
    assert.throws(
      () => readPackageManifest(extracted),
      /malformed npm tarball: package\/package\.json is not valid JSON/,
    );
  });

  test("rejects a manifest with no name", () => {
    const extracted = fakeExtracted([manifestFile(JSON.stringify({ version: "1.0.0" }))], 1);
    assert.throws(
      () => readPackageManifest(extracted),
      /malformed npm tarball: package\/package\.json declares no name/,
    );
  });

  test("rejects a manifest with no version", () => {
    const extracted = fakeExtracted([manifestFile(JSON.stringify({ name: "lodash" }))], 1);
    assert.throws(
      () => readPackageManifest(extracted),
      /malformed npm tarball: package\/package\.json declares no version/,
    );
  });
});
