import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { buildReleaseContext } from "../src/server.js";
import type { UpstreamPackument } from "../src/upstream.js";

function pm(): UpstreamPackument {
  return {
    doc: { name: "acme", versions: {} } as never,
    time: { "1.0.0": "2023-01-01T00:00:00Z", "2.0.0": "2026-01-01T00:00:00Z" },
    versions: {
      "1.0.0": { version: "1.0.0", author: null, maintainers: ["alice"], license: "MIT", signatures: null, hasProvenance: false, integrity: null, hasInstallScripts: false },
      "2.0.0": { version: "2.0.0", author: null, maintainers: ["mallory"], license: "MIT", signatures: null, hasProvenance: false, integrity: null, hasInstallScripts: false },
    },
  };
}

describe("buildReleaseContext", () => {
  test("derives previous version, its maintainers, both publish times, and version count", () => {
    const rc = buildReleaseContext(pm(), "2.0.0");
    assert.equal(rc.previousVersion, "1.0.0");
    assert.deepEqual(rc.previousMaintainers, ["alice"]);
    assert.equal(rc.previousPublishedAt, "2023-01-01T00:00:00Z");
    assert.equal(rc.currentPublishedAt, "2026-01-01T00:00:00Z");
    assert.equal(rc.versionCount, 2);
  });

  test("first version → no previous fields, versionCount 1", () => {
    const p = pm(); p.versions = { "1.0.0": p.versions["1.0.0"]! }; p.time = { "1.0.0": "2023-01-01T00:00:00Z" };
    const rc = buildReleaseContext(p, "1.0.0");
    assert.equal(rc.previousVersion, undefined);
    assert.equal(rc.versionCount, 1);
    assert.equal(rc.currentPublishedAt, "2023-01-01T00:00:00Z");
  });
});
