import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { releaseAnomalyRule } from "../src/rules/release-anomaly.js";
import type { AuditInput, ReleaseContext, PackageMeta } from "../src/types.js";

function meta(over: Partial<PackageMeta> = {}): PackageMeta {
  return {
    name: "acme", version: "2.0.0", author: null, maintainers: ["alice"],
    license: "MIT", hasInstallScripts: false, integrity: "sha512-x",
    unpackedSize: 1, fileCount: 1, signature: "unsigned", provenance: "absent",
    ...over,
  } as PackageMeta;
}
function input(m: Partial<PackageMeta>, rc: ReleaseContext | undefined): AuditInput {
  return { meta: meta(m), files: [], mode: "full", releaseContext: rc };
}
const ids = (fs: { message: string }[]) => fs.map((f) => f.message);

describe("release-anomaly rule", () => {
  test("no releaseContext → inert (no findings)", () => {
    assert.deepEqual(releaseAnomalyRule.run(input({}, undefined)), []);
  });

  test("same maintainers, small time gap → no findings (false-positive guard)", () => {
    const rc: ReleaseContext = {
      previousVersion: "1.9.0", previousMaintainers: ["alice"],
      previousPublishedAt: "2026-06-01T00:00:00Z", currentPublishedAt: "2026-06-10T00:00:00Z",
      versionCount: 5,
    };
    assert.deepEqual(releaseAnomalyRule.run(input({ maintainers: ["alice"] }, rc)), []);
  });

  test("maintainer ADDED (superset) → a maintainer-change finding", () => {
    const rc: ReleaseContext = { previousVersion: "1.9.0", previousMaintainers: ["alice"], versionCount: 5 };
    const fs = releaseAnomalyRule.run(input({ maintainers: ["alice", "mallory"] }, rc));
    assert.equal(fs.length, 1);
    assert.match(fs[0]!.message, /new maintainer/i);
    assert.equal(fs[0]!.severity, "low");
  });

  test("maintainer TURNOVER (no prior maintainer remains) → higher-severity finding", () => {
    const rc: ReleaseContext = { previousVersion: "1.9.0", previousMaintainers: ["alice"], versionCount: 5 };
    const fs = releaseAnomalyRule.run(input({ maintainers: ["mallory"] }, rc));
    assert.equal(fs.length, 1);
    assert.match(fs[0]!.message, /ownership|took over|replaced/i);
    assert.equal(fs[0]!.severity, "high");
  });

  test("dormancy: prev→current gap ≥ 365 days → a dormancy finding", () => {
    const rc: ReleaseContext = {
      previousVersion: "1.9.0", previousMaintainers: ["alice"], versionCount: 5,
      previousPublishedAt: "2023-01-01T00:00:00Z", currentPublishedAt: "2026-01-01T00:00:00Z",
    };
    const fs = releaseAnomalyRule.run(input({ maintainers: ["alice"] }, rc));
    assert.equal(fs.length, 1);
    assert.match(fs[0]!.message, /dormant|dormancy/i);
  });

  test("new-package risk: first version + install scripts → a finding", () => {
    const rc: ReleaseContext = { versionCount: 1 };
    const fs = releaseAnomalyRule.run(input({ version: "1.0.0", hasInstallScripts: true }, rc));
    assert.equal(fs.length, 1);
    assert.match(fs[0]!.message, /first published version|new package/i);
  });

  test("first version WITHOUT install scripts → no finding", () => {
    assert.deepEqual(releaseAnomalyRule.run(input({ hasInstallScripts: false }, { versionCount: 1 })), []);
  });
});
