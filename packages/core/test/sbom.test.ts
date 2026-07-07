import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { toCycloneDX } from "../src/sbom.js";
import type { TreeAuditResult } from "../src/tree.js";

const tree: TreeAuditResult = {
  aggregate: { verdict: "warn", gated: false, counts: { allow: 1, warn: 1, block: 0, error: 0 }, provenance: { verified: 0, invalid: 0, absent: 2, unknown: 0 }, integrityMismatch: 0 },
  packages: [
    { name: "lodash", version: "4.17.21", status: "allow", score: 100, topFinding: null, error: null, provenance: "absent", integrityMismatch: false },
    { name: "@scope/pkg", version: "1.2.3", status: "warn", score: 60, topFinding: "network egress", error: null, provenance: "absent", integrityMismatch: false },
  ],
};

describe("toCycloneDX", () => {
  const bom = toCycloneDX(tree, { now: "2026-07-07T00:00:00Z" });
  test("valid CycloneDX 1.6 envelope with the Sentinel tool + injected timestamp", () => {
    assert.equal(bom.bomFormat, "CycloneDX");
    assert.equal(bom.specVersion, "1.6");
    assert.equal(bom.metadata.timestamp, "2026-07-07T00:00:00Z");
    assert.equal(bom.metadata.tools[0]!.name, "sentinel");
  });
  test("one component per package with a purl and sentinel properties", () => {
    assert.equal(bom.components.length, 2);
    const lodash = bom.components.find((c) => c.name === "lodash")!;
    assert.equal(lodash.type, "library");
    assert.equal(lodash.version, "4.17.21");
    assert.equal(lodash.purl, "pkg:npm/lodash@4.17.21");
    assert.equal(lodash.properties.find((p) => p.name === "sentinel:verdict")!.value, "allow");
    assert.equal(lodash.properties.find((p) => p.name === "sentinel:score")!.value, "100");
  });
  test("scoped-name purl percent-encodes the @", () => {
    const scoped = bom.components.find((c) => c.name === "@scope/pkg")!;
    assert.equal(scoped.purl, "pkg:npm/%40scope/pkg@1.2.3");
  });
});
