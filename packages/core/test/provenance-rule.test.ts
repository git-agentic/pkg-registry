import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { provenanceRule } from "../src/rules/provenance.js";
import type { AuditInput, PackageMeta } from "../src/types.js";

function input(signature: PackageMeta["signature"], provenance: PackageMeta["provenance"]): AuditInput {
  return {
    meta: { name: "p", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, signature, provenance, integrity: "sha512-x", unpackedSize: 1, fileCount: 1 },
    files: [], mode: "full",
  };
}

describe("provenanceRule", () => {
  test("invalid signature is critical", () => {
    const f = provenanceRule.run(input("invalid", "verified"));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.severity, "critical");
  });
  test("unsigned is low", () => {
    assert.equal(provenanceRule.run(input("unsigned", "verified"))[0]!.severity, "low");
  });
  test("unknown is info", () => {
    assert.equal(provenanceRule.run(input("unknown", "verified"))[0]!.severity, "info");
  });
  test("absent provenance is info", () => {
    const f = provenanceRule.run(input("verified", "absent"));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.severity, "info");
  });
  test("verified + verified emits nothing", () => {
    assert.deepEqual(provenanceRule.run(input("verified", "verified")), []);
  });
  test("invalid provenance is critical", () => {
    const f = provenanceRule.run(input("verified", "invalid"));
    assert.equal(f.find((x) => x.message.includes("provenance"))!.severity, "critical");
  });
  test("unknown provenance is low", () => {
    const f = provenanceRule.run(input("verified", "unknown"));
    assert.equal(f.find((x) => x.message.includes("provenance"))!.severity, "low");
  });
  test("verified provenance emits nothing", () => {
    assert.deepEqual(provenanceRule.run(input("verified", "verified")), []);
  });
});
