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
    const f = provenanceRule.run(input("invalid", "present"));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.severity, "critical");
  });
  test("unsigned is low", () => {
    assert.equal(provenanceRule.run(input("unsigned", "present"))[0]!.severity, "low");
  });
  test("unknown is info", () => {
    assert.equal(provenanceRule.run(input("unknown", "present"))[0]!.severity, "info");
  });
  test("absent provenance is info", () => {
    const f = provenanceRule.run(input("verified", "absent"));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.severity, "info");
  });
  test("verified + present emits nothing", () => {
    assert.deepEqual(provenanceRule.run(input("verified", "present")), []);
  });
});
