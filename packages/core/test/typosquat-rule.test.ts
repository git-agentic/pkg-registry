import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { typosquatRule } from "../src/rules/typosquat.js";
import type { AuditInput, PackageMeta } from "../src/types.js";

function input(name: string): AuditInput {
  const meta = { name, version: "1.0.0", author: null, maintainers: [], license: null,
    hasInstallScripts: false, signature: "unsigned", provenance: "absent", integrity: null,
    unpackedSize: 0, fileCount: 0 } as unknown as PackageMeta;
  return { meta, files: [], mode: "full" };
}

describe("typosquat rule", () => {
  test("a near-miss of a popular name is flagged medium, naming the target", () => {
    const f = typosquatRule.run(input("expres"));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.severity, "medium");
    assert.equal(f[0]!.category, "metadata");
    assert.match(f[0]!.message, /express/);
  });

  test("a name that IS in the corpus is NOT flagged (FP control)", () => {
    assert.deepEqual(typosquatRule.run(input("express")), []);
  });

  test("a clearly-unrelated name is not flagged", () => {
    assert.deepEqual(typosquatRule.run(input("my-unique-app-9000")), []);
  });

  test("a very short name (<4 chars) is not flagged (FP control)", () => {
    assert.deepEqual(typosquatRule.run(input("axi")), []);
  });

  test("a homoglyph squat is flagged", () => {
    const f = typosquatRule.run(input("l0dash"));
    assert.equal(f.length, 1);
    assert.match(f[0]!.message, /lodash/);
  });
});
