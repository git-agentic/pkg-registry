import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { parse } from "yaml";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const doc = parse(readFileSync(join(REPO, "action.yml"), "utf8")) as {
  name?: string; runs?: { using?: string; steps?: unknown[] };
  inputs?: Record<string, unknown>; outputs?: Record<string, unknown>;
};

describe("action.yml", () => {
  test("is a composite action", () => {
    assert.equal(doc.runs?.using, "composite");
    assert.ok(Array.isArray(doc.runs?.steps) && doc.runs!.steps!.length > 0);
  });
  test("declares the documented inputs", () => {
    for (const k of ["lockfile", "policy", "sbom-path", "fail-on", "comment", "working-directory"]) {
      assert.ok(doc.inputs && k in doc.inputs, `missing input ${k}`);
    }
  });
  test("declares the documented outputs", () => {
    for (const k of ["verdict", "gated", "blocked", "warned", "errored", "sbom-path"]) {
      assert.ok(doc.outputs && k in doc.outputs, `missing output ${k}`);
    }
  });
});
