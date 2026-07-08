import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { capabilityNoveltyFindings } from "../src/rules/capability-novelty.js";
import type { CapabilityDelta, ReleaseContext } from "../src/types.js";

const rc: ReleaseContext = { previousVersion: "1.0.0" };
const netCap = { kind: "network" as const, target: "203.0.113.9", evidence: [] };
const procCap = { kind: "process" as const, target: "sh", evidence: [] };
const fsCap = { kind: "filesystem" as const, target: "/tmp/x", evidence: [] };

describe("capabilityNoveltyFindings", () => {
  test("newly-added network capability (with a predecessor) → a finding", () => {
    const delta: CapabilityDelta = { added: [netCap], removed: [] };
    const fs = capabilityNoveltyFindings(delta, rc);
    assert.equal(fs.length, 1);
    assert.match(fs[0]!.message, /new(ly)?|did not|previously/i);
    assert.equal(fs[0]!.category, "metadata");
  });

  test("newly-added process capability → a finding", () => {
    assert.equal(capabilityNoveltyFindings({ added: [procCap], removed: [] }, rc).length, 1);
  });

  test("only a benign (filesystem) capability added → no finding", () => {
    assert.deepEqual(capabilityNoveltyFindings({ added: [fsCap], removed: [] }, rc), []);
  });

  test("no predecessor (first release) → no finding even with a dangerous add", () => {
    assert.deepEqual(capabilityNoveltyFindings({ added: [netCap], removed: [] }, { versionCount: 1 }), []);
  });

  test("null delta (no baseline) → no finding", () => {
    assert.deepEqual(capabilityNoveltyFindings(null, rc), []);
  });

  test("undefined releaseContext → no finding", () => {
    assert.deepEqual(capabilityNoveltyFindings({ added: [netCap], removed: [] }, undefined), []);
  });
});
