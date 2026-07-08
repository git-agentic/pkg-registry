import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { TreeAuditResult } from "@sentinel/core";
import { formatTree, treeExitCode } from "../src/format.js";

const gated: TreeAuditResult = {
  aggregate: {
    verdict: "block", gated: true, counts: { allow: 1, warn: 0, block: 1, error: 0 },
    provenance: { verified: 0, invalid: 1, absent: 1, unknown: 0 },
  },
  packages: [
    { name: "leftpad-lite", version: "1.0.0", status: "allow", score: 100, topFinding: null, topFindingRuleId: null, error: null, provenance: "absent" },
    { name: "color-stream", version: "1.4.1", status: "block", score: 10, topFinding: "exfiltrates env to network", topFindingRuleId: "network-egress", error: null, provenance: "invalid" },
  ],
};
const clean: TreeAuditResult = {
  aggregate: {
    verdict: "allow", gated: false, counts: { allow: 1, warn: 0, block: 0, error: 0 },
    provenance: { verified: 1, invalid: 0, absent: 0, unknown: 0 },
  },
  packages: [{ name: "leftpad-lite", version: "1.0.0", status: "allow", score: 100, topFinding: null, topFindingRuleId: null, error: null, provenance: "verified" }],
};

describe("formatTree / treeExitCode", () => {
  test("renders each package, the summary line, and the aggregate verdict", () => {
    const out = formatTree(gated);
    assert.match(out, /leftpad-lite@1\.0\.0/);
    assert.match(out, /color-stream@1\.4\.1/);
    assert.match(out, /exfiltrates env to network/);
    assert.match(out, /1 allow · 0 warn · 1 block · 0 error/);
    assert.match(out, /BLOCK/);
    assert.match(out, /GATED/);
  });

  test("exit code is 2 when gated, 0 otherwise", () => {
    assert.equal(treeExitCode(gated), 2);
    assert.equal(treeExitCode(clean), 0);
  });
});
