import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { aggregateTree, type TreePackageRow } from "../src/tree.js";

function row(status: TreePackageRow["status"]): TreePackageRow {
  return { name: "p", version: "1.0.0", status, score: null, topFinding: null, error: null };
}

describe("aggregateTree", () => {
  test("worst-case-wins verdict and counts", () => {
    const a = aggregateTree([row("allow"), row("warn"), row("block"), row("allow")], "block");
    assert.equal(a.verdict, "block");
    assert.deepEqual(a.counts, { allow: 2, warn: 1, block: 1, error: 0 });
    assert.equal(a.gated, true);
  });

  test("gates at the treeGate level", () => {
    const warnTree = [row("allow"), row("warn")];
    assert.equal(aggregateTree(warnTree, "block").gated, false); // worst=warn, gate=block
    assert.equal(aggregateTree(warnTree, "warn").gated, true);   // worst=warn, gate=warn
  });

  test("error rows are counted but never set the verdict or the gate", () => {
    const a = aggregateTree([row("allow"), row("error"), row("error")], "block");
    assert.equal(a.verdict, "allow");
    assert.equal(a.gated, false);
    assert.equal(a.counts.error, 2);
  });

  test("empty tree is allow / not gated", () => {
    const a = aggregateTree([], "block");
    assert.equal(a.verdict, "allow");
    assert.equal(a.gated, false);
  });

  test("aggregate is order-independent", () => {
    const rows = [row("block"), row("allow"), row("warn")];
    const forward = aggregateTree(rows, "block");
    const reversed = aggregateTree([...rows].reverse(), "block");
    assert.deepEqual(forward, reversed);
  });
});
