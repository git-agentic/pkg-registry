import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const base = {
  name: "left-pad", version: "1.3.0", integrity: "sha512-AAA",
  reason: "needed for string padding", requestedBy: { type: "agent" as const, id: "mcp" },
  capabilities: [{ kind: "network" as const, target: "*", evidence: [] }],
};

describe("ApprovalRequestStore", () => {
  test("records a pending request, retrievable by integrity", () => {
    const s = new ApprovalRequestStore();
    const rec = s.record(base, "2026-07-07T00:00:00Z");
    assert.equal(rec.requestedAt, "2026-07-07T00:00:00Z");
    assert.equal(s.get("sha512-AAA")?.reason, "needed for string padding");
    assert.equal(s.recent().length, 1);
  });

  test("re-recording the same integrity replaces (no duplicate)", () => {
    const s = new ApprovalRequestStore();
    s.record(base);
    s.record({ ...base, reason: "updated reason" });
    assert.equal(s.recent().length, 1);
    assert.equal(s.get("sha512-AAA")?.reason, "updated reason");
  });

  test("clear removes the request", () => {
    const s = new ApprovalRequestStore();
    s.record(base);
    assert.equal(s.clear("sha512-AAA"), true);
    assert.equal(s.get("sha512-AAA"), undefined);
    assert.equal(s.clear("sha512-AAA"), false);
  });
});
