import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { ApprovalStore, type Approval } from "../src/approvals.js";

function approval(over: Partial<Approval> = {}): Approval {
  return {
    name: "pkg", version: "1.0.0", integrity: "sha512-a", decision: "approved",
    approvedCapabilities: [], actor: { type: "agent", id: "ci" }, decidedAt: "2026-06-24T00:00:00.000Z",
    ...over,
  };
}

describe("ApprovalStore", () => {
  test("put/get by integrity", () => {
    const s = new ApprovalStore();
    s.put(approval({ integrity: "sha512-x" }));
    assert.equal(s.get("sha512-x")?.decision, "approved");
    assert.equal(s.get("sha512-missing"), undefined);
  });

  test("remove revokes", () => {
    const s = new ApprovalStore();
    s.put(approval({ integrity: "sha512-x" }));
    assert.equal(s.remove("sha512-x"), true);
    assert.equal(s.get("sha512-x"), undefined);
  });

  test("latestApprovedFor returns the highest approved semver, ignoring denials", () => {
    const s = new ApprovalStore();
    s.put(approval({ version: "1.0.0", integrity: "a", decision: "approved" }));
    s.put(approval({ version: "1.2.0", integrity: "b", decision: "approved" }));
    s.put(approval({ version: "1.3.0", integrity: "c", decision: "denied" }));
    assert.equal(s.latestApprovedFor("pkg")?.version, "1.2.0");
    assert.equal(s.latestApprovedFor("other"), undefined);
  });
});
