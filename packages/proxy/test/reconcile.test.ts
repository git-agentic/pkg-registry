import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Capability } from "@agentic-sentinel/core";
import { reconcileApproval } from "../src/reconcile.js";
import type { Approval } from "../src/approvals.js";

const net = (t: string): Capability => ({ kind: "network", target: t, evidence: [] });
function approval(caps: Capability[], over: Partial<Approval> = {}): Approval {
  return { name: "pkg", version: "1.0.0", integrity: "x", decision: "approved",
    approvedCapabilities: caps, actor: { type: "agent", id: "ci" }, decidedAt: "t", ...over };
}

describe("reconcileApproval", () => {
  test("n-a when there are no capabilities", () => {
    assert.equal(reconcileApproval({ capabilities: [] }).state, "n-a");
  });
  test("approved when an explicit approval exists for this integrity", () => {
    const r = reconcileApproval({ capabilities: [net("a")], explicit: approval([net("a")]) });
    assert.equal(r.state, "approved");
  });
  test("denied when an explicit denial exists", () => {
    const r = reconcileApproval({ capabilities: [net("a")], explicit: approval([], { decision: "denied" }) });
    assert.equal(r.state, "denied");
  });
  test("required at first sight (no prior approval)", () => {
    const r = reconcileApproval({ capabilities: [net("a")] });
    assert.equal(r.state, "required");
    assert.deepEqual(r.approvalRequired.map((c) => c.target), ["a"]);
  });
  test("inherited when caps are a subset of a prior approved version", () => {
    const r = reconcileApproval({ capabilities: [net("a")], priorApproved: approval([net("a")], { version: "1.0.0" }) });
    assert.equal(r.state, "inherited");
    assert.equal(r.inheritedFrom, "1.0.0");
    assert.equal(r.approvalRequired.length, 0);
  });
  test("required when a NEW atom appears vs the prior approved version", () => {
    const r = reconcileApproval({ capabilities: [net("a"), net("b")], priorApproved: approval([net("a")], { version: "1.0.0" }) });
    assert.equal(r.state, "required");
    assert.deepEqual(r.approvalRequired.map((c) => c.target), ["b"]);
  });
});
