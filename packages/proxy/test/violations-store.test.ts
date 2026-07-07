import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { ViolationStore } from "../src/violations.js";

const base = {
  name: "evil", version: "1.0.0", integrity: "sha512-AAA",
  kind: "filesystem" as const, target: "/Users/x/.ssh/id_rsa",
  confidence: "confirmed" as const, deniedResource: "/Users/x/.ssh",
  evidence: { exitCode: 1, stderrExcerpt: "EPERM ..." },
};

describe("ViolationStore", () => {
  test("a confirmed violation is recorded and quarantines the integrity", () => {
    const s = new ViolationStore();
    const rec = s.record(base);
    assert.equal(rec.quarantined, true);
    assert.equal(s.isQuarantined("sha512-AAA"), true);
    assert.equal(s.get("sha512-AAA")?.target, "/Users/x/.ssh/id_rsa");
  });

  test("a suspected violation is recorded but does NOT quarantine", () => {
    const s = new ViolationStore();
    const rec = s.record({ ...base, confidence: "suspected", target: null, deniedResource: null });
    assert.equal(rec.quarantined, false);
    assert.equal(s.isQuarantined("sha512-AAA"), false);
  });

  test("idempotent on (integrity, kind, target): no duplicate records", () => {
    const s = new ViolationStore();
    s.record(base);
    s.record(base);
    assert.equal(s.recent().length, 1);
  });

  test("a suspected report does NOT lift a confirmed quarantine", () => {
    const s = new ViolationStore();
    s.record(base);
    const rec = s.record({ ...base, confidence: "suspected", kind: "network", target: null, deniedResource: null });
    assert.equal(s.isQuarantined("sha512-AAA"), true);
    assert.equal(rec.confidence, "confirmed");
  });

  test("clear removes the quarantine", () => {
    const s = new ViolationStore();
    s.record(base);
    assert.equal(s.clear("sha512-AAA"), true);
    assert.equal(s.isQuarantined("sha512-AAA"), false);
  });
});
