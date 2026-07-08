import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { HistoryDb } from "../src/history-db.js";
import { AuditStore } from "../src/store.js";
import { ViolationStore } from "../src/violations.js";
import type { AuditReport } from "@sentinel/core";
import type { ViolationRecord } from "../src/violations.js";

const report = {
  schema: 3, meta: { name: "p", version: "1.0.0", integrity: "sha512-w", signature: "unsigned", provenance: "absent" },
  score: 100, verdict: "allow", findings: [],
} as unknown as AuditReport;

describe("store write-through to HistoryDb", () => {
  test("AuditStore.put with a HistoryDb lands an audit row", () => {
    const h = new HistoryDb(":memory:");
    const store = new AuditStore(undefined, undefined, h);
    store.put(report);
    assert.equal(h.summary().total, 1);
    h.close();
  });

  test("AuditStore.put without a HistoryDb still works (default path unchanged)", () => {
    const store = new AuditStore();
    assert.equal(store.put(report).name, "p");
    assert.equal(store.stats().total, 1);
  });

  test("ViolationStore.record with a HistoryDb lands a violation row", () => {
    const h = new HistoryDb(":memory:");
    const vs = new ViolationStore(undefined, h);
    vs.record({ name: "evil", version: "1.0.0", integrity: "sha512-v", kind: "network", target: "203.0.113.9", confidence: "confirmed", deniedResource: null, evidence: { exitCode: 1, stderrExcerpt: "x" } });
    assert.equal(h.summary().violations, 1);
    h.close();
  });

  test("a HistoryDb whose write throws is swallowed; the store record still succeeds", () => {
    const broken = { recordAudit() { throw new Error("db down"); } } as unknown as HistoryDb;
    const store = new AuditStore(undefined, undefined, broken);
    assert.equal(store.put(report).name, "p"); // no throw
  });
});
