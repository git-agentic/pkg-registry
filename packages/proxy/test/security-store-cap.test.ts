import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { AuditReport } from "@git-agentic/sentinel-core";
import { AuditStore, MAX_AUDIT_ENTRIES } from "../src/store.js";

function report(name: string, integrity: string): AuditReport {
  return { schema: 3, meta: { name, version: "1.0.0", integrity }, verdict: "allow", score: 100, findings: [], policy: { version: "t", hash: "h" } } as unknown as AuditReport;
}

describe("AuditStore is bounded", () => {
  test("keeps at most MAX_AUDIT_ENTRIES, evicting the oldest by insertion order", () => {
    const store = new AuditStore();
    const extra = 5;
    for (let i = 0; i < MAX_AUDIT_ENTRIES + extra; i++) store.put(report(`pkg-${i}`, `sha512-${i}`));
    assert.equal(store.stats().total, MAX_AUDIT_ENTRIES);
    for (let i = 0; i < extra; i++) assert.equal(store.get(`pkg-${i}`, "1.0.0", `sha512-${i}`), undefined, `pkg-${i} should be evicted`);
    const last = MAX_AUDIT_ENTRIES + extra - 1;
    assert.ok(store.get(`pkg-${last}`, "1.0.0", `sha512-${last}`));
    assert.ok(store.get(`pkg-${extra}`, "1.0.0", `sha512-${extra}`), "the oldest survivor is still cached");
    assert.equal(store.recent(1)[0]!.name, `pkg-${last}`);
  });

  test("re-putting an existing coordinate does not evict anything", () => {
    const store = new AuditStore();
    for (let i = 0; i < 10; i++) store.put(report("same", "sha512-same"));
    assert.equal(store.stats().total, 1);
  });
});
