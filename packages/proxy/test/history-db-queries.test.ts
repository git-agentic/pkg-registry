import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { HistoryDb } from "../src/history-db.js";
import type { AuditReport } from "@git-agentic/sentinel-core";
import type { ViolationRecord } from "../src/violations.js";

function rep(integrity: string, name: string, verdict: "allow" | "warn" | "block", finding: string | null, at: string): [AuditReport, string] {
  return [{
    schema: 3,
    meta: { name, version: "1.0.0", integrity, signature: "unsigned", provenance: "absent" },
    score: verdict === "block" ? 10 : verdict === "warn" ? 60 : 100, verdict,
    findings: finding ? [{ id: "x", message: finding, severity: "high", category: "metadata", weight: 25 }] : [],
  } as unknown as AuditReport, at];
}

describe("HistoryDb queries", () => {
  function seed(): HistoryDb {
    const db = new HistoryDb(":memory:");
    db.recordAudit(...rep("sha512-1", "left-pad", "block", "install script", "2026-07-01T10:00:00Z"));
    db.recordAudit(...rep("sha512-2", "left-pad", "warn", "network egress", "2026-07-01T12:00:00Z"));
    db.recordAudit(...rep("sha512-3", "chalk", "allow", null, "2026-07-02T09:00:00Z"));
    db.recordAudit(...rep("sha512-4", "evil", "block", "secret exfil", "2026-07-02T15:00:00Z"));
    db.recordViolation({ name: "evil", version: "1.0.0", integrity: "sha512-4", kind: "network", target: "203.0.113.9", confidence: "confirmed", deniedResource: null, evidence: { exitCode: 1, stderrExcerpt: "x" }, quarantined: true, reportedAt: "2026-07-02T15:01:00Z" } as ViolationRecord);
    return db;
  }

  test("history filters by verdict and paginates, most-recent first", () => {
    const db = seed();
    const blocks = db.history({ verdict: "block", limit: 10, offset: 0 });
    assert.deepEqual(blocks.map((r) => r.name), ["evil", "left-pad"]); // 07-02 before 07-01
    assert.equal(blocks[0]!.topFinding, "secret exfil");
    const page = db.history({ limit: 2, offset: 0 });
    assert.equal(page.length, 2);
    db.close();
  });

  test("history filters by name", () => {
    const db = seed();
    assert.equal(db.history({ name: "left-pad", limit: 10, offset: 0 }).length, 2);
    db.close();
  });

  test("trends buckets verdicts per day, chronological", () => {
    const db = seed();
    const t = db.trends({ limit: 30 });
    assert.deepEqual(t, [
      { date: "2026-07-01", allow: 0, warn: 1, block: 1 },
      { date: "2026-07-02", allow: 1, warn: 0, block: 1 },
    ]);
    db.close();
  });

  test("topFlagged ranks by warn+block count", () => {
    const db = seed();
    const top = db.topFlagged({ limit: 10 });
    assert.equal(top[0]!.name, "left-pad"); // 1 warn + 1 block = 2
    assert.equal(top[0]!.warn, 1);
    assert.equal(top[0]!.block, 1);
    db.close();
  });

  test("violationTimeline returns recent events", () => {
    const db = seed();
    const tl = db.violationTimeline({ limit: 50 });
    assert.equal(tl.length, 1);
    assert.equal(tl[0]!.name, "evil");
    assert.equal(tl[0]!.quarantined, true);
    assert.equal(tl[0]!.detail, "network:203.0.113.9");
    db.close();
  });

  test("allReports returns the stored AuditReports, newest-first, bounded by limit", () => {
    const db = new HistoryDb(":memory:");
    const rep = (integrity: string, name: string, verdict: "allow" | "block"): AuditReport =>
      ({ schema: 3, meta: { name, version: "1.0.0", integrity, signature: "unsigned", provenance: "absent" }, score: verdict === "block" ? 10 : 100, verdict, findings: [] } as unknown as AuditReport);
    db.recordAudit(rep("sha512-1", "a", "allow"), "2026-07-01T00:00:00Z");
    db.recordAudit(rep("sha512-2", "b", "block"), "2026-07-02T00:00:00Z");
    const all = db.allReports();
    assert.equal(all.length, 2);
    assert.equal(all.every((r) => r.schema === 3), true);
    assert.equal(all[0]!.meta.name, "b"); // newest-first
    assert.equal(db.allReports(1).length, 1); // limit caps
    db.close();
  });
});
