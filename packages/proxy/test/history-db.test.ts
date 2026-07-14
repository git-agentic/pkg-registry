import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { HistoryDb } from "../src/history-db.js";
import type { AuditReport } from "@agentic-sentinel/core";
import type { ViolationRecord } from "../src/violations.js";

function auditReport(over: Partial<{ integrity: string; name: string; version: string; verdict: "allow" | "warn" | "block"; score: number; finding: string; signature: string; provenance: string }> = {}): AuditReport {
  return {
    schema: 3,
    meta: {
      name: over.name ?? "leftpad-lite", version: over.version ?? "1.0.0",
      integrity: over.integrity ?? "sha512-aaa",
      signature: (over.signature ?? "unsigned") as never,
      provenance: (over.provenance ?? "absent") as never,
    },
    score: over.score ?? 100,
    verdict: over.verdict ?? "allow",
    findings: over.finding ? [{ id: "x", message: over.finding, severity: "high", category: "metadata", weight: 25 } as never] : [],
  } as unknown as AuditReport;
}
function violation(over: Partial<ViolationRecord> = {}): ViolationRecord {
  return {
    name: "evil", version: "1.0.0", integrity: over.integrity ?? "sha512-v",
    kind: over.kind ?? "network", target: over.target ?? "203.0.113.9",
    confidence: over.confidence ?? "confirmed", deniedResource: over.deniedResource ?? null,
    evidence: { exitCode: 1, stderrExcerpt: "denied" },
    quarantined: over.quarantined ?? true, reportedAt: over.reportedAt ?? "2026-07-01T00:00:00Z",
    ...over,
  } as ViolationRecord;
}

describe("HistoryDb — schema, writes, summary", () => {
  test("recordAudit + summary counts verdict/signature/provenance", () => {
    const db = new HistoryDb(":memory:");
    db.recordAudit(auditReport({ integrity: "sha512-a", verdict: "allow", signature: "verified", provenance: "verified" }), "2026-07-01T10:00:00Z");
    db.recordAudit(auditReport({ integrity: "sha512-b", verdict: "block", score: 10 }), "2026-07-01T11:00:00Z");
    const s = db.summary();
    assert.equal(s.total, 2);
    assert.equal(s.verdict.allow, 1);
    assert.equal(s.verdict.block, 1);
    assert.equal(s.signature.verified, 1);
    assert.equal(s.provenance.verified, 1);
    db.close();
  });

  test("recordAudit is upsert-ignore: re-recording an integrity does not duplicate or move audited_at", () => {
    const db = new HistoryDb(":memory:");
    db.recordAudit(auditReport({ integrity: "sha512-a", verdict: "block" }), "2026-07-01T10:00:00Z");
    db.recordAudit(auditReport({ integrity: "sha512-a", verdict: "allow" }), "2026-07-05T10:00:00Z"); // ignored
    const s = db.summary();
    assert.equal(s.total, 1);
    assert.equal(s.verdict.block, 1); // kept the first row
    assert.equal(s.verdict.allow, 0);
    db.close();
  });

  test("recordViolation is append-only: suspected then confirmed keeps both", () => {
    const db = new HistoryDb(":memory:");
    db.recordViolation(violation({ integrity: "sha512-v", confidence: "suspected", quarantined: false, reportedAt: "2026-07-01T00:00:00Z" }));
    db.recordViolation(violation({ integrity: "sha512-v", confidence: "confirmed", quarantined: true, reportedAt: "2026-07-01T00:00:05Z" }));
    const s = db.summary();
    assert.equal(s.violations, 2);
    assert.equal(s.quarantined, 1);
    db.close();
  });

  test("native download counting dedupes one package version per npm session", () => {
    const db = new HistoryDb(":memory:");
    assert.deepEqual(db.recordDownload({ name: "@acme/x", version: "1.0.0", integrity: "sha512-x", npmSession: "session-a", servedAt: "2026-07-13T10:00:00Z" }), { count: 1, recorded: true });
    assert.deepEqual(db.recordDownload({ name: "@acme/x", version: "1.0.0", integrity: "sha512-x", npmSession: "session-a", servedAt: "2026-07-13T10:00:01Z" }), { count: 1, recorded: false });
    db.recordDownload({ name: "@acme/x", version: "1.0.0", integrity: "sha512-x", npmSession: "session-b", servedAt: "2026-07-13T10:00:02Z" });
    db.recordDownload({ name: "@acme/x", version: "1.0.0", integrity: "sha512-x", servedAt: "2026-07-13T10:00:03Z" });
    db.recordDownload({ name: "@acme/x", version: "1.0.0", integrity: "sha512-x", servedAt: "2026-07-13T10:00:04Z" });
    assert.equal(db.downloadCount("@acme/x", "1.0.0"), 4);
    db.close();
  });

  test("window-hit telemetry is append-only and never rewrites stored audit reports", () => {
    const db = new HistoryDb(":memory:");
    db.recordAudit(auditReport({ integrity: "sha512-immutable" }), "2026-07-13T09:00:00Z");
    const before = JSON.stringify(db.allReports());
    db.recordRetractionWindowHit({
      name: "@acme/x", version: "1.0.0", ageHours: 73, downloads: 5,
      maxAgeHours: 72, maxDownloads: 1_000, ageExceeded: true, downloadsExceeded: false,
      attemptedAt: "2026-07-13T10:00:00Z",
    });
    assert.equal(db.retractionWindowHits().length, 1);
    assert.equal(db.retractionWindowHits()[0]?.ageExceeded, true);
    assert.equal(JSON.stringify(db.allReports()), before);
    db.close();
  });
});
