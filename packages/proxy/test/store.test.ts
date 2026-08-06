import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import type { AuditReport } from "@git-agentic/sentinel-core";
import { AuditStore } from "../src/store.js";

function report(name: string, integrity: string): AuditReport {
  return {
    schema: 3,
    meta: { name, version: "1.0.0", integrity },
    verdict: "allow",
    score: 100,
    findings: [],
    policy: { version: "test", hash: "sha256-test" },
  } as unknown as AuditReport;
}

describe("AuditStore schema handling", () => {
  test("drops persisted schema-1 audits on load", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-store-"));
    const file = join(dir, "audits.json");
    const legacy = [{
      key: "old@1.0.0", name: "old", version: "1.0.0",
      report: { schema: 1, meta: { integrity: "sha512-legacy" }, verdict: "allow", score: 100, findings: [] },
    }];
    writeFileSync(file, JSON.stringify(legacy));
    const store = new AuditStore(file);
    assert.equal(store.get("old", "1.0.0", "sha512-legacy"), undefined, "schema-1 entry is not served from cache");
  });

  test("drops persisted schema-3 audits that lack actual integrity", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-store-"));
    const file = join(dir, "audits.json");
    const missingIntegrity = report("old", "sha512-placeholder");
    missingIntegrity.meta.integrity = null;
    writeFileSync(file, JSON.stringify([{
      key: "old@1.0.0", name: "old", version: "1.0.0", report: missingIntegrity,
    }]));

    assert.equal(new AuditStore(file).stats().total, 0);
  });
});

describe("AuditStore cache identity", () => {
  test("stores byte-identical package coordinates independently", () => {
    const store = new AuditStore();
    store.put(report("express", "sha512-shared"));
    store.put(report("expres", "sha512-shared"));

    assert.equal(store.get("express", "1.0.0", "sha512-shared")?.name, "express");
    assert.equal(store.get("expres", "1.0.0", "sha512-shared")?.name, "expres");
    assert.equal(store.stats().total, 2);
  });

  test("integrity-only control-plane lookup fails closed when bytes are shared", () => {
    const store = new AuditStore();
    store.put(report("express", "sha512-shared"));
    assert.equal(store.getUniqueByIntegrity("sha512-shared")?.name, "express");

    store.put(report("expres", "sha512-shared"));
    assert.equal(store.getUniqueByIntegrity("sha512-shared"), undefined);
  });

  test("rejects a new report without actual integrity", () => {
    const store = new AuditStore();
    const missingIntegrity = report("express", "sha512-placeholder");
    missingIntegrity.meta.integrity = null;
    assert.throws(() => store.put(missingIntegrity), /without actual integrity/);
  });
});
