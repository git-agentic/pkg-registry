import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { AuditStore } from "../src/store.js";

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
    assert.equal(store.get("sha512-legacy"), undefined, "schema-1 entry is not served from cache");
  });
});
