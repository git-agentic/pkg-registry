import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { formatViolations, type ViolationRow } from "../src/format.js";

const rows: ViolationRow[] = [
  {
    name: "color-stream", version: "1.4.1", kind: "network", target: "203.0.113.5",
    confidence: "high", quarantined: true,
    evidence: { exitCode: 1, stderrExcerpt: "connect ECONNREFUSED 203.0.113.5:443" },
  },
  {
    name: "leftpad-lite", version: "1.0.0", kind: "file-write", target: "/tmp/probe",
    confidence: "low", quarantined: false,
    evidence: { exitCode: 0, stderrExcerpt: "" },
  },
];

describe("formatViolations", () => {
  test("renders QUARANTINED for a quarantined row, including its target", () => {
    const out = formatViolations(rows);
    assert.match(out, /QUARANTINED/);
    assert.match(out, /color-stream@1\.4\.1/);
    assert.match(out, /network → 203\.0\.113\.5/);
    assert.match(out, /LOW/);
    assert.match(out, /leftpad-lite@1\.0\.0/);
  });

  test("empty list renders 'none recorded'", () => {
    const out = formatViolations([]);
    assert.match(out, /none recorded/);
    assert.match(out, /runtime violations \(0\)/);
  });
});
