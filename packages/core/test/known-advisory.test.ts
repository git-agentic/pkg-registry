import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { knownAdvisoryRule } from "../src/rules/known-advisory.js";
import { KNOWN_ADVISORIES, parseAdvisories, type Advisory } from "../src/advisory-corpus.js";
import type { AuditInput, PackageMeta } from "../src/types.js";
import { buildAudit } from "../src/audit.js";
import { score } from "../src/score.js";
import { DEFAULT_POLICY } from "../src/policy.js";

function input(name: string, version: string, advisories?: Advisory[]): AuditInput {
  return { meta: { name, version } as PackageMeta, files: [], mode: "full", advisories };
}
const A = (over: Partial<Advisory> = {}): Advisory => ({ name: "evil-pkg", version: "1.0.0", id: "MAL-TEST-0001", ...over });

describe("known-advisory rule", () => {
  test("an operator-supplied advisory match → a critical metadata finding naming the id", () => {
    const fs = knownAdvisoryRule.run(input("evil-pkg", "1.0.0", [A()]));
    assert.equal(fs.length, 1);
    assert.equal(fs[0]!.severity, "critical");
    assert.equal(fs[0]!.category, "metadata");
    assert.match(fs[0]!.message, /MAL-TEST-0001/);
  });

  test("a non-matching version → no finding", () => {
    assert.deepEqual(knownAdvisoryRule.run(input("evil-pkg", "2.0.0", [A()])), []);
  });

  test("a per-advisory severity is honored", () => {
    assert.equal(knownAdvisoryRule.run(input("evil-pkg", "1.0.0", [A({ severity: "high" })]))[0]!.severity, "high");
  });

  test("operator advisories MERGE with the bundled corpus (both fire)", () => {
    const bundled = KNOWN_ADVISORIES[0]!;
    assert.equal(knownAdvisoryRule.run(input(bundled.name, bundled.version)).length, 1); // bundled alone
    assert.equal(knownAdvisoryRule.run(input("evil-pkg", "1.0.0", [A()])).length, 1);    // operator alone
  });

  test("no advisories + clean package → inert", () => {
    assert.deepEqual(knownAdvisoryRule.run(input("totally-fine", "9.9.9")), []);
  });

  test("a bundled known-advisory match HARD-BLOCKS under the default policy (feature promise, not just the finding)", () => {
    const b = KNOWN_ADVISORIES[0]!;
    const meta: PackageMeta = {
      name: b.name, version: b.version, integrity: null, unpackedSize: 0, fileCount: 0,
      hasInstallScripts: false, signature: "unknown", provenance: "unknown",
    } as PackageMeta;
    const audit = buildAudit(meta, []);
    const report = score(audit, DEFAULT_POLICY);
    assert.equal(report.verdict, "block");
    assert.ok(report.findings.some((f) => f.ruleId === "known-advisory"));
  });
});

describe("KNOWN_ADVISORIES corpus hygiene", () => {
  test("non-empty; every entry has name+version+id; no duplicate (name,version)", () => {
    assert.ok(KNOWN_ADVISORIES.length > 0);
    const seen = new Set<string>();
    for (const a of KNOWN_ADVISORIES) {
      assert.ok(a.name && a.version && a.id, `malformed entry: ${JSON.stringify(a)}`);
      const key = `${a.name}@${a.version}`;
      assert.equal(seen.has(key), false, `duplicate ${key}`);
      seen.add(key);
    }
  });
});

describe("parseAdvisories", () => {
  test("well-formed → parsed; malformed entry dropped; garbage → []", () => {
    const raw = JSON.stringify([{ name: "a", version: "1", id: "X" }, { name: "b" }, { version: "2", id: "Y" }]);
    assert.deepEqual(parseAdvisories(raw), [{ name: "a", version: "1", id: "X" }]);
    assert.deepEqual(parseAdvisories("not json"), []);
    assert.deepEqual(parseAdvisories(JSON.stringify({ not: "an array" })), []);
  });
});
