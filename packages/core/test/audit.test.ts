import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { auditTarball, type AuditReport } from "../src/index.js";
import { ensureFixtures, tarball } from "./helpers.js";

const baseMeta = {
  author: null,
  maintainers: [] as string[],
  license: null,
  hasInstallScripts: false,
  signatureStatus: "unknown" as const,
};

async function audit(name: string, version: string, baselineVersion?: string): Promise<AuditReport> {
  return auditTarball({
    meta: { name, version, ...baseMeta },
    tarball: tarball(name, version),
    baselineTarball: baselineVersion ? tarball(name, baselineVersion) : undefined,
  });
}

describe("audit engine", () => {
  before(() => ensureFixtures());

  test("benign package scores 100 and is allowed", async () => {
    const r = await audit("leftpad-lite", "1.0.1");
    assert.equal(r.verdict, "allow");
    assert.equal(r.score, 100);
    assert.equal(r.findings.length, 0);
    assert.ok(r.meta.fileCount >= 2, "should count package files");
    assert.ok(r.meta.unpackedSize > 0);
  });

  test("clean baseline version of the trojaned package is allowed", async () => {
    const r = await audit("color-stream", "1.4.0");
    assert.equal(r.verdict, "allow");
    assert.equal(r.score, 100);
  });

  test("MALICIOUS release is blocked with score 0", async () => {
    const r = await audit("color-stream", "1.4.1", "1.4.0");
    assert.equal(r.verdict, "block");
    assert.equal(r.score, 0);
    assert.equal(r.engine.mode, "diff");
    assert.ok(r.meta.hasInstallScripts, "must detect the postinstall hook");
  });

  test("malicious release triggers every rule category", async () => {
    const r = await audit("color-stream", "1.4.1", "1.4.0");
    const cats = new Set(r.findings.map((f) => f.category));
    for (const c of ["install-script", "secret-exfil", "network", "obfuscation"]) {
      assert.ok(cats.has(c as never), `expected a ${c} finding`);
    }
    const crit = r.findings.filter((f) => f.severity === "critical");
    assert.ok(crit.length >= 2, "secret-exfil + install-script should both be critical");
  });

  test("secret-exfil finding cites correlated egress as critical", async () => {
    const r = await audit("color-stream", "1.4.1", "1.4.0");
    const exfil = r.findings.find((f) => f.ruleId === "secret-exfil");
    assert.ok(exfil);
    assert.equal(exfil.severity, "critical");
    assert.ok(exfil.evidence.length > 0, "must include evidence snippets");
  });

  test("scoring is deterministic across runs", async () => {
    const a = await audit("color-stream", "1.4.1", "1.4.0");
    const b = await audit("color-stream", "1.4.1", "1.4.0");
    assert.equal(a.score, b.score);
    assert.deepEqual(
      a.findings.map((f) => [f.ruleId, f.severity, f.weight]),
      b.findings.map((f) => [f.ruleId, f.severity, f.weight]),
    );
  });

  test("diff mode weights changed files more heavily than full mode", async () => {
    const diff = await audit("color-stream", "1.4.1", "1.4.0");
    const full = await audit("color-stream", "1.4.1");
    const sum = (r: AuditReport) => r.findings.reduce((s, f) => s + f.weight, 0);
    assert.ok(sum(diff) >= sum(full), "diff penalties should be >= full penalties");
    // both still block; the malware is caught regardless of mode
    assert.equal(diff.verdict, "block");
    assert.equal(full.verdict, "block");
  });

  test("integrity hash is computed and stable", async () => {
    const a = await audit("leftpad-lite", "1.0.0");
    const b = await audit("leftpad-lite", "1.0.0");
    assert.match(a.meta.integrity ?? "", /^sha512-/);
    assert.equal(a.meta.integrity, b.meta.integrity);
  });
});
