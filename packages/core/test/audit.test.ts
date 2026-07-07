import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { auditTarball, runAudit, integrityOf, NPM_SIGNING_KEYS, type AuditReport, type NpmSigningKey, type RegistrySignature } from "../src/index.js";
import { ensureFixtures, tarball } from "./helpers.js";

const baseMeta = {
  author: null,
  maintainers: [] as string[],
  license: null,
  hasInstallScripts: false,
};

// A synthetic registry-signing key used to make these fixtures resolve to
// signature: "verified" through the real runAudit verification path. These
// fixtures don't claim provenance (no attestation bundles are wired here) —
// hasProvenance stays false so provenance is "absent" and these signature-
// focused tests aren't perturbed by the (Task 9) provenance-status finding.
const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const spkiPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
const TEST_KEYID = "SHA256:" + createHash("sha256").update(spkiDer).digest("base64");
const TEST_KEYS: NpmSigningKey[] = [{ keyid: TEST_KEYID, spkiPem, expires: null }];

function signFor(name: string, version: string, integrity: string): RegistrySignature {
  const sig = sign("sha256", Buffer.from(`${name}@${version}:${integrity}`), privateKey);
  return { keyid: TEST_KEYID, sig: sig.toString("base64") };
}

async function audit(name: string, version: string, baselineVersion?: string): Promise<AuditReport> {
  const tgz = tarball(name, version);
  const integrity = integrityOf(tgz);
  return auditTarball({
    meta: { name, version, ...baseMeta, integrity },
    tarball: tgz,
    baselineTarball: baselineVersion ? tarball(name, baselineVersion) : undefined,
    signatures: [signFor(name, version, integrity)],
    hasProvenance: false,
    signingKeys: TEST_KEYS,
  });
}

describe("audit engine", () => {
  before(() => ensureFixtures());

  test("benign package scores 100 and is allowed", async () => {
    const r = await audit("leftpad-lite", "1.0.1");
    assert.equal(r.verdict, "allow");
    assert.equal(r.score, 100);
    // The only finding is the informational "no provenance attestation" note
    // (this fixture doesn't claim provenance) — info severity, zero weight.
    assert.deepEqual(r.findings.map((f) => f.ruleId), ["provenance"]);
    assert.equal(r.findings[0]!.severity, "info");
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

  test("runAudit populates signature/provenance (unsigned when no signatures)", async () => {
    const tgz = tarball("leftpad-lite", "1.0.0");
    const audit = await runAudit({
      meta: { name: "demo", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity: "sha512-x" },
      tarball: tgz,
      signatures: null,
      hasProvenance: false,
      signingKeys: NPM_SIGNING_KEYS,
    });
    assert.equal(audit.meta.signature, "unsigned");
    assert.equal(audit.meta.provenance, "absent");
  });
});

describe("phase 9: integrity recompute + provenance wiring", () => {
  test("claimed integrity mismatch yields a critical integrity-mismatch finding and actual integrity on meta", async () => {
    const tgz = tarball("leftpad-lite", "1.0.0");
    const audit = await runAudit({
      meta: { name: "leftpad-lite", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity: "sha512-BOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUSBOGUS==" },
      tarball: tgz, signatures: null, hasProvenance: false, attestations: null, trustMaterial: null,
    });
    const f = audit.findings.find((x) => x.ruleId === "integrity-mismatch");
    assert.ok(f, "integrity-mismatch finding expected");
    assert.equal(f!.severity, "critical");
    assert.notEqual(audit.meta.integrity, "sha512-BOGUS…");
    assert.match(audit.meta.integrity!, /^sha512-/);
  });

  test("matching claimed integrity yields no tamper finding", async () => {
    const tgz = tarball("leftpad-lite", "1.0.0");
    const { integrityOf } = await import("../src/extract.js");
    const audit = await runAudit({
      meta: { name: "leftpad-lite", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity: integrityOf(tgz) },
      tarball: tgz, signatures: null, hasProvenance: false, attestations: null, trustMaterial: null,
    });
    assert.equal(audit.findings.find((x) => x.ruleId === "integrity-mismatch"), undefined);
  });

  test("provenance status flows to meta: claimed + no bundles + no trust = unknown", async () => {
    const audit = await runAudit({
      meta: { name: "x", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false },
      tarball: tarball("leftpad-lite", "1.0.0"), signatures: null,
      hasProvenance: true, attestations: null, trustMaterial: null,
    });
    assert.equal(audit.meta.provenance, "unknown");
  });
});
