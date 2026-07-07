import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { runAudit, score, integrityOf, DEFAULT_POLICY, matchPackage, type EnterprisePolicy, type NpmSigningKey, type RegistrySignature } from "../src/index.js";
import { ensureFixtures, tarball } from "./helpers.js";
import type { Audit, PackageMeta } from "../src/types.js";

const baseMeta = {
  author: null, maintainers: [] as string[], license: null,
  hasInstallScripts: false,
};

// A synthetic registry-signing key so these fixtures resolve to
// signature: "verified" through the real runAudit verification path. No
// attestation bundles are wired here, so provenance stays "absent" (info,
// zero weight) rather than claiming provenance we can't actually verify.
const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const spkiPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
const TEST_KEYID = "SHA256:" + createHash("sha256").update(spkiDer).digest("base64");
const TEST_KEYS: NpmSigningKey[] = [{ keyid: TEST_KEYID, spkiPem, expires: null }];

function signFor(name: string, version: string, integrity: string): RegistrySignature {
  const sig = sign("sha256", Buffer.from(`${name}@${version}:${integrity}`), privateKey);
  return { keyid: TEST_KEYID, sig: sig.toString("base64") };
}

const auditOf = (name: string, version: string, baseline?: string) => {
  const tgz = tarball(name, version);
  const integrity = integrityOf(tgz);
  return runAudit({ meta: { name, version, ...baseMeta, integrity }, tarball: tgz,
    baselineTarball: baseline ? tarball(name, baseline) : undefined,
    signatures: [signFor(name, version, integrity)],
    hasProvenance: false,
    signingKeys: TEST_KEYS,
  });
};

function policy(over: Partial<EnterprisePolicy> = {}): EnterprisePolicy {
  return { ...DEFAULT_POLICY, version: "test", ...over };
}

describe("matchPackage glob", () => {
  test("exact and prefix match, anchored", () => {
    assert.equal(matchPackage("esbuild", "esbuild"), true);
    assert.equal(matchPackage("esbuild", "esbuild-wasm"), false);   // anchored, not substring
    assert.equal(matchPackage("evilcorp-*", "evilcorp-utils"), true);
    assert.equal(matchPackage("@acme/*", "@acme/payments"), true);
    assert.equal(matchPackage("@acme/*", "@other/x"), false);
    assert.equal(matchPackage("a.b", "axb"), false);                // '.' is literal, not regex
  });
});

describe("score under policies", () => {
  before(() => ensureFixtures());

  test("default policy blocks the malicious fixture (regression)", async () => {
    const r = score(await auditOf("color-stream", "1.4.1", "1.4.0"), DEFAULT_POLICY);
    assert.equal(r.verdict, "block");
    assert.equal(r.score, 0);
    assert.equal(r.policy.version, "default");
    assert.match(r.policy.hash, /^sha256-/);
  });

  test("same bytes, two policies → different verdicts", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    const strict = score(audit, DEFAULT_POLICY);
    const lax = score(audit, policy({
      rules: { disabled: ["secret-exfil", "install-scripts", "network-egress", "obfuscation"] },
    }));
    assert.equal(strict.verdict, "block");
    assert.equal(lax.verdict, "allow");           // all rules disabled → nothing scores or hard-blocks
    assert.equal(lax.score, 100);
  });

  test("allow waiver clears a finding from score AND hard-block, keeps it visible", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    // Waive every rule that fires, for this package only.
    const waived = score(audit, policy({
      allow: [{ package: "color-stream", rules: ["secret-exfil", "install-scripts", "network-egress", "obfuscation", "provenance"], reason: "test" }],
    }));
    assert.equal(waived.verdict, "allow", "no non-waived critical remains to hard-block");
    assert.ok(waived.findings.length > 0, "findings still present");
    assert.ok(waived.findings.every((f) => f.waived), "all marked waived");
    assert.ok(waived.findings[0]?.waivedBy?.startsWith("allow: color-stream"));
  });

  test("deny forces block on an otherwise-clean package", async () => {
    const clean = await auditOf("leftpad-lite", "1.0.1");
    const denied = score(clean, policy({ deny: [{ package: "leftpad-lite", reason: "blocked" }] }));
    assert.equal(denied.verdict, "block");
    const allowed = score(clean, DEFAULT_POLICY);
    assert.equal(allowed.verdict, "allow");
  });

  test("threshold + weight overrides change the verdict", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    const lenient = score(audit, policy({
      scoring: { ...DEFAULT_POLICY.scoring, hardBlockSeverity: "critical", severityWeight: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, thresholds: { allow: 0, warn: 0 } },
    }));
    // hardBlock still fires on the (non-waived) critical severity regardless of zeroed weights
    assert.equal(lenient.verdict, "block");
  });

  test("scoring is deterministic for a fixed policy", async () => {
    const audit = await auditOf("color-stream", "1.4.1", "1.4.0");
    const a = score(audit, DEFAULT_POLICY);
    const b = score(audit, DEFAULT_POLICY);
    assert.deepEqual(a.findings.map((f) => [f.ruleId, f.weight, f.waived]), b.findings.map((f) => [f.ruleId, f.weight, f.waived]));
    assert.equal(a.verdict, b.verdict);
  });
});

function auditWith(signature: string, provenance: string, provenanceIdentity?: object | null, name = "acme-lib") {
  return {
    schema: 3 as const, meta: { name, version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, signature, provenance, provenanceIdentity: provenanceIdentity ?? null, integrity: "sha512-x", unpackedSize: 1, fileCount: 1 },
    findings: [], capabilities: [], capabilityDelta: null,
    engine: { version: "0.1.0", rules: [], mode: "full" as const }, auditedAt: "t", durationMs: 0,
  } as Parameters<typeof score>[0];
}

const ID = {
  workflow: "https://github.com/acme/pkg/.github/workflows/release.yml@refs/heads/main",
  issuer: "https://token.actions.githubusercontent.com",
  sourceRepository: "https://github.com/acme/pkg", ref: "refs/heads/main",
  builder: "https://github.com/actions/runner/github-hosted", commit: "abc123",
};

describe("requireSignature / requireProvenance policy gate", () => {
  test("requireSignature blocks a non-verified package", () => {
    const p = { ...DEFAULT_POLICY, requireSignature: ["acme-*"] };
    assert.equal(score(auditWith("unsigned", "verified"), p).verdict, "block");
    assert.equal(score(auditWith("verified", "verified"), p).verdict, "allow");
  });
  test("requireProvenance blocks a package without verified provenance", () => {
    const p = { ...DEFAULT_POLICY, requireProvenance: ["acme-*"] };
    assert.equal(score(auditWith("verified", "absent"), p).verdict, "block");
    assert.equal(score(auditWith("verified", "verified", ID), p).verdict, "allow");
  });
  test("no requirement -> not gated on signature/provenance", () => {
    assert.equal(score(auditWith("unsigned", "absent"), DEFAULT_POLICY).verdict, "allow");
  });
  test("requireProvenance rejects verified provenance without build identity", () => {
    const p = { ...DEFAULT_POLICY, requireProvenance: ["acme-lib"] };
    assert.equal(score(auditWith("verified", "verified"), p).verdict, "block");
  });
  test("requireProvenance passes verified provenance with identity", () => {
    const p = { ...DEFAULT_POLICY, requireProvenance: ["acme-lib"] };
    assert.equal(score(auditWith("verified", "verified", ID), p).verdict, "allow");
  });
});

describe("provenance identity gate", () => {
  const policyWith = (entry: object) => ({ ...DEFAULT_POLICY, provenanceIdentities: [entry] } as EnterprisePolicy);

  test("verified + matching identity passes", () => {
    const r = score(auditWith("verified", "verified", ID), policyWith({ pattern: "acme-lib", repository: "https://github.com/acme/*" }));
    assert.equal(r.verdict, "allow");
  });
  test("verified + wrong repository blocks with a critical zero-weight finding", () => {
    const r = score(auditWith("verified", "verified", ID), policyWith({ pattern: "acme-lib", repository: "https://github.com/evil/*" }));
    assert.equal(r.verdict, "block");
    const f = r.findings.find((x) => x.ruleId === "provenance-identity");
    assert.ok(f); assert.equal(f!.severity, "critical"); assert.equal(f!.weight, 0);
  });
  test("absent provenance in an identity-constrained namespace blocks", () => {
    assert.equal(score(auditWith("verified", "absent"), policyWith({ pattern: "acme-lib", repository: "https://github.com/acme/*" })).verdict, "block");
  });
  test("unknown provenance does NOT trip the identity gate (outage tolerance)", () => {
    assert.equal(score(auditWith("verified", "unknown"), policyWith({ pattern: "acme-lib", repository: "https://github.com/acme/*" })).verdict, "allow");
  });
  test("non-matching pattern is unaffected", () => {
    assert.equal(score(auditWith("verified", "absent"), policyWith({ pattern: "other-pkg", repository: "x" })).verdict, "allow");
  });
  test("requireProvenance demands verified: unknown trips it", () => {
    const p = { ...DEFAULT_POLICY, requireProvenance: ["acme-lib"] } as EnterprisePolicy;
    assert.equal(score(auditWith("verified", "unknown"), p).verdict, "block");
    assert.equal(score(auditWith("verified", "verified", ID), p).verdict, "allow");
  });
});

function auditNamed(name: string): Audit {
  const meta = { name, version: "1.0.0", author: null, maintainers: [], license: null,
    hasInstallScripts: false, signature: "unsigned", provenance: "absent", integrity: "sha512-x",
    unpackedSize: 10, fileCount: 1 } as unknown as PackageMeta;
  return { schema: 3, meta, findings: [], capabilities: [], capabilityDelta: null,
    engine: { version: "0.1.0", rules: [], mode: "full" }, auditedAt: "t", durationMs: 0 };
}
const withClaim = (ns: string[]): EnterprisePolicy => ({ ...DEFAULT_POLICY, privateNamespaces: ns });

describe("dependency-confusion gate", () => {
  test("a public look-alike of a claimed scope is flagged high", () => {
    const r = score(auditNamed("acme-internal"), withClaim(["@acme/*"]));
    const f = r.findings.find((x) => x.ruleId === "dependency-confusion");
    assert.ok(f, "expected a dependency-confusion finding");
    assert.equal(f!.severity, "high");
    assert.equal(f!.category, "metadata");
    assert.match(f!.message, /@acme/);
  });

  test("the legitimate claimed package itself is NOT flagged", () => {
    const r = score(auditNamed("@acme/utils"), withClaim(["@acme/*"]));
    assert.equal(r.findings.find((x) => x.ruleId === "dependency-confusion"), undefined);
  });

  test("an unrelated public package is NOT flagged", () => {
    const r = score(auditNamed("lodash"), withClaim(["@acme/*"]));
    assert.equal(r.findings.find((x) => x.ruleId === "dependency-confusion"), undefined);
  });

  test("no claimed namespaces (default policy) → gate inert", () => {
    const r = score(auditNamed("acme-internal"), DEFAULT_POLICY);
    assert.equal(r.findings.find((x) => x.ruleId === "dependency-confusion"), undefined);
  });

  test("the finding is weighted (contributes to the score), not a forced block", () => {
    const r = score(auditNamed("acme-internal"), withClaim(["@acme/*"]));
    assert.ok(r.score < 100, "the high finding must lower the score");
    // high (-25) alone → 75 → warn, not block:
    assert.equal(r.verdict, "warn");
  });
});
