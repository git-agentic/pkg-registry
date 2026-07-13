import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { auditTarball } from "../src/audit.js";
import { ensureFixtures, tarball } from "./helpers.js";

async function verdict(name: string, version: string): Promise<string> {
  const report = await auditTarball({ meta: { name, version, author: null, maintainers: [], license: null, hasInstallScripts: false, integrity: null }, tarball: tarball(name, version) });
  return report.verdict;
}

// Both-direction VERDICT-LEVEL fixtures for the loader-chain analyzer v2 remediation
// (docs/superpowers/specs/2026-07-13-loader-chain-analyzer-v2-remediation.md,
// "Acceptance — both directions"). These exercise the whole audit pipeline, not just
// analyzeLoaderChain/nativePayloadLoaderRule in isolation.
describe("loader-chain v2 remediation fixtures", () => {
  before(() => ensureFixtures());

  describe("false-positive controls (must allow)", () => {
    test("custom-reader: user object with fs-like method names (S1 binding tracking) → allow", async () =>
      assert.equal(await verdict("custom-reader", "1.0.0"), "allow"));
    test("external-file-tool: absolute/non-package read (Spec1 origin) → allow", async () =>
      assert.equal(await verdict("external-file-tool", "1.0.0"), "allow"));
    test("scoped-names: same-named var in sibling scopes (S2 scope isolation) → allow", async () =>
      assert.equal(await verdict("scoped-names", "1.0.0"), "allow"));
  });

  describe("evasion closures (must block)", () => {
    test("loader-inline-path: inline-repeat write/launch path (S3) → block", async () =>
      assert.equal(await verdict("loader-inline-path", "1.0.0"), "block"));
    test("loader-base64: Buffer.from(read, 'base64') decode (Spec2) → block", async () =>
      assert.equal(await verdict("loader-base64", "1.0.0"), "block"));
    test("loader-native-require: require(writtenPath) native load (Spec2) → block", async () =>
      assert.equal(await verdict("loader-native-require", "1.0.0"), "block"));
  });
});
