import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { DEFAULT_POLICY, generateKeypair, type Audit, type ClaimCorpus } from "@sentinel/core";
import { PrivatePackageStore } from "../src/private-store.js";
import { configureRegistryMode } from "../src/registry-mode.js";
import { exportNativeStore } from "../src/registry-export.js";

const audit = { schema: 3, meta: {}, findings: [], capabilities: [], capabilityDelta: null,
  engine: { version: "x", rules: [], mode: "full" }, auditedAt: "t", durationMs: 0 } as unknown as Audit;
const claimantPublicKey = generateKeypair().publicKey;
const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "fixtures");
const corpus: ClaimCorpus = { schema: 1, version: "claims-1", issuedAt: "2026-07-13T00:00:00.000Z", claims: [{
  namespace: "claimed-name", domain: "example.test", claimantPublicKey, status: "active",
  challenge: { method: "dns-txt", id: "c", verifiedAt: "2026-07-12T00:00:00.000Z" }, renewalDueAt: "2027-07-12T00:00:00.000Z",
}] };

describe("Phase 33 registry migration", () => {
  test("mode-off is fail-closed with retained content and manifests only source flips", () => {
    const store = new PrivatePackageStore();
    for (const name of ["claimed-name", "@private/x"]) store.publish({ name, version: "1.0.0", integrity: `sha512-${name}`,
      manifest: { name, version: "1.0.0", dist: { integrity: `sha512-${name}` } }, tarball: Buffer.from(name), audit, actor: "test" });
    const policy = { ...DEFAULT_POLICY, privateNamespaces: ["@private/*"] };
    const before = JSON.stringify(store.packument("claimed-name"));
    assert.throws(() => configureRegistryMode({ rawMode: "off", privateStore: store, policy, claimCorpus: corpus }), /ACK=1/);
    const file = join(mkdtempSync(join(tmpdir(), "sentinel-revert-")), "manifest.json");
    const configured = configureRegistryMode({ rawMode: "off", acknowledged: "1", manifestPath: file, privateStore: store, policy, claimCorpus: corpus,
      now: () => Date.parse("2026-07-13T12:00:00.000Z") });
    assert.deepEqual(configured.manifest?.resolutionFlips.map((row) => row.name), ["claimed-name"]);
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), configured.manifest);
    assert.deepEqual(store.names().sort(), ["@private/x", "claimed-name"], "revert retains all native data");
    assert.equal(JSON.stringify(store.packument("claimed-name")), before, "off/on round-trip leaves native resolution bytes unchanged");
  });

  test("export preserves tarball bytes and emits full stock-registry inputs", () => {
    const source = mkdtempSync(join(tmpdir(), "sentinel-export-source-"));
    const output = mkdtempSync(join(tmpdir(), "sentinel-export-output-"));
    const store = new PrivatePackageStore(source, () => Date.parse("2026-07-13T12:00:00.000Z"));
    const bytes = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
    store.publish({ name: "leftpad-lite", version: "1.0.1", integrity: "sha512-test", manifest: {
      name: "leftpad-lite", version: "1.0.1", dist: { integrity: "sha512-test" },
    }, tarball: bytes, audit, actor: "test" });
    assert.deepEqual(exportNativeStore(source, output), { packages: 1, versions: 1 });
    const storedMeta = JSON.parse(readFileSync(join(source, encodeURIComponent("leftpad-lite"), "1.0.1", "meta.json"), "utf8"));
    assert.equal(storedMeta.sourceClass, undefined, "source class remains derived and is never stored");
    const dir = join(output, encodeURIComponent("leftpad-lite"));
    assert.deepEqual(readFileSync(join(dir, "1.0.1.tgz")), bytes);
    assert.doesNotThrow(() => execFileSync("npm", ["publish", join(dir, "1.0.1.tgz"), "--dry-run", "--json"], { stdio: "pipe" }),
      "exported tarball is accepted by the stock npm publish client");
    const packument = JSON.parse(readFileSync(join(dir, "packument.json"), "utf8"));
    assert.equal(packument.time["1.0.1"], "2026-07-13T12:00:00.000Z");
    assert.equal(packument.versions["1.0.1"].dist.integrity, "sha512-test");
  });
});
