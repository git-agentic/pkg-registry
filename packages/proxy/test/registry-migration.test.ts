import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { DEFAULT_POLICY, generateKeypair, type Audit, type ClaimCorpus } from "@git-agentic/sentinel-core";
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

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

describe("Phase 33 registry migration", () => {
  test("mode-off is fail-closed with retained content and manifests only source flips", () => {
    const store = new PrivatePackageStore();
    for (const name of ["claimed-name", "@private/x"]) store.publish({ name, version: "1.0.0", integrity: `sha512-${name}`,
      manifest: { name, version: "1.0.0", dist: { integrity: `sha512-${name}` } }, tarball: Buffer.from(name), audit, actor: "test" });
    const policy = { ...DEFAULT_POLICY, privateNamespaces: [
      "@private/*", "@covered*", "@claimed/__sentinel_revert_probe__", "@claimed/private-*",
    ] };
    const claims: ClaimCorpus = { ...corpus, claims: [
      ...corpus.claims,
      { ...corpus.claims[0]!, namespace: "never-published" },
      { ...corpus.claims[0]!, namespace: "@claimed/*" },
      { ...corpus.claims[0]!, namespace: "@private/*" },
      { ...corpus.claims[0]!, namespace: "@covered/*" },
    ] };
    const before = JSON.stringify(store.packument("claimed-name"));
    assert.throws(() => configureRegistryMode({ rawMode: "off", privateStore: store, policy, claimCorpus: claims }), /ACK=1/);
    const file = join(mkdtempSync(join(tmpdir(), "sentinel-revert-")), "manifest.json");
    const configured = configureRegistryMode({ rawMode: "off", acknowledged: "1", manifestPath: file, privateStore: store, policy, claimCorpus: claims,
      now: () => Date.parse("2026-07-13T12:00:00.000Z") });
    assert.deepEqual(configured.manifest?.resolutionFlips.map((row) => [row.name, row.selector]), [
      ["claimed-name", "package"], ["never-published", "package"], ["@claimed/*", "namespace"],
    ]);
    assert.deepEqual(configured.manifest?.resolutionFlips.at(-1)?.exceptPolicyPatterns, policy.privateNamespaces,
      "namespace flip is represented exactly as claim selector minus policy-private exceptions");
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), configured.manifest);
    assert.deepEqual(store.names().sort(), ["@private/x", "claimed-name"], "revert retains all native data");
    assert.equal(JSON.stringify(store.packument("claimed-name")), before, "off/on round-trip leaves native resolution bytes unchanged");
  });

  test("export preserves tarball bytes and full stock-registry inputs", () => {
    const source = mkdtempSync(join(tmpdir(), "sentinel-export-source-"));
    const output = mkdtempSync(join(tmpdir(), "sentinel-export-output-"));
    const store = new PrivatePackageStore(source, () => Date.parse("2026-07-13T12:00:00.000Z"));
    const bytes = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
    store.publish({ name: "leftpad-lite", version: "1.0.1", integrity: "sha512-test", manifest: {
      name: "leftpad-lite", version: "1.0.1", dist: { integrity: "sha512-test" },
    }, tarball: bytes, audit, actor: "test" });
    store.setDistTag("leftpad-lite", "stable", "1.0.1");
    assert.deepEqual(exportNativeStore(source, output), { packages: 1, versions: 1 });
    for (const relative of readdirSync(source, { recursive: true }).filter((entry) => String(entry).endsWith(".json"))) {
      const json = readFileSync(join(source, String(relative)), "utf8");
      assert.doesNotMatch(json, /"(?:sourceClass|source_class|registrySource)"\s*:/,
        `source class remains derived and is absent from ${String(relative)}`);
    }
    const dir = join(output, encodeURIComponent("leftpad-lite"));
    assert.deepEqual(readFileSync(join(dir, "1.0.1.tgz")), bytes);
    const packument = JSON.parse(readFileSync(join(dir, "packument.json"), "utf8"));
    assert.equal(packument.time["1.0.1"], "2026-07-13T12:00:00.000Z");
    assert.equal(packument.versions["1.0.1"].dist.integrity, "sha512-test");
  });

  test("export republishes to a stock-compatible Verdaccio registry",
    { skip: !process.env.SENTINEL_VERDACCIO_BIN }, async () => {
    const source = mkdtempSync(join(tmpdir(), "sentinel-export-source-"));
    const output = mkdtempSync(join(tmpdir(), "sentinel-export-output-"));
    const store = new PrivatePackageStore(source);
    const bytes = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
    store.publish({ name: "leftpad-lite", version: "1.0.1", integrity: "sha512-test", manifest: {
      name: "leftpad-lite", version: "1.0.1", dist: { integrity: "sha512-test" },
    }, tarball: bytes, audit, actor: "test" });
    exportNativeStore(source, output);
    const dir = join(output, encodeURIComponent("leftpad-lite"));
    const verdaccio = mkdtempSync(join(tmpdir(), "sentinel-verdaccio-"));
    const port = await freePort();
    const registry = `http://127.0.0.1:${port}`;
    const config = join(verdaccio, "config.yaml");
    writeFileSync(config, `storage: ${join(verdaccio, "storage")}\nauth:\n  htpasswd:\n    file: ${join(verdaccio, "htpasswd")}\n    max_users: 1000\nuplinks: {}\npackages:\n  '@*/*':\n    access: $all\n    publish: $authenticated\n  '**':\n    access: $all\n    publish: $authenticated\nlog:\n  type: stdout\n  format: pretty\n  level: error\n`);
    const child = spawn(process.env.SENTINEL_VERDACCIO_BIN!, ["--config", config, "--listen", `127.0.0.1:${port}`], { stdio: "ignore" });
    try {
      let ready = false;
      for (let attempt = 0; attempt < 100 && !ready; attempt++) {
        try { ready = (await fetch(`${registry}/-/ping`)).ok; } catch { /* starting */ }
        if (!ready) await new Promise((resolve) => setTimeout(resolve, 50));
      }
      assert.equal(ready, true, "Verdaccio did not start");
      const login = await fetch(`${registry}/-/user/org.couchdb.user:export-test`, { method: "PUT", headers: { "content-type": "application/json" },
        body: JSON.stringify({ _id: "org.couchdb.user:export-test", name: "export-test", password: "export-test-password", type: "user", roles: [] }) });
      assert.equal(login.status, 201, await login.clone().text());
      const token = (await login.json()).token as string;
      const npmrc = join(verdaccio, ".npmrc");
      writeFileSync(npmrc, `registry=${registry}/\n//127.0.0.1:${port}/:_authToken=${token}\n`);
      execFileSync("npm", ["publish", join(dir, "1.0.1.tgz"), "--registry", registry, "--access", "public"], {
        stdio: "pipe", env: { ...process.env, npm_config_userconfig: npmrc },
      });
      const republished = await (await fetch(`${registry}/leftpad-lite`)).json();
      assert.ok(republished.versions["1.0.1"], "stock-compatible registry serves the republished export");
    } finally { child.kill("SIGTERM"); }
  });
});
