import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { generateKeypair, signClaimCorpus, type Audit } from "@git-agentic/sentinel-core";
import { PrivatePackageStore } from "../src/private-store.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const ENTRY = join(ROOT, "packages", "proxy", "src", "index.ts");
const audit = { schema: 3, meta: {}, findings: [], capabilities: [], capabilityDelta: null,
  engine: { version: "x", rules: [], mode: "full" }, auditedAt: "t", durationMs: 0 } as unknown as Audit;

function configured() {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-mode-startup-"));
  const storeDir = join(dir, "store");
  new PrivatePackageStore(storeDir).publish({ name: "leftpad-lite", version: "1.0.1", integrity: "sha512-test",
    manifest: { name: "leftpad-lite", version: "1.0.1", dist: { integrity: "sha512-test" } }, tarball: Buffer.from("bytes"), audit, actor: "test" });
  const { publicKey, privateKey } = generateKeypair();
  const corpus = Buffer.from(JSON.stringify({ schema: 1, version: "claims", issuedAt: "2026-07-13T00:00:00.000Z", claims: [{
    namespace: "leftpad-lite", domain: "example.test", claimantPublicKey: publicKey, status: "active",
    challenge: { method: "dns-txt", id: "c", verifiedAt: "2026-07-12T00:00:00.000Z" }, renewalDueAt: "2027-07-12T00:00:00.000Z",
  }] }));
  const file = join(dir, "claims.json");
  writeFileSync(file, corpus); writeFileSync(`${file}.sig`, signClaimCorpus(corpus, privateKey)); writeFileSync(join(dir, "pub.pem"), publicKey);
  return { dir, env: { SENTINEL_PRIVATE_STORE: storeDir, SENTINEL_CLAIM_CORPUS_FILE: file,
    SENTINEL_CLAIM_CORPUS_PUBKEY: join(dir, "pub.pem"), SENTINEL_REGISTRY_MODE: "off" } };
}

function boot(env: Record<string, string>) {
  try {
    const output = execFileSync("node", ["--import", "tsx", ENTRY], { cwd: ROOT, env: { ...process.env, ...env,
      SENTINEL_UPSTREAM: "fixtures", SENTINEL_PORT: "0", SENTINEL_BOOT_EXIT: "1" }, encoding: "utf8" });
    return { ok: true, output };
  } catch (error) {
    const value = error as { stdout?: string; stderr?: string };
    return { ok: false, output: `${value.stdout ?? ""}${value.stderr ?? ""}` };
  }
}

describe("registry-mode startup", () => {
  test("unacknowledged off switch is FATAL; acknowledged switch emits its manifest", () => {
    const config = configured();
    const rejected = boot(config.env);
    assert.equal(rejected.ok, false);
    assert.match(rejected.output, /FATAL.*REGISTRY_MODE_OFF_ACK=1/is);
    const accepted = boot({ ...config.env, SENTINEL_REGISTRY_MODE_OFF_ACK: "1" });
    assert.equal(accepted.ok, true, accepted.output);
    const manifest = JSON.parse(readFileSync(join(config.env.SENTINEL_PRIVATE_STORE, "revert-manifest.json"), "utf8"));
    assert.deepEqual(manifest.resolutionFlips.map((row: { name: string }) => row.name), ["leftpad-lite"]);
  });
});
