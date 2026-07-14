import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { generateKeypair, signClaimCorpus, signRetractionCorpus } from "@agentic-sentinel/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");
const ENTRY = join(ROOT, "packages", "proxy", "src", "index.ts");

function boot(env: Record<string, string>): { ok: boolean; output: string } {
  try {
    return { ok: true, output: execFileSync("node", ["--import", "tsx", ENTRY], {
      cwd: ROOT, env: { ...process.env, ...env, SENTINEL_UPSTREAM: "fixtures", SENTINEL_PORT: "0", SENTINEL_BOOT_EXIT: "1" },
      timeout: 15_000, encoding: "utf8",
    }) };
  } catch (error) {
    const e = error as { stdout?: string; stderr?: string };
    return { ok: false, output: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}

function configured(mode: "valid" | "tampered" | "malformed" = "valid"): Record<string, string> {
  const { publicKey, privateKey } = generateKeypair();
  const dir = mkdtempSync(join(tmpdir(), "sentinel-claim-boot-"));
  const file = join(dir, "claims.json");
  const raw = Buffer.from(JSON.stringify({
    schema: 1, version: "2026.07.1", issuedAt: "2026-07-02T00:00:00.000Z",
    claims: [{ namespace: "@acme/*", domain: "acme.example", claimantPublicKey: publicKey, status: "active",
      challenge: { method: "dns-txt", id: "c-1", verifiedAt: "2026-07-01T00:00:00.000Z" },
      renewalDueAt: "2027-07-01T00:00:00.000Z" }],
  }));
  const written = mode === "tampered" ? Buffer.from(raw.toString().replace("2026.07.1", "tampered"))
    : mode === "malformed" ? Buffer.from(JSON.stringify({ schema: 1, version: "bad", issuedAt: "not-a-date", claims: [] }))
    : raw;
  writeFileSync(file, written);
  writeFileSync(`${file}.sig`, signClaimCorpus(mode === "tampered" ? raw : written, privateKey));
  writeFileSync(join(dir, "pub.pem"), publicKey);
  return { SENTINEL_CLAIM_CORPUS_FILE: file, SENTINEL_CLAIM_CORPUS_PUBKEY: join(dir, "pub.pem") };
}

describe("claim corpus startup", () => {
  test("a valid signed corpus boots and reports its version", () => {
    const result = boot(configured());
    assert.equal(result.ok, true);
    assert.match(result.output, /claim corpus.*2026\.07\.1/i);
  });

  test("tamper is a boot-time FATAL", () => {
    const result = boot(configured("tampered"));
    assert.equal(result.ok, false);
    assert.match(result.output, /FATAL.*claim corpus.*signature/is);
  });

  test("a correctly signed but malformed corpus is also a boot-time FATAL", () => {
    const result = boot(configured("malformed"));
    assert.equal(result.ok, false);
    assert.match(result.output, /FATAL.*claim corpus.*invalid claim corpus/is);
  });

  test("configuring a corpus without its pinned public key is a boot-time FATAL", () => {
    const env = configured();
    delete env.SENTINEL_CLAIM_CORPUS_PUBKEY;
    const result = boot(env);
    assert.equal(result.ok, false);
    assert.match(result.output, /FATAL.*SENTINEL_CLAIM_CORPUS_PUBKEY/is);
  });
});

function configuredRetractions(mode: "valid" | "tampered" | "malformed" = "valid"): Record<string, string> {
  const { publicKey, privateKey } = generateKeypair();
  const dir = mkdtempSync(join(tmpdir(), "sentinel-retraction-boot-"));
  const file = join(dir, "advisories.json");
  const raw = Buffer.from(JSON.stringify({
    schema: 1, version: "retractions-1", issuedAt: "2026-07-13T12:00:00.000Z",
    advisories: [{ kind: "retraction", id: "SENTINEL-RETRACT-boot", name: "@acme/x", version: "1.0.0",
      integrity: "sha512-YWJj", reason: "security", retractedAt: "2026-07-13T11:00:00.000Z", severity: "high" }],
  }));
  const written = mode === "tampered" ? Buffer.from(raw.toString().replace("retractions-1", "tampered"))
    : mode === "malformed" ? Buffer.from(JSON.stringify({ schema: 1, version: "bad", issuedAt: "not-a-date", advisories: [] }))
    : raw;
  writeFileSync(file, written);
  writeFileSync(`${file}.sig`, signRetractionCorpus(mode === "tampered" ? raw : written, privateKey));
  writeFileSync(join(dir, "pub.pem"), publicKey);
  return { SENTINEL_RETRACTION_CORPUS_FILE: file, SENTINEL_RETRACTION_CORPUS_PUBKEY: join(dir, "pub.pem") };
}

describe("retraction corpus startup", () => {
  test("a valid signed corpus boots and reports its version", () => {
    const result = boot(configuredRetractions());
    assert.equal(result.ok, true);
    assert.match(result.output, /retraction corpus.*retractions-1/i);
  });

  test("tamper and correctly-signed malformed data are boot-time FATAL", () => {
    for (const mode of ["tampered", "malformed"] as const) {
      const result = boot(configuredRetractions(mode));
      assert.equal(result.ok, false);
      assert.match(result.output, /FATAL.*retraction corpus/is);
    }
  });

  test("a configured corpus requires a pinned public key", () => {
    const env = configuredRetractions();
    delete env.SENTINEL_RETRACTION_CORPUS_PUBKEY;
    const result = boot(env);
    assert.equal(result.ok, false);
    assert.match(result.output, /FATAL.*RETRACTION_CORPUS_PUBKEY/is);
  });
});
