import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import {
  generateKeypair, loadRetractionCorpus, parseRetractionCorpus, retractionCorpusHashOfBytes,
  signRetractionCorpus, verifyRetractionCorpusBytes,
} from "../src/index.js";

const document = {
  schema: 1,
  version: "retractions-2026-07-13",
  issuedAt: "2026-07-13T12:00:00.000Z",
  advisories: [{
    kind: "retraction", id: "SENTINEL-RETRACT-abc", name: "@acme/widget", version: "2.0.0",
    integrity: "sha512-YWJj", reason: "security", retractedAt: "2026-07-13T11:00:00.000Z", severity: "high",
  }],
};

describe("signed retraction corpus", () => {
  test("strictly parses reason-coded, integrity-bound advisories", () => {
    const parsed = parseRetractionCorpus(Buffer.from(JSON.stringify(document)));
    assert.equal(parsed.advisories[0]?.reason, "security");
    assert.equal(parsed.advisories[0]?.severity, "high");
    assert.equal(retractionCorpusHashOfBytes(Buffer.from(JSON.stringify(document))), retractionCorpusHashOfBytes(Buffer.from(JSON.stringify(document))));
  });

  test("rejects malformed timestamps, reasons, and reason/severity mismatches", () => {
    for (const advisory of [
      { ...document.advisories[0], reason: "other" },
      { ...document.advisories[0], retractedAt: "yesterday" },
      { ...document.advisories[0], severity: "medium" },
      { ...document.advisories[0], integrity: "not-sri" },
    ]) {
      assert.throws(() => parseRetractionCorpus(Buffer.from(JSON.stringify({ ...document, advisories: [advisory] }))), /retraction corpus/);
    }
  });

  test("verifies signed bytes before loading and rejects tamper", () => {
    const keys = generateKeypair();
    const raw = Buffer.from(JSON.stringify(document));
    const signature = signRetractionCorpus(raw, keys.privateKey);
    assert.equal(verifyRetractionCorpusBytes(raw, signature, keys.publicKey), true);
    assert.equal(verifyRetractionCorpusBytes(Buffer.from(raw.toString().replace("2.0.0", "2.0.1")), signature, keys.publicKey), false);

    const dir = mkdtempSync(join(tmpdir(), "sentinel-retraction-corpus-"));
    const file = join(dir, "advisories.json");
    writeFileSync(file, raw);
    writeFileSync(`${file}.sig`, signature);
    const loaded = loadRetractionCorpus({ file, sig: `${file}.sig`, publicKeyPem: keys.publicKey });
    assert.equal(loaded.corpus.version, document.version);
    assert.equal(loaded.hash, retractionCorpusHashOfBytes(raw));
  });
});
