import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import {
  claimCorpusHashOfBytes,
  generateKeypair,
  loadClaimCorpus,
  parseClaimCorpus,
  signClaimCorpus,
  type ClaimCorpus,
} from "../src/index.js";

const claim = (over: Record<string, unknown> = {}) => ({
  namespace: "@acme/*",
  domain: "acme.example",
  status: "active",
  challenge: { method: "dns-txt", id: "challenge-1", verifiedAt: "2026-07-01T00:00:00.000Z" },
  renewalDueAt: "2027-07-01T00:00:00.000Z",
  ...over,
});

const corpus = (claims: unknown[] = [claim()]): ClaimCorpus => ({
  schema: 1,
  version: "2026.07.1",
  issuedAt: "2026-07-02T00:00:00.000Z",
  claims: claims as ClaimCorpus["claims"],
});

describe("signed claim corpus", () => {
  test("loads a valid corpus only when the raw bytes match its Ed25519 signature", () => {
    const { publicKey, privateKey } = generateKeypair();
    const raw = Buffer.from(JSON.stringify(corpus()));
    const dir = mkdtempSync(join(tmpdir(), "sentinel-claims-"));
    const file = join(dir, "claims.json");
    const sig = `${file}.sig`;
    writeFileSync(file, raw);
    writeFileSync(sig, signClaimCorpus(raw, privateKey));

    const loaded = loadClaimCorpus({ file, sig, publicKeyPem: publicKey });
    assert.equal(loaded.corpus.version, "2026.07.1");
    assert.equal(loaded.hash, claimCorpusHashOfBytes(raw));

    writeFileSync(file, Buffer.from(JSON.stringify({ ...corpus(), version: "tampered" })));
    assert.throws(() => loadClaimCorpus({ file, sig, publicKeyPem: publicKey }), /signature/i);
  });

  test("rejects malformed entries, missing passed challenges, overlap, and short timelocks", () => {
    assert.throws(() => parseClaimCorpus(Buffer.from(JSON.stringify(corpus([
      claim({ challenge: undefined }),
    ])))), /challenge/i);
    assert.throws(() => parseClaimCorpus(Buffer.from(JSON.stringify(corpus([
      claim(), claim({ namespace: "@acme/*", domain: "other.example" }),
    ])))), /overlap/i);
    assert.throws(() => parseClaimCorpus(Buffer.from(JSON.stringify(corpus([
      claim({ pending: {
        kind: "transfer", announcedAt: "2026-07-01T00:00:00.000Z",
        effectiveAt: "2026-07-30T23:59:59.999Z", targetDomain: "new.example",
        challenge: { method: "dns-txt", id: "new-1", verifiedAt: "2026-07-01T00:00:00.000Z" },
        authorizedBy: "old-claimant-signature",
      } }),
    ])))), /30 days/i);
  });

  test("accepts frozen/disputed claims and a fully timelocked pending transfer without changing the current owner", () => {
    const parsed = parseClaimCorpus(Buffer.from(JSON.stringify(corpus([
      claim({ status: "frozen" }),
      claim({
        namespace: "contested-name", status: "disputed",
        pending: {
          kind: "transfer", announcedAt: "2026-07-01T00:00:00.000Z",
          effectiveAt: "2026-07-31T00:00:00.000Z", targetDomain: "new.example",
          challenge: { method: "dns-txt", id: "new-1", verifiedAt: "2026-07-01T00:00:00.000Z" },
          authorizedBy: "old-claimant-signature",
        },
      }),
    ]))));
    assert.equal(parsed.claims[1]?.domain, "acme.example");
    assert.equal(parsed.claims[1]?.pending?.targetDomain, "new.example");
  });
});
