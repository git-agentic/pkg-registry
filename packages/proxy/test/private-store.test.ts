import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { PrivatePackageStore } from "../src/private-store.js";
import type { Audit } from "@sentinel/core";

const audit = { schema: 3, meta: {}, findings: [], capabilities: [], capabilityDelta: null,
  engine: { version: "x", rules: [], mode: "full" }, auditedAt: "t", durationMs: 0 } as unknown as Audit;
const put = (s: PrivatePackageStore, name: string, version: string, body = "x") =>
  s.put({ name, version, integrity: `sha512-${version}`, manifest: { name, version, dist: {} }, tarball: Buffer.from(body), audit, actor: "ci" });

describe("PrivatePackageStore", () => {
  test("put/get/has + versions + packument synthesis", () => {
    const s = new PrivatePackageStore();
    assert.equal(s.has("@acme/x"), false);
    put(s, "@acme/x", "1.0.0", "v1");
    put(s, "@acme/x", "1.1.0", "v2");
    assert.equal(s.has("@acme/x"), true);
    assert.deepEqual(s.versions("@acme/x").sort(), ["1.0.0", "1.1.0"]);
    assert.equal(s.getTarball("@acme/x", "1.1.0")?.toString(), "v2");
    assert.ok(s.getAudit("@acme/x", "1.0.0"));
    const pm = s.packument("@acme/x")!;
    assert.equal(pm.name, "@acme/x");
    assert.equal(pm["dist-tags"].latest, "1.1.0");           // highest semver
    assert.deepEqual(Object.keys(pm.versions).sort(), ["1.0.0", "1.1.0"]);
    assert.equal(s.packument("@acme/missing"), undefined);
  });

  test("persists to disk and reloads", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-priv-"));
    const a = new PrivatePackageStore(dir);
    put(a, "@acme/y", "2.0.0", "bytes-y");
    const b = new PrivatePackageStore(dir);  // fresh instance, same dir
    assert.equal(b.has("@acme/y"), true);
    assert.equal(b.getTarball("@acme/y", "2.0.0")?.toString(), "bytes-y");
    assert.equal(b.getVersion("@acme/y", "2.0.0")?.integrity, "sha512-2.0.0");
  });

  test("preserves claim attribution as an immutable publication-time snapshot", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-priv-attribution-"));
    const s = new PrivatePackageStore(dir);
    const attribution = { namespace: "@acme/*", domain: "old.example", claimantPublicKey: "old-key" };
    s.publish({ name: "@acme/x", version: "1.0.0", integrity: "sha512-1", manifest: {},
      tarball: Buffer.from("v1"), audit, actor: "ci", claimAtPublication: attribution });
    attribution.domain = "new.example";
    attribution.claimantPublicKey = "new-key";
    assert.deepEqual(s.getVersion("@acme/x", "1.0.0")?.claimAtPublication,
      { namespace: "@acme/*", domain: "old.example", claimantPublicKey: "old-key" });
    assert.deepEqual(new PrivatePackageStore(dir).getVersion("@acme/x", "1.0.0")?.claimAtPublication,
      { namespace: "@acme/*", domain: "old.example", claimantPublicKey: "old-key" });
  });

  test("atomic publish-if-absent rejects a duplicate without replacing bytes", () => {
    const s = new PrivatePackageStore();
    const first = { name: "@acme/x", version: "1.0.0", integrity: "sha512-first",
      manifest: { name: "@acme/x", version: "1.0.0", dist: {} }, tarball: Buffer.from("first"), audit, actor: "ci" };
    s.publish(first);
    assert.throws(() => s.publish({ ...first, integrity: "sha512-second", tarball: Buffer.from("second") }), /already published/);
    assert.equal(s.getTarball("@acme/x", "1.0.0")?.toString(), "first");
  });

  test("persistence failure leaves no visible in-memory or on-disk publication", () => {
    const s = new PrivatePackageStore("/dev/null/sentinel-registry-store");
    assert.throws(() => s.publish({
      name: "@acme/fail", version: "1.0.0", integrity: "sha512-fail",
      manifest: { name: "@acme/fail", version: "1.0.0", dist: {} },
      tarball: Buffer.from("bytes"), audit, actor: "ci",
    }));
    assert.equal(s.has("@acme/fail"), false);
    assert.equal(s.packument("@acme/fail"), undefined);
  });

  test("retraction removes availability, retargets latest, and permanently spends the identifier", () => {
    const s = new PrivatePackageStore();
    put(s, "@acme/x", "1.0.0", "v1");
    put(s, "@acme/x", "2.0.0", "v2");
    const beforeAudit = structuredClone(s.getAudit("@acme/x", "2.0.0"));
    const tombstone = s.retract({
      name: "@acme/x", version: "2.0.0", reason: "broken",
      retractedAt: "2026-07-13T12:00:00.000Z", advisoryId: "SENTINEL-RETRACT-test",
    });

    assert.equal(tombstone.reason, "broken");
    assert.equal(s.getRetraction("@acme/x", "2.0.0")?.advisoryId, "SENTINEL-RETRACT-test");
    assert.deepEqual(s.getAudit("@acme/x", "2.0.0"), beforeAudit, "stored audit history is unchanged");
    assert.equal(s.getTarball("@acme/x", "2.0.0")?.toString(), "v2", "historical bytes remain retained internally");

    const pm = s.packument("@acme/x")!;
    assert.deepEqual(Object.keys(pm.versions), ["1.0.0"]);
    assert.equal(pm["dist-tags"].latest, "1.0.0");
    assert.deepEqual(pm._sentinel?.retractions["2.0.0"], {
      retractedAt: "2026-07-13T12:00:00.000Z", reason: "broken", advisoryId: "SENTINEL-RETRACT-test",
    });
    assert.throws(() => put(s, "@acme/x", "2.0.0", "replacement"), /spent|retracted/i);
  });

  test("all-retracted packages retain an empty packument plus durable tombstones", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-priv-retraction-"));
    const a = new PrivatePackageStore(dir);
    put(a, "@acme/y", "1.0.0", "bytes");
    a.retract({ name: "@acme/y", version: "1.0.0", reason: "security",
      retractedAt: "2026-07-13T12:00:00.000Z", advisoryId: "SENTINEL-RETRACT-durable" });

    const b = new PrivatePackageStore(dir);
    assert.deepEqual(b.packument("@acme/y"), {
      name: "@acme/y", "dist-tags": {}, versions: {},
      _sentinel: { retractions: { "1.0.0": {
        retractedAt: "2026-07-13T12:00:00.000Z", reason: "security", advisoryId: "SENTINEL-RETRACT-durable",
      } } },
    });
    assert.throws(() => put(b, "@acme/y", "1.0.0", "replacement"), /spent|retracted/i);
  });

  test("fallback download counts and window-hit telemetry persist without SQLite", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-priv-telemetry-"));
    const a = new PrivatePackageStore(dir);
    put(a, "@acme/z", "1.0.0");
    a.recordDownload("@acme/z", "1.0.0");
    a.recordDownload("@acme/z", "1.0.0");
    a.recordRetractionWindowHit({ ageExceeded: true, downloadsExceeded: false });

    const b = new PrivatePackageStore(dir);
    assert.equal(b.downloadCount("@acme/z", "1.0.0"), 2);
    assert.deepEqual(b.retractionWindowHits(), { age: 1, downloads: 0, both: 0 });
  });

  test("corrupt operational security state fails closed", () => {
    const invalidStates = [
      { schema: 1, retractions: [{ name: "@acme/x", version: "1.0.0" }], downloads: [], windowHits: { age: 0, downloads: 0, both: 0 } },
      { schema: 1, retractions: [], downloads: [{ name: "@acme/x", version: "1.0.0", count: -1 }], windowHits: { age: 0, downloads: 0, both: 0 } },
      { schema: 1, retractions: [], downloads: [], windowHits: { age: 0.5, downloads: 0, both: 0 } },
    ];
    for (const state of invalidStates) {
      const dir = mkdtempSync(join(tmpdir(), "sentinel-priv-corrupt-state-"));
      writeFileSync(join(dir, ".registry-state.json"), JSON.stringify(state));
      assert.throws(() => new PrivatePackageStore(dir), /invalid private registry operational state/);
    }
  });

  test("retraction leaves stored audit and attestation bytes unchanged", () => {
    const s = new PrivatePackageStore();
    const attestations = { attestations: [{ bundle: { dsseEnvelope: { payload: "immutable" } } }] };
    s.publish({ name: "@acme/attested", version: "1.0.0", integrity: "sha512-attested", manifest: {},
      tarball: Buffer.from("bytes"), audit, attestations, actor: "ci" });
    const before = JSON.stringify(s.getVersion("@acme/attested", "1.0.0"));
    s.retract({ name: "@acme/attested", version: "1.0.0", reason: "security",
      retractedAt: "2026-07-13T12:00:00.000Z", advisoryId: "SENTINEL-RETRACT-attested" });
    assert.equal(JSON.stringify(s.getVersion("@acme/attested", "1.0.0")), before);
    assert.deepEqual(s.getAttestations("@acme/attested", "1.0.0"), attestations);
  });
});
