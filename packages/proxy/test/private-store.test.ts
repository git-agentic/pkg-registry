import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtempSync } from "node:fs";
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
});
