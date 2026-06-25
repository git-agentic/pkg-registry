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
});
