import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { describe, test } from "node:test";
import { isClaimed, parsePublishBody, publishTokenValid } from "../src/private.js";
import { DEFAULT_POLICY, type EnterprisePolicy } from "@sentinel/core";

const policy = (ns: string[]): EnterprisePolicy => ({ ...DEFAULT_POLICY, privateNamespaces: ns });

// Build a publish payload matching the captured npm shape.
function publishBody(name: string, version: string, bytes = "tarball-bytes", integrity?: string) {
  const data = Buffer.from(bytes).toString("base64");
  return {
    _id: name, name, "dist-tags": { latest: version },
    versions: { [version]: { name, version, dist: { integrity, shasum: "x", tarball: "http://x" } } },
    _attachments: { [`${name}-${version}.tgz`]: { content_type: "application/octet-stream", data, length: bytes.length } },
  };
}

describe("isClaimed", () => {
  test("matches exact + scope glob, anchored", () => {
    assert.equal(isClaimed("@acme/payments", policy(["@acme/*"])), true);
    assert.equal(isClaimed("acme-config", policy(["acme-config"])), true);
    assert.equal(isClaimed("@other/x", policy(["@acme/*"])), false);
    assert.equal(isClaimed("anything", policy([])), false);
  });
});

describe("parsePublishBody", () => {
  test("extracts the single new version, manifest, and base64 tarball", () => {
    const p = parsePublishBody("@acme/x", publishBody("@acme/x", "1.2.3", "hello", "sha512-zzz"));
    assert.equal(p.version, "1.2.3");
    assert.equal(p.tarball.toString(), "hello");
    assert.equal(p.declaredIntegrity, "sha512-zzz");
    assert.equal((p.manifest as { version: string }).version, "1.2.3");
  });
  test("throws on a body with no _attachments", () => {
    assert.throws(() => parsePublishBody("@acme/x", { versions: {} }));
  });
});

describe("publishTokenValid", () => {
  test("accepts a configured bearer token, rejects others/absent/none", () => {
    assert.equal(publishTokenValid("Bearer tok-1", ["tok-1", "tok-2"]), true);
    assert.equal(publishTokenValid("Bearer nope", ["tok-1"]), false);
    assert.equal(publishTokenValid(undefined, ["tok-1"]), false);
    assert.equal(publishTokenValid("Bearer tok-1", []), false); // no tokens configured ⇒ publishing disabled
  });
});
