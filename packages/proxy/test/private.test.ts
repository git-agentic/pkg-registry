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
  test("throws on path-traversal version", () => {
    const body = {
      versions: {},
      _attachments: { "@acme/x-../evil.tgz": { data: Buffer.from("x").toString("base64") } },
    };
    assert.throws(() => parsePublishBody("@acme/x", body));
  });
  test("throws on bad attachment key (wrong prefix)", () => {
    const body = {
      versions: { "1.0.0": { name: "other", version: "1.0.0" } },
      _attachments: { "other.tgz": { data: Buffer.from("x").toString("base64") } },
    };
    assert.throws(() => parsePublishBody("@acme/x", body));
  });
  test("throws on missing data in attachment", () => {
    const body = {
      versions: { "1.0.0": {} },
      _attachments: { "@acme/x-1.0.0.tgz": { content_type: "x" } },
    };
    assert.throws(() => parsePublishBody("@acme/x", body));
  });
  test("throws on missing manifest for the version", () => {
    const body = {
      versions: {},
      _attachments: { "@acme/x-1.0.0.tgz": { data: Buffer.from("x").toString("base64") } },
    };
    assert.throws(() => parsePublishBody("@acme/x", body));
  });
  test("throws when manifest name mismatches package name", () => {
    const body = publishBody("@acme/x", "1.2.3");
    body.versions["1.2.3"].name = "@evil/x";
    assert.throws(() => parsePublishBody("@acme/x", body), /does not match/);
  });
  test("throws when manifest version mismatches attachment version", () => {
    const body = publishBody("@acme/x", "1.2.3");
    body.versions["1.2.3"].version = "9.9.9";
    assert.throws(() => parsePublishBody("@acme/x", body), /does not match/);
  });
});

describe("publishTokenValid", () => {
  test("accepts a configured bearer token, rejects others/absent/none", () => {
    assert.equal(publishTokenValid("Bearer tok-1", ["tok-1", "tok-2"]), true);
    assert.equal(publishTokenValid("Bearer nope", ["tok-1"]), false);
    assert.equal(publishTokenValid(undefined, ["tok-1"]), false);
    assert.equal(publishTokenValid("Bearer tok-1", []), false); // no tokens configured ⇒ publishing disabled
  });
  test("valid token returns true, wrong token returns false", () => {
    assert.equal(publishTokenValid("Bearer correct-token", ["correct-token"]), true);
    assert.equal(publishTokenValid("Bearer wrong-token", ["correct-token"]), false);
  });
});
