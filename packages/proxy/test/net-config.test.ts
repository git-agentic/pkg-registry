import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  parseTarballOrigins,
  parsePublicBaseUrl,
  isLoopbackHost,
  assertAllowedTarballUrl,
} from "../src/net-config.js";

describe("parseTarballOrigins", () => {
  test("parses a comma-separated list into origins", () => {
    assert.deepEqual(
      parseTarballOrigins("https://cdn.example.com, http://mirror.corp:8080"),
      ["https://cdn.example.com", "http://mirror.corp:8080"],
    );
  });

  test("normalizes case and default ports via URL.origin", () => {
    assert.deepEqual(parseTarballOrigins("HTTPS://CDN.Example.com:443"), ["https://cdn.example.com"]);
  });

  test("rejects an entry with a path", () => {
    assert.throws(() => parseTarballOrigins("https://cdn.example.com/tarballs"), /bare origin/);
  });

  test("rejects an entry with a query", () => {
    assert.throws(() => parseTarballOrigins("https://cdn.example.com/?x=1"), /bare origin/);
  });

  test("rejects a non-http(s) protocol", () => {
    assert.throws(() => parseTarballOrigins("ftp://cdn.example.com"), /http/);
  });

  test("rejects garbage", () => {
    assert.throws(() => parseTarballOrigins("not a url"));
  });

  test("empty string yields an empty list", () => {
    assert.deepEqual(parseTarballOrigins(""), []);
  });
});

describe("parsePublicBaseUrl", () => {
  test("accepts an https URL and strips the trailing slash", () => {
    assert.equal(parsePublicBaseUrl("https://sentinel.corp.example/"), "https://sentinel.corp.example");
  });

  test("accepts a path prefix (proxy mounted behind an LB route)", () => {
    assert.equal(parsePublicBaseUrl("https://lb.corp.example/sentinel/"), "https://lb.corp.example/sentinel");
  });

  test("rejects a query string", () => {
    assert.throws(() => parsePublicBaseUrl("https://x.example/?a=1"), /query or fragment/);
  });

  test("rejects a non-http(s) protocol", () => {
    assert.throws(() => parsePublicBaseUrl("ftp://x.example"), /http/);
  });

  test("rejects garbage", () => {
    assert.throws(() => parsePublicBaseUrl("not a url"));
  });
});

describe("isLoopbackHost", () => {
  test("localhost with and without port", () => {
    assert.equal(isLoopbackHost("localhost"), true);
    assert.equal(isLoopbackHost("localhost:4873"), true);
  });

  test("127.0.0.0/8 with port", () => {
    assert.equal(isLoopbackHost("127.0.0.1:4873"), true);
    assert.equal(isLoopbackHost("127.1.2.3:80"), true);
  });

  test("IPv6 loopback", () => {
    assert.equal(isLoopbackHost("[::1]:4873"), true);
  });

  test("non-loopback hosts are false", () => {
    assert.equal(isLoopbackHost("registry.evil.example"), false);
    assert.equal(isLoopbackHost("192.168.1.10:4873"), false);
    assert.equal(isLoopbackHost("127.0.0.1.evil.example"), false);
    assert.equal(isLoopbackHost(""), false);
  });
});

describe("assertAllowedTarballUrl", () => {
  const registry = "https://registry.npmjs.org";

  test("same-origin tarball URL passes", () => {
    assertAllowedTarballUrl("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", registry, []);
  });

  test("allowlisted extra origin passes", () => {
    assertAllowedTarballUrl("https://cdn.corp.example/lodash.tgz", registry, ["https://cdn.corp.example"]);
  });

  test("cross-origin URL throws", () => {
    assert.throws(
      () => assertAllowedTarballUrl("http://169.254.169.254/latest/meta-data", registry, []),
      /not the registry origin/,
    );
  });

  test("same host but different port is a different origin", () => {
    assert.throws(() => assertAllowedTarballUrl("https://registry.npmjs.org:8443/x.tgz", registry, []), /not the registry origin/);
  });

  test("non-http(s) protocol throws even for a matching host", () => {
    assert.throws(() => assertAllowedTarballUrl("file:///etc/passwd", registry, []), /protocol/);
  });

  test("malformed URL throws", () => {
    assert.throws(() => assertAllowedTarballUrl("not a url", registry, []), /malformed/);
  });
});
