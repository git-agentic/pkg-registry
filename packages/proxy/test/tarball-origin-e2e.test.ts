import assert from "node:assert/strict";
import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, describe, test } from "node:test";
import { gzipSync } from "node:zlib";
import { NpmUpstream, HttpError } from "../src/upstream.js";

const TARBALL_BYTES = "fake-tarball-bytes";

function listen(server: Server): Promise<string> {
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

describe("NpmUpstream tarball origin pinning (hermetic local registry)", () => {
  let canaryHit = false;
  let compatibilityRequest: Buffer | undefined;
  let canary: Server, registry: Server;
  let canaryBase = "", registryBase = "";

  before(async () => {
    // Canary: an "attacker" origin. Any request here trips canaryHit.
    canary = createHttpServer((_req, res) => {
      canaryHit = true;
      res.end(TARBALL_BYTES);
    });
    canaryBase = await listen(canary);

    // Registry: packuments name a tarball URL per package.
    registry = createHttpServer((req, res) => {
      if (req.url === "/-/npm/v1/security/advisories/bulk") {
        const chunks: Buffer[] = [];
        req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        req.on("end", () => {
          compatibilityRequest = Buffer.concat(chunks);
          const encoded = gzipSync(Buffer.from("encoded-response"));
          res.statusCode = 207;
          res.setHeader("content-encoding", "gzip");
          res.setHeader("content-length", encoded.length);
          res.setHeader("set-cookie", ["a=1; HttpOnly", "b=2; Secure"]);
          res.end(encoded);
        });
        return;
      }
      const pkg = (req.url ?? "").split("/")[1] ?? "";
      if (pkg === "good-pkg" || pkg === "evil-pkg" || pkg === "redirect-pkg") {
        const tarball = pkg === "good-pkg"
          ? `${registryBase}/good-pkg/-/good-pkg-1.0.0.tgz`
          : pkg === "redirect-pkg"
            ? `${registryBase}/redirect-pkg/-/redirect-pkg-1.0.0.tgz` // same-origin (allowed) URL...
            : `${canaryBase}/evil.tgz`;
        if ((req.url ?? "").includes("/-/")) {
          if (pkg === "redirect-pkg") {
            // ...that itself 302s to the cross-origin canary. The fetch-follow
            // bypass this test guards against: an allowed initial URL redirecting
            // off-allowlist must be refused, not silently followed.
            res.statusCode = 302;
            res.setHeader("location", `${canaryBase}/evil.tgz`);
            res.end();
            return;
          }
          res.end(TARBALL_BYTES); // same-origin tarball path
          return;
        }
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({
          name: pkg,
          versions: { "1.0.0": { name: pkg, version: "1.0.0", dist: { tarball } } },
        }));
        return;
      }
      res.statusCode = 404;
      res.end("{}");
    });
    registryBase = await listen(registry);
  });

  after(() => { canary.close(); registry.close(); });
  beforeEach(() => { canaryHit = false; });

  test("same-origin tarball URL is fetched", async () => {
    const up = new NpmUpstream(registryBase);
    const buf = await up.getTarball("good-pkg", "1.0.0");
    assert.equal(buf.toString(), TARBALL_BYTES);
  });

  test("compatibility proxy preserves encoded request and response bytes", async () => {
    const up = new NpmUpstream(registryBase);
    const requestBody = gzipSync(Buffer.from("encoded-request"));
    const response = await up.proxyRegistryRequest("/-/npm/v1/security/advisories/bulk", {
      method: "POST", headers: { "content-encoding": "gzip", "content-length": String(requestBody.length), "accept-encoding": "gzip" }, body: requestBody,
    });
    assert.deepEqual(compatibilityRequest, requestBody);
    assert.equal(response.status, 207);
    assert.equal(response.headers["content-encoding"], "gzip");
    assert.deepEqual(response.headers["set-cookie"], ["a=1; HttpOnly", "b=2; Secure"]);
    assert.deepEqual(response.body, gzipSync(Buffer.from("encoded-response")));
  });

  test("compatibility proxy refuses unrecognized routes and foreign origins", async () => {
    const up = new NpmUpstream(registryBase);
    await assert.rejects(() => up.proxyRegistryRequest("/-/not-supported", { method: "GET", headers: {} }), /unrecognized/);
    await assert.rejects(() => up.proxyRegistryRequest(`${canaryBase}/-/v1/search`, { method: "GET", headers: {} }), /outside registry origin/);
    assert.equal(canaryHit, false);
  });

  test("cross-origin tarball URL is refused with 502 — and never requested", async () => {
    const up = new NpmUpstream(registryBase);
    await assert.rejects(
      () => up.getTarball("evil-pkg", "1.0.0"),
      (err: unknown) => err instanceof HttpError && err.status === 502 && /not the registry origin/.test(err.message),
    );
    assert.equal(canaryHit, false, "the disallowed origin must never receive a request");
  });

  test("an origin in the allowlist is admitted", async () => {
    const up = new NpmUpstream(registryBase, [new URL(canaryBase).origin]);
    const buf = await up.getTarball("evil-pkg", "1.0.0");
    assert.equal(buf.toString(), TARBALL_BYTES);
    assert.equal(canaryHit, true);
  });

  test("a same-origin tarball URL that 302s to a cross-origin target is refused — and the redirect target is never contacted", async () => {
    const up = new NpmUpstream(registryBase);
    await assert.rejects(
      () => up.getTarball("redirect-pkg", "1.0.0"),
      (err: unknown) => err instanceof HttpError && err.status === 502,
    );
    assert.equal(canaryHit, false, "the redirect target must never receive a request — auto-follow must not bypass the allowlist");
  });
});
