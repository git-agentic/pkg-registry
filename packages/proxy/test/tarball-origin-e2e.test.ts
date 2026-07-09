import assert from "node:assert/strict";
import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, describe, test } from "node:test";
import { NpmUpstream, HttpError } from "../src/upstream.js";

const TARBALL_BYTES = "fake-tarball-bytes";

function listen(server: Server): Promise<string> {
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

describe("NpmUpstream tarball origin pinning (hermetic local registry)", () => {
  let canaryHit = false;
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
      const pkg = (req.url ?? "").split("/")[1] ?? "";
      if (pkg === "good-pkg" || pkg === "evil-pkg") {
        const tarball = pkg === "good-pkg"
          ? `${registryBase}/good-pkg/-/good-pkg-1.0.0.tgz`
          : `${canaryBase}/evil.tgz`;
        if ((req.url ?? "").includes("/-/")) {
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
});
