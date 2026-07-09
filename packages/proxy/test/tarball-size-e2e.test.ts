import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, test } from "node:test";
import { NpmUpstream, HttpError } from "../src/upstream.js";

function listen(server: Server): Promise<string> {
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

describe("NpmUpstream byte caps (hermetic local registry)", () => {
  let registry: Server;
  let base = "";

  before(async () => {
    registry = createHttpServer((req, res) => {
      const url = req.url ?? "";
      // Packument for big-pkg: small JSON pointing tarball at the same origin.
      if (url === "/big-pkg") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({
          name: "big-pkg",
          versions: { "1.0.0": { name: "big-pkg", version: "1.0.0", dist: { tarball: `${base}/big-pkg/-/big-pkg-1.0.0.tgz` } } },
        }));
        return;
      }
      // Oversized tarball: 50 KB body, no content-length (chunked) so the cap must catch it mid-stream.
      if (url === "/big-pkg/-/big-pkg-1.0.0.tgz") {
        res.end(Buffer.alloc(50 * 1024, 9));
        return;
      }
      // Oversized packument for huge-doc: 50 KB JSON-ish body.
      if (url === "/huge-doc") {
        res.setHeader("content-type", "application/json");
        res.end(Buffer.alloc(50 * 1024, 0x20)); // spaces — irrelevant, cap trips before parse
        return;
      }
      res.statusCode = 404;
      res.end("{}");
    });
    base = await listen(registry);
  });
  after(() => registry.close());

  test("a tarball over the cap is refused with 502", async () => {
    const up = new NpmUpstream(base, [], 1024, 128 * 1024 * 1024); // 1 KB tarball cap
    await assert.rejects(
      () => up.getTarball("big-pkg", "1.0.0"),
      (err: unknown) => err instanceof HttpError && err.status === 502 && /too large/.test(err.message),
    );
  });

  test("a packument over the cap is refused with 502", async () => {
    const up = new NpmUpstream(base, [], 256 * 1024 * 1024, 1024); // 1 KB packument cap
    await assert.rejects(
      () => up.getPackument("huge-doc"),
      (err: unknown) => err instanceof HttpError && err.status === 502 && /too large/.test(err.message),
    );
  });

  test("a tarball under the cap fetches fine", async () => {
    const up = new NpmUpstream(base, [], 1024 * 1024, 128 * 1024 * 1024); // 1 MB tarball cap
    const buf = await up.getTarball("big-pkg", "1.0.0");
    assert.equal(buf.length, 50 * 1024);
  });
});
