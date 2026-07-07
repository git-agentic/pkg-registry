import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import { createServer, type Server } from "node:http";
import { reportViolation } from "../src/script-shell.js";

describe("reportViolation", () => {
  let server: Server;
  let base: string;
  const posts: any[] = [];
  before(async () => {
    server = createServer((req, res) => {
      if (req.url?.startsWith("/-/manifest/")) {
        res.setHeader("content-type", "application/json");
        return res.end(JSON.stringify({ meta: { integrity: "sha512-XYZ" } }));
      }
      if (req.url === "/-/violations" && req.method === "POST") {
        let b = "";
        req.on("data", (c) => (b += c));
        req.on("end", () => {
          posts.push(JSON.parse(b));
          res.end("{}");
        });
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    await new Promise<void>((r) =>
      server.listen(0, () => {
        base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        r();
      }),
    );
  });
  after(() => server.close());

  test("posts the violation with the manifest integrity", async () => {
    await reportViolation(base, "evil", "1.0.0", {
      kind: "filesystem",
      target: "/x/.ssh/id_rsa",
      confidence: "confirmed",
      deniedResource: "/x/.ssh",
      evidence: { exitCode: 1, stderrExcerpt: "EPERM" },
    });
    assert.equal(posts.length, 1);
    assert.equal(posts[0].integrity, "sha512-XYZ");
    assert.equal(posts[0].confidence, "confirmed");
  });

  test("a proxy error is swallowed (no throw)", async () => {
    await assert.doesNotReject(
      reportViolation("http://127.0.0.1:1", "x", "1.0.0", {
        kind: "network",
        target: null,
        confidence: "suspected",
        deniedResource: null,
        evidence: { exitCode: 1, stderrExcerpt: "" },
      }),
    );
  });
});
