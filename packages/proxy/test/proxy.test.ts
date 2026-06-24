import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], {
    cwd: REPO_ROOT,
    stdio: "ignore",
  });
}

describe("registry proxy (block policy, local fixtures)", () => {
  let server: Server;
  let base: string;

  before(async () => {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      policy: "block",
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const { port } = server.address() as AddressInfo;
        base = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(() => server?.close());

  test("health reports the upstream and policy", async () => {
    const h = await (await fetch(`${base}/-/health`)).json();
    assert.equal(h.ok, true);
    assert.equal(h.upstream, "local-fixtures");
    assert.equal(h.policy, "block");
  });

  test("packument is served with tarball URLs rewritten to the proxy", async () => {
    const doc = await (await fetch(`${base}/color-stream`)).json();
    assert.ok(doc.versions["1.4.1"], "packument lists versions");
    const url: string = doc.versions["1.4.1"].dist.tarball;
    assert.ok(url.startsWith(base), `tarball URL should point at the proxy, got ${url}`);
    assert.ok(url.endsWith("/color-stream/-/color-stream-1.4.1.tgz"));
  });

  test("audit API allows the clean version", async () => {
    const r = await (await fetch(`${base}/-/audit/color-stream/1.4.0`)).json();
    assert.equal(r.verdict, "allow");
    assert.equal(r.score, 100);
  });

  test("audit API blocks the malicious version", async () => {
    const r = await (await fetch(`${base}/-/audit/color-stream/1.4.1`)).json();
    assert.equal(r.verdict, "block");
    assert.ok(r.findings.length >= 4);
  });

  test("benign tarball is served with verdict headers", async () => {
    const res = await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.1.tgz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-sentinel-verdict"), "allow");
    assert.equal(res.headers.get("content-type"), "application/octet-stream");
    const body = Buffer.from(await res.arrayBuffer());
    assert.ok(body.length > 0, "tarball bytes are streamed through");
  });

  test("malicious tarball is BLOCKED with 403 under block policy", async () => {
    const res = await fetch(`${base}/color-stream/-/color-stream-1.4.1.tgz`);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-sentinel-verdict"), "block");
    const body = await res.json();
    assert.match(body.error, /blocked by Sentinel/i);
    assert.ok(body.findings.length >= 4, "403 body explains why");
  });

  test("audit log accumulates stats", async () => {
    const data = await (await fetch(`${base}/-/audits`)).json();
    assert.ok(data.stats.total >= 2);
    assert.ok(data.stats.block >= 1);
    assert.ok(Array.isArray(data.audits));
  });
});
