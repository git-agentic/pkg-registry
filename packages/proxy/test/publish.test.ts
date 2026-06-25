import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { DEFAULT_POLICY, integrityOf, type EnterprisePolicy } from "@sentinel/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "..", "..", "fixtures");
function ensure() { if (!existsSync(join(FIXTURES, "registry.json")) || !existsSync(join(FIXTURES, ".tarballs")))
  execFileSync("npx", ["tsx", join(HERE, "..", "..", "..", "scripts", "make-fixtures.ts")], { stdio: "ignore" }); }

const policy = (ns: string[]): EnterprisePolicy => ({ ...DEFAULT_POLICY, privateNamespaces: ns });

// A benign tarball lifted from the fixtures, wrapped as an npm publish payload.
import { readFileSync } from "node:fs";
function publishPayload(name: string, version: string, tgz: Buffer) {
  const data = tgz.toString("base64");
  return JSON.stringify({
    _id: name, name, "dist-tags": { latest: version },
    versions: { [version]: { name, version, dist: { integrity: integrityOf(tgz), shasum: "x", tarball: "http://x" } } },
    _attachments: { [`${name}-${version}.tgz`]: { content_type: "application/octet-stream", data, length: tgz.length } },
  });
}

describe("publish route (PUT /:pkg)", () => {
  let server: Server; let base: string; let priv: PrivatePackageStore;
  const benign = () => readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
  const malicious = () => readFileSync(join(FIXTURES, ".tarballs", "color-stream-1.4.1.tgz"));

  before(async () => {
    ensure();
    priv = new PrivatePackageStore();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(), approvals: new ApprovalStore(), privateStore: priv,
      enterprisePolicy: policy(["@acme/*"]), publishTokens: ["tok-1"], policy: "block",
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  const put = (name: string, body: string, headers: Record<string,string> = {}) =>
    fetch(`${base}/${encodeURIComponent(name)}`, { method: "PUT", headers: { "content-type": "application/json", ...headers }, body });

  test("401 without a valid token", async () => {
    const res = await put("@acme/widget", publishPayload("@acme/widget", "1.0.0", benign()));
    assert.equal(res.status, 401);
  });

  test("403 publishing a name outside any claimed namespace", async () => {
    const res = await put("not-claimed", publishPayload("not-claimed", "1.0.0", benign()), { authorization: "Bearer tok-1" });
    assert.equal(res.status, 403);
  });

  test("201 publishes a claimed package and stores it", async () => {
    const res = await put("@acme/widget", publishPayload("@acme/widget", "1.0.0", benign()), { authorization: "Bearer tok-1" });
    assert.equal(res.status, 201);
    assert.equal((await res.json()).ok, true);
    assert.equal(priv.has("@acme/widget"), true);
    assert.equal(priv.getTarball("@acme/widget", "1.0.0")?.length, benign().length);
  });

  test("409 on a duplicate version", async () => {
    const res = await put("@acme/widget", publishPayload("@acme/widget", "1.0.0", benign()), { authorization: "Bearer tok-1" });
    assert.equal(res.status, 409);
  });

  test("403 publish is rejected when the audit verdict is block", async () => {
    const res = await put("@acme/evil", publishPayload("@acme/evil", "1.0.0", malicious()), { authorization: "Bearer tok-1" });
    assert.equal(res.status, 403);
    assert.match((await res.json()).error, /block/i);
    assert.equal(priv.has("@acme/evil"), false); // not stored
  });
});
