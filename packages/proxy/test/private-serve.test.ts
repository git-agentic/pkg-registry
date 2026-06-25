import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { DEFAULT_POLICY, runAudit, integrityOf, type EnterprisePolicy } from "@sentinel/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "..", "..", "fixtures");
function ensure() { if (!existsSync(join(FIXTURES, "registry.json")) || !existsSync(join(FIXTURES, ".tarballs")))
  execFileSync("npx", ["tsx", join(HERE, "..", "..", "..", "scripts", "make-fixtures.ts")], { stdio: "ignore" }); }
const policy = (ns: string[]): EnterprisePolicy => ({ ...DEFAULT_POLICY, privateNamespaces: ns });

describe("private serve routing", () => {
  let server: Server; let base: string; let priv: PrivatePackageStore;

  before(async () => {
    ensure();
    priv = new PrivatePackageStore();
    // Seed a published private package directly (a benign tarball).
    const tgz = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
    const meta = { name: "@acme/widget", version: "1.0.0", author: null, maintainers: [], license: null,
      hasInstallScripts: false, signatureStatus: "unknown" as const, integrity: integrityOf(tgz) };
    const audit = await runAudit({ meta, tarball: tgz });
    priv.put({ name: "@acme/widget", version: "1.0.0", integrity: integrityOf(tgz),
      manifest: { name: "@acme/widget", version: "1.0.0", dist: {} }, tarball: tgz, audit, actor: "seed" });

    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(), approvals: new ApprovalStore(), privateStore: priv,
      enterprisePolicy: policy(["@acme/*"]), policy: "block",
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  test("claimed packument is synthesized with rewritten tarball URLs", async () => {
    const doc = await (await fetch(`${base}/@acme%2fwidget`)).json();
    assert.equal(doc.name, "@acme/widget");
    assert.ok(doc.versions["1.0.0"]);
    assert.ok(String(doc.versions["1.0.0"].dist.tarball).startsWith(base));
  });

  test("claimed tarball is served privately with x-sentinel-private", async () => {
    const res = await fetch(`${base}/@acme/widget/-/widget-1.0.0.tgz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-sentinel-private"), "true");
    assert.ok((await res.arrayBuffer()).byteLength > 0);
  });

  test("claimed but UNPUBLISHED name → 404, never public", async () => {
    const pm = await fetch(`${base}/@acme%2fmissing`);
    assert.equal(pm.status, 404);
    const tb = await fetch(`${base}/@acme/missing/-/missing-9.9.9.tgz`);
    assert.equal(tb.status, 404);
  });

  test("non-claimed name still passes through to public (fixtures)", async () => {
    const doc = await (await fetch(`${base}/leftpad-lite`)).json();
    assert.ok(doc.versions["1.0.1"], "public passthrough unchanged");
  });

  test("/-/audit of a claimed published package returns its report without hitting upstream", async () => {
    const res = await fetch(`${base}/-/audit/@acme%2fwidget/1.0.0`);
    assert.equal(res.status, 200);
    const body = await res.json() as { meta: { name: string }; verdict: string };
    assert.equal(body.meta.name, "@acme/widget");
    assert.ok(body.verdict, "verdict should be present");
  });

  test("/-/manifest of a claimed published package works", async () => {
    const res = await fetch(`${base}/-/manifest/@acme%2fwidget/1.0.0`);
    assert.equal(res.status, 200);
    const body = await res.json() as { meta: { name: string }; approvalState: string };
    assert.equal(body.meta.name, "@acme/widget");
    assert.ok(body.approvalState !== undefined, "approvalState should be present");
  });

  test("/-/audit of a claimed UNPUBLISHED name → 404 (fail-closed, no upstream)", async () => {
    const res = await fetch(`${base}/-/audit/@acme%2fmissing/1.0.0`);
    assert.equal(res.status, 404);
  });

  test("approval round-trip for a claimed package", async () => {
    // First fetch manifest to populate the store
    const manifestRes = await fetch(`${base}/-/manifest/@acme%2fwidget/1.0.0`);
    assert.equal(manifestRes.status, 200);
    const manifest = await manifestRes.json() as { meta: { integrity: string } };
    const integrity = manifest.meta.integrity;
    assert.ok(integrity, "integrity should be present in manifest");

    // Now POST approval — should succeed (not 400 "audit first")
    const approvalRes = await fetch(`${base}/-/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ integrity, decision: "approved", actor: { type: "agent", id: "t" } }),
    });
    assert.equal(approvalRes.status, 200, "approval should succeed, not 400 'audit first'");
  });
});
