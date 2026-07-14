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
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import { LocalFixtureUpstream, type Upstream } from "../src/upstream.js";
import { DEFAULT_POLICY, generateKeypair, runAudit, integrityOf, type EnterprisePolicy } from "@agentic-sentinel/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "..", "..", "fixtures");
function ensure() { if (!existsSync(join(FIXTURES, "registry.json")) || !existsSync(join(FIXTURES, ".tarballs")))
  execFileSync("npx", ["tsx", join(HERE, "..", "..", "..", "scripts", "make-fixtures.ts")], { stdio: "ignore" }); }
const policy = (ns: string[]): EnterprisePolicy => ({ ...DEFAULT_POLICY, privateNamespaces: ns });
const CLAIMANT_KEY = generateKeypair().publicKey;
const verifiedCorpus = (namespace: string) => ({
  schema: 1 as const, version: "test", issuedAt: "2026-07-02T00:00:00.000Z", claims: [{ namespace,
    domain: "claim.example", claimantPublicKey: CLAIMANT_KEY, status: "active" as const,
    challenge: { method: "dns-txt" as const, id: "c-1", verifiedAt: "2026-07-01T00:00:00.000Z" },
    renewalDueAt: "2027-07-01T00:00:00.000Z" }],
});

describe("private serve routing", () => {
  let server: Server; let base: string; let priv: PrivatePackageStore; let fixtureUpstream: LocalFixtureUpstream;

  before(async () => {
    ensure();
    priv = new PrivatePackageStore();
    // Seed a published private package directly (a benign tarball).
    const tgz = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
    const meta = { name: "@acme/widget", version: "1.0.0", author: null, maintainers: [], license: null,
      hasInstallScripts: false, signature: "unsigned" as const, provenance: "absent" as const, integrity: integrityOf(tgz) };
    const audit = await runAudit({ meta, tarball: tgz });
    priv.put({ name: "@acme/widget", version: "1.0.0", integrity: integrityOf(tgz),
      manifest: { name: "@acme/widget", version: "1.0.0", dist: {} }, tarball: tgz, audit, actor: "seed" });

    fixtureUpstream = new LocalFixtureUpstream(FIXTURES);
    const app = createServer({
      upstream: fixtureUpstream,
      store: new AuditStore(), approvals: new ApprovalStore(), privateStore: priv,
      enterprisePolicy: policy(["@acme/*"]), policy: "block",
      violations: new ViolationStore(),
      approvalRequests: new ApprovalRequestStore(),
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

  test("mirrored packument changes only dist.tarball URLs", async () => {
    const expected = structuredClone((await fixtureUpstream.getPackument("leftpad-lite")).doc);
    for (const [version, manifest] of Object.entries(expected.versions)) {
      manifest.dist.tarball = `${base}/leftpad-lite/-/leftpad-lite-${version}.tgz`;
    }
    const actual = await (await fetch(`${base}/leftpad-lite`)).json();
    assert.deepEqual(actual, JSON.parse(JSON.stringify(expected)));
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

  test("GET /-/private lists claims and published packages", async () => {
    const data = await (await fetch(`${base}/-/private`)).json();
    assert.deepEqual(data.claims, ["@acme/*"]);
    assert.ok(data.packages.some((p: { name: string }) => p.name === "@acme/widget"));
  });
});

describe("Phase 30 packument source isolation", () => {
  test("legacy uppercase public names remain transparent on packument and tarball GETs", async () => {
    ensure();
    const tgz = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
    const calls: string[] = [];
    const upstream: Upstream = {
      name: "legacy-uppercase",
      async getPackument(name) {
        calls.push(`packument:${name}`);
        return {
          doc: {
            name,
            "dist-tags": { latest: "1.0.0" },
            versions: { "1.0.0": { name, version: "1.0.0", dist: { tarball: `https://registry.example/${name}-1.0.0.tgz` } } },
          },
          versions: { "1.0.0": { version: "1.0.0", author: null, maintainers: [], license: null,
            signatures: null, hasProvenance: false, integrity: null, hasInstallScripts: false } },
        };
      },
      async getTarball(name) { calls.push(`tarball:${name}`); return tgz; },
      async getAttestations() { return null; },
    };
    const app = createServer({ upstream, store: new AuditStore(), approvals: new ApprovalStore(),
      privateStore: new PrivatePackageStore(), enterprisePolicy: policy([]), policy: "observe",
      violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore() });
    const server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const packument = await fetch(`${base}/JSONStream`);
      assert.equal(packument.status, 200);
      assert.equal((await packument.json()).name, "JSONStream");
      const tarball = await fetch(`${base}/JSONStream/-/JSONStream-1.0.0.tgz`);
      assert.equal(tarball.status, 200);
      assert.ok(calls.includes("packument:JSONStream"));
      assert.ok(calls.includes("tarball:JSONStream"));
    } finally { server.close(); }
  });

  test("native source never merges upstream versions or tarball URLs", async () => {
    ensure();
    const tgz = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
    const priv = new PrivatePackageStore();
    const audit = await runAudit({ meta: { name: "leftpad-lite", version: "9.0.0", author: null, maintainers: [],
      license: null, hasInstallScripts: false, signature: "unsigned", provenance: "absent", integrity: integrityOf(tgz) }, tarball: tgz });
    priv.put({ name: "leftpad-lite", version: "9.0.0", integrity: integrityOf(tgz),
      manifest: { name: "leftpad-lite", version: "9.0.0", dist: { tarball: "https://upstream.invalid/should-not-survive" } },
      tarball: tgz, audit, actor: "seed" });
    const app = createServer({ upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
      privateStore: priv, enterprisePolicy: policy(["leftpad-lite"]), policy: "block",
      violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore() });
    const server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      const doc = await (await fetch(`${base}/leftpad-lite`)).json();
      assert.deepEqual(Object.keys(doc.versions), ["9.0.0"]);
      assert.deepEqual(doc["dist-tags"], { latest: "9.0.0" });
      assert.equal(doc.versions["1.0.1"], undefined);
      assert.equal(doc.versions["9.0.0"].dist.tarball, `${base}/leftpad-lite/-/leftpad-lite-9.0.0.tgz`);
    } finally { server.close(); }
  });

  test("verified-claimed but unpublished name returns 404 without touching upstream", async () => {
    ensure();
    const inner = new LocalFixtureUpstream(FIXTURES);
    let calls = 0;
    const upstream: Upstream = {
      name: "counting",
      async getPackument(name) { calls++; return inner.getPackument(name); },
      async getTarball(name, version) { calls++; return inner.getTarball(name, version); },
      async getAttestations(name, version) { calls++; return inner.getAttestations(name, version); },
    };
    const app = createServer({ upstream, store: new AuditStore(), approvals: new ApprovalStore(),
      privateStore: new PrivatePackageStore(), enterprisePolicy: policy([]), claimCorpus: verifiedCorpus("leftpad-lite"),
      policy: "block", violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore() });
    const server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      assert.equal((await fetch(`${base}/leftpad-lite`)).status, 404);
      assert.equal((await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.1.tgz`)).status, 404);
      assert.equal(calls, 0);
    } finally { server.close(); }
  });
});
