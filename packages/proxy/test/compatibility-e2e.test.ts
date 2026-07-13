import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { gzipSync } from "node:zlib";
import { DEFAULT_POLICY, generateKeypair, integrityOf, integrityOfAlgo, runAudit, signToken, type ClaimCorpus, type EnterprisePolicy } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { LocalFixtureUpstream, type Upstream } from "../src/upstream.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const FIXTURES = join(ROOT, "fixtures");
const NOW = Date.parse("2026-07-13T12:00:00.000Z");
const policy: EnterprisePolicy = { ...DEFAULT_POLICY, privateNamespaces: ["@acme/*"] };
const servers: Server[] = [];
after(() => servers.forEach((server) => server.close()));

async function seed(store: PrivatePackageStore, name = "@acme/widget", version = "1.0.0", publishedAt?: string) {
  const tarball = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
  const integrity = integrityOf(tarball);
  const audit = await runAudit({ meta: { name, version, author: null, maintainers: [], license: null,
    hasInstallScripts: false, integrity }, tarball });
  store.publish({ name, version, integrity, manifest: { name, version, dependencies: { x: "1" }, dist: { integrity } },
    tarball, audit, actor: "test", ...(publishedAt ? { publishedAt } : {}) });
}

async function boot(store = new PrivatePackageStore(undefined, () => NOW), overrides: Partial<Parameters<typeof createServer>[0]> = {}) {
  const app = createServer({ upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    privateStore: store, enterprisePolicy: policy, publishTokens: ["publish-token"], policy: "observe", now: () => NOW,
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(), ...overrides });
  const server = await new Promise<Server>((resolve) => { const value = app.listen(0, () => resolve(value)); });
  servers.push(server);
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, store };
}

describe("Phase 33 npm compatibility surface", () => {
  test("native packuments negotiate full and abbreviated documents", async () => {
    const store = new PrivatePackageStore(undefined, () => NOW);
    await seed(store);
    const { base } = await boot(store);
    const fullResponse = await fetch(`${base}/@acme%2fwidget?write=true`);
    const full = await fullResponse.json();
    assert.match(fullResponse.headers.get("content-type") ?? "", /^application\/json/);
    assert.equal(full.time["1.0.0"], "2026-07-13T12:00:00.000Z");
    assert.match(full._rev, /^1-/);

    const abbreviatedResponse = await fetch(`${base}/@acme%2fwidget`, { headers: { accept: "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8" } });
    const abbreviated = await abbreviatedResponse.json();
    assert.match(abbreviatedResponse.headers.get("content-type") ?? "", /^application\/vnd\.npm\.install-v1\+json/);
    assert.equal(abbreviated.time, undefined);
    assert.equal(abbreviated.versions["1.0.0"].dependencies.x, "1");
  });

  test("legacy login, whoami, dist-tags, and deprecation work with npm wire shapes", async () => {
    const store = new PrivatePackageStore(undefined, () => NOW);
    await seed(store);
    const { base } = await boot(store);
    const login = await fetch(`${base}/-/user/org.couchdb.user:alice`, { method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({ _id: "org.couchdb.user:alice", name: "alice", password: "publish-token", type: "user", roles: [] }) });
    assert.equal(login.status, 201);
    const token = (await login.json()).token as string;
    assert.deepEqual(await (await fetch(`${base}/-/whoami`, { headers: { authorization: `Bearer ${token}` } })).json(), { username: "alice" });

    const auth = { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/vnd.npm.install-v1+json" };
    assert.equal((await fetch(`${base}/-/package/@acme%2fwidget/dist-tags/stable`, { method: "PUT", headers: auth, body: JSON.stringify("1.0.0") })).status, 201);
    assert.deepEqual(await (await fetch(`${base}/-/package/@acme%2fwidget/dist-tags`)).json(), { latest: "1.0.0", stable: "1.0.0" });
    assert.equal((await fetch(`${base}/-/package/@acme%2fwidget/dist-tags/stable`, { method: "DELETE", headers: auth })).status, 200);

    const packument = await (await fetch(`${base}/@acme%2fwidget?write=true`)).json();
    packument.versions["1.0.0"].deprecated = "use v2";
    const update = await fetch(`${base}/@acme%2fwidget`, { method: "PUT", headers: auth, body: JSON.stringify(packument) });
    assert.equal(update.status, 201);
    assert.equal((await (await fetch(`${base}/@acme%2fwidget?write=true`)).json()).versions["1.0.0"].deprecated, "use v2");
  });

  test("whoami echoes the subject of a signed role token", async () => {
    const keys = generateKeypair();
    const { base } = await boot(undefined, { authPublicKey: keys.publicKey });
    const token = signToken({ role: "publisher", sub: "release-bot", ttlSeconds: 60 }, keys.privateKey);
    assert.deepEqual(await (await fetch(`${base}/-/whoami`, { headers: { authorization: `Bearer ${token}` } })).json(), { username: "release-bot" });
  });

  test("legacy login sessions expire", async () => {
    let clock = NOW;
    const { base } = await boot(undefined, { now: () => clock, publishRateLimit: { limit: 10, windowMs: 60_000 } });
    const login = await fetch(`${base}/-/user/org.couchdb.user:alice`, { method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "alice", password: "publish-token" }) });
    const token = (await login.json()).token as string;
    assert.equal((await fetch(`${base}/-/whoami`, { headers: { authorization: `Bearer ${token}` } })).status, 200);
    clock += 60 * 60_000 + 1;
    assert.equal((await fetch(`${base}/-/whoami`, { headers: { authorization: `Bearer ${token}` } })).status, 401);
  });

  test("legacy login is rate-limited", async () => {
    const { base } = await boot(undefined, { publishRateLimit: { limit: 1, windowMs: 60_000 } });
    const request = () => fetch(`${base}/-/user/org.couchdb.user:alice`, { method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "alice", password: "publish-token" }) });
    assert.equal((await request()).status, 201);
    assert.equal((await request()).status, 429);
  });

  test("whoami authentication is rate-limited", async () => {
    const { base } = await boot(undefined, { publishRateLimit: { limit: 2, windowMs: 60_000 } });
    const login = await fetch(`${base}/-/user/org.couchdb.user:alice`, { method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "alice", password: "publish-token" }) });
    const token = (await login.json()).token as string;
    const request = () => fetch(`${base}/-/whoami`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal((await request()).status, 200);
    assert.equal((await request()).status, 429);
  });

  test("npm's -rev dance maps single-version unpublish onto retraction", async () => {
    const store = new PrivatePackageStore(undefined, () => NOW);
    await seed(store);
    const { base } = await boot(store);
    const packument = await (await fetch(`${base}/@acme%2fwidget?write=true`)).json();
    const headers = { authorization: "Bearer publish-token", "content-type": "application/json" };
    const stage = await fetch(`${base}/@acme%2fwidget/-rev/${packument._rev}`, { method: "PUT", headers, body: JSON.stringify(packument) });
    assert.equal(stage.status, 200);
    const remove = await fetch(`${base}/@acme/widget/-/widget-1.0.0.tgz/-rev/${packument._rev}`, { method: "DELETE", headers });
    assert.equal(remove.status, 201);
    assert.equal((await fetch(`${base}/@acme/widget/-/widget-1.0.0.tgz`)).status, 410);
  });

  test("unpublish past the window surfaces the full 403 window state", async () => {
    const store = new PrivatePackageStore(undefined, () => NOW - 73 * 3_600_000);
    await seed(store);
    const { base } = await boot(store);
    const packument = await (await fetch(`${base}/@acme%2fwidget?write=true`)).json();
    const response = await fetch(`${base}/@acme%2fwidget/-rev/${packument._rev}`, { method: "DELETE", headers: { authorization: "Bearer publish-token" } });
    assert.equal(response.status, 403);
    const body = await response.json();
    assert.equal(body.code, "retraction-window-closed");
    assert.equal(body.window.maxAgeHours, 72);
  });

  test("whole-package unpublish retracts all versions atomically", async () => {
    const store = new PrivatePackageStore(undefined, () => NOW);
    await seed(store, "@acme/widget", "1.0.0");
    await seed(store, "@acme/widget", "2.0.0");
    const { base } = await boot(store);
    const revision = (await (await fetch(`${base}/@acme%2fwidget?write=true`)).json())._rev;
    const response = await fetch(`${base}/@acme%2fwidget/-rev/${revision}`, { method: "DELETE", headers: { authorization: "Bearer publish-token" } });
    assert.equal(response.status, 201, await response.clone().text());
    assert.deepEqual(Object.keys((await (await fetch(`${base}/@acme%2fwidget?write=true`)).json()).versions), []);
  });

  test("whole-package unpublish does not partially retract when one version is outside the window", async () => {
    const store = new PrivatePackageStore(undefined, () => NOW);
    await seed(store, "@acme/widget", "1.0.0", new Date(NOW - 73 * 3_600_000).toISOString());
    await seed(store, "@acme/widget", "2.0.0", new Date(NOW - 2 * 3_600_000).toISOString());
    const { base } = await boot(store);
    const revision = (await (await fetch(`${base}/@acme%2fwidget?write=true`)).json())._rev;
    const response = await fetch(`${base}/@acme%2fwidget/-rev/${revision}`, { method: "DELETE", headers: { authorization: "Bearer publish-token" } });
    assert.equal(response.status, 403);
    assert.deepEqual(Object.keys(store.packument("@acme/widget")!.versions).sort(), ["1.0.0", "2.0.0"]);
  });

  test("all designated proxy routes preserve request and response bytes and end-to-end headers", async () => {
    const expected = Buffer.from("{\n  \"order\": [3, 2, 1]\n}\n");
    const seen: { path: string; method: string; headers: Record<string, string>; body?: Buffer }[] = [];
    const upstream: Upstream = {
      name: "proxy-probe",
      async getPackument() { throw new Error("unused"); }, async getTarball() { throw new Error("unused"); }, async getAttestations() { return null; },
      async proxyRegistryRequest(path, init) { seen.push({ path, ...init }); return { status: 207,
        headers: { "content-type": "application/json", etag: "probe", "set-cookie": ["a=1; HttpOnly", "b=2; Secure"] }, body: expected }; },
    };
    const { base } = await boot(undefined, { upstream });
    const raw = Buffer.from("{ \n  \"lodash\" : [\"1.0.0\"] \n}\n");
    const gzipped = gzipSync(raw);
    const routes = [
      { path: "/-/v1/search?text=x", method: "GET" },
      { path: "/-/npm/v1/security/advisories/bulk", method: "POST", body: gzipped, encoding: "gzip" },
      { path: "/-/npm/v1/keys", method: "GET" },
      { path: "/-/npm/v1/attestations/%40acme%2Fwidget@1.0.0", method: "GET" },
      { path: "/-/v1/login", method: "POST", body: raw },
    ];
    for (const route of routes) {
      const response = await fetch(`${base}${route.path}`, { method: route.method, headers: {
        authorization: "Bearer upstream-token", "if-none-match": "old-etag", "content-type": "application/json", "x-probe": "preserve",
        ...(route.encoding ? { "content-encoding": route.encoding } : {}),
      }, ...(route.body ? { body: route.body } : {}) });
      assert.equal(response.status, 207);
      assert.equal(response.headers.get("etag"), "probe");
      assert.deepEqual(response.headers.getSetCookie(), ["a=1; HttpOnly", "b=2; Secure"]);
      assert.deepEqual(Buffer.from(await response.arrayBuffer()), expected);
    }
    assert.deepEqual(seen.map((call) => call.path), routes.map((route) => route.path));
    for (const [index, call] of seen.entries()) {
      assert.equal(call.headers.authorization, "Bearer upstream-token");
      assert.equal(call.headers["if-none-match"], "old-etag");
      assert.equal(call.headers["x-probe"], "preserve");
      assert.equal(call.headers["content-encoding"], routes[index]!.encoding);
      assert.equal(call.headers.host, undefined);
      assert.deepEqual(call.body, routes[index]!.body);
    }
  });

  test("audit-gated history import preserves pre-claim integrity", async () => {
    const claimantPublicKey = generateKeypair().publicKey;
    const claimCorpus: ClaimCorpus = { schema: 1, version: "claim-import", issuedAt: "2026-07-13T00:00:00.000Z", claims: [{
      namespace: "leftpad-lite", domain: "example.test", claimantPublicKey, status: "active",
      challenge: { method: "dns-txt", id: "c", verifiedAt: "2026-07-12T00:00:00.000Z" }, renewalDueAt: "2027-07-12T00:00:00.000Z",
    }] };
    const fixture = new LocalFixtureUpstream(FIXTURES);
    const bytes = await fixture.getTarball("leftpad-lite", "1.0.1");
    const expectedIntegrity = integrityOfAlgo(bytes, "sha1");
    const legacyUpstream: Upstream = {
      name: "legacy-integrity",
      async getPackument(name) {
        const packument = structuredClone(await fixture.getPackument(name));
        packument.doc.versions["1.0.1"]!.dist.integrity = expectedIntegrity;
        packument.doc["dist-tags"] = { latest: "1.0.0", legacy: "1.0.1" };
        return packument;
      },
      getTarball: (name, version) => fixture.getTarball(name, version),
      getAttestations: (name, version) => fixture.getAttestations(name, version),
    };
    const { base } = await boot(new PrivatePackageStore(undefined, () => NOW), {
      enterprisePolicy: { ...DEFAULT_POLICY, privateNamespaces: [] }, claimCorpus, upstream: legacyUpstream,
    });
    assert.equal((await fetch(`${base}/leftpad-lite`)).status, 404);
    const imported = await fetch(`${base}/-/registry/import`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "leftpad-lite" }) });
    assert.equal(imported.status, 201, await imported.text());
    const after = await (await fetch(`${base}/leftpad-lite`)).json();
    assert.equal(after.versions["1.0.1"].dist.integrity, expectedIntegrity);
    assert.deepEqual(after["dist-tags"], { latest: "1.0.0", legacy: "1.0.1" });
    assert.equal((await fetch(after.versions["1.0.1"].dist.tarball)).status, 200);
  });

  test("mode on/off/on restarts preserve native packument bytes on the same origin", async () => {
    const native = new PrivatePackageStore(undefined, () => NOW);
    await seed(native, "leftpad-lite", "9.0.0");
    const claimantPublicKey = generateKeypair().publicKey;
    const claimCorpus: ClaimCorpus = { schema: 1, version: "roundtrip", issuedAt: "2026-07-13T00:00:00.000Z", claims: [{
      namespace: "leftpad-lite", domain: "example.test", claimantPublicKey, status: "active",
      challenge: { method: "dns-txt", id: "c", verifiedAt: "2026-07-12T00:00:00.000Z" }, renewalDueAt: "2027-07-12T00:00:00.000Z",
    }] };
    const makeApp = (registryMode: "on" | "off") => createServer({ upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(), approvals: new ApprovalStore(), privateStore: native,
      enterprisePolicy: { ...DEFAULT_POLICY, privateNamespaces: [] }, claimCorpus, registryMode,
      policy: "observe", now: () => NOW, violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore() });
    const listen = (mode: "on" | "off", port: number) => new Promise<Server>((resolve) => {
      const server = makeApp(mode).listen(port, "127.0.0.1", () => resolve(server));
    });
    const close = (server: Server) => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    const first = await listen("on", 0);
    const port = (first.address() as AddressInfo).port;
    const url = `http://127.0.0.1:${port}/leftpad-lite`;
    const before = Buffer.from(await (await fetch(url)).arrayBuffer());
    await close(first);
    const off = await listen("off", port);
    const publicBytes = Buffer.from(await (await fetch(url)).arrayBuffer());
    await close(off);
    assert.notDeepEqual(publicBytes, before);
    const restored = await listen("on", port);
    const after = Buffer.from(await (await fetch(url)).arrayBuffer());
    await close(restored);
    assert.deepEqual(after, before);
  });
});
