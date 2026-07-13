import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, test } from "node:test";
import { DEFAULT_POLICY, generateKeypair, integrityOf, retractionCorpusHashOfBytes, signToken, type Audit, type EnterprisePolicy, type RetractionCorpus } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import { HistoryDb } from "../src/history-db.js";
import type { Upstream } from "../src/upstream.js";

const NOW = Date.parse("2026-07-13T12:00:00.000Z");
const servers: Server[] = [];
afterEach(() => { while (servers.length) servers.pop()!.close(); });

const upstream: Upstream = {
  name: "must-not-be-called",
  async getPackument() { throw new Error("native names must not reach upstream"); },
  async getTarball() { throw new Error("native names must not reach upstream"); },
  async getAttestations() { throw new Error("native names must not reach upstream"); },
};

function policy(retraction = { maxAgeHours: 72, maxDownloads: 1_000 }): EnterprisePolicy {
  return { ...DEFAULT_POLICY, privateNamespaces: ["@acme/*"], retraction };
}

function audit(name: string, version: string, tarball: Buffer): Audit {
  return {
    schema: 3,
    meta: {
      name, version, integrity: integrityOf(tarball), author: null, maintainers: [], license: null,
      hasInstallScripts: false, signature: "unsigned", provenance: "absent", unpackedSize: tarball.length, fileCount: 1,
    },
    findings: [], capabilities: [], capabilityDelta: null,
    engine: { version: "test", rules: [], mode: "full" }, auditedAt: "2026-07-13T00:00:00.000Z", durationMs: 1,
  };
}

async function boot(ageHours: number, downloads: number, enterprisePolicy = policy(), retractionCorpus?: RetractionCorpus, authPublicKey?: string, history?: HistoryDb) {
  const privateStore = new PrivatePackageStore(undefined, () => NOW - ageHours * 3_600_000);
  const store = new AuditStore();
  for (const version of ["1.0.0", "2.0.0"]) {
    const tarball = Buffer.from(`tarball-${version}`);
    privateStore.publish({
      name: "@acme/widget", version, integrity: integrityOf(tarball), tarball,
      manifest: { name: "@acme/widget", version, dist: { integrity: integrityOf(tarball) } },
      audit: audit("@acme/widget", version, tarball), actor: "publisher",
    });
  }
  for (let i = 0; i < downloads; i++) privateStore.recordDownload("@acme/widget", "2.0.0");
  const app = createServer({
    upstream, store, approvals: new ApprovalStore(), privateStore, enterprisePolicy,
    policy: "block", violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(), now: () => NOW,
    retractionCorpus,
    authPublicKey,
    history,
  });
  const server = await new Promise<Server>((resolve) => { const value = app.listen(0, () => resolve(value)); });
  servers.push(server);
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const retract = (reason: "security" | "withdrawn" | "broken" | "legal" = "security", authorization?: string) => fetch(`${base}/-/retractions`, {
    method: "POST", headers: { "content-type": "application/json", ...(authorization ? { authorization } : {}) },
    body: JSON.stringify({ name: "@acme/widget", version: "2.0.0", reason }),
  });
  return { base, privateStore, store, retract };
}

describe("Phase 32 time-locked retraction", () => {
  test("71 h / 999 succeeds; range metadata retargets and the tarball becomes a 410 tombstone", async () => {
    const ctx = await boot(71, 999);
    const before = await fetch(`${ctx.base}/-/audit/${encodeURIComponent("@acme/widget")}/2.0.0`);
    assert.equal(before.status, 200);
    const storedBefore = JSON.stringify(ctx.store.get(integrityOf(Buffer.from("tarball-2.0.0")))?.report);

    const response = await ctx.retract("security");
    assert.equal(response.status, 201, await response.clone().text());
    const created = await response.json();
    assert.equal(created.tombstone.reason, "security");
    assert.match(created.tombstone.advisoryId, /^SENTINEL-RETRACT-/);
    const feed = await (await fetch(`${ctx.base}/-/retractions`)).json();
    assert.equal(feed.advisories[0].id, created.tombstone.advisoryId);
    assert.match(feed.downloadCounting, /successful.*npm-session/i);

    const packument = await (await fetch(`${ctx.base}/@acme%2Fwidget`)).json();
    assert.deepEqual(Object.keys(packument.versions), ["1.0.0"]);
    assert.equal(packument["dist-tags"].latest, "1.0.0");
    assert.deepEqual(packument._sentinel.retractions["2.0.0"], created.tombstone);

    const gone = await fetch(`${ctx.base}/@acme%2Fwidget/-/widget-2.0.0.tgz`);
    assert.equal(gone.status, 410);
    assert.deepEqual(await gone.json(), {
      error: "package version retracted", package: "@acme/widget@2.0.0", ...created.tombstone,
    });
    assert.equal((await fetch(`${ctx.base}/@acme%2Fwidget/-/widget-1.0.0.tgz`)).status, 200);
    assert.equal(JSON.stringify(ctx.store.get(integrityOf(Buffer.from("tarball-2.0.0")))?.report), storedBefore,
      "serve-time retraction overlay must not rewrite the cached AuditReport");
  });

  test("73 h / 5 and 2 h / 1,001 reject with distinct bound errors and telemetry", async () => {
    const old = await boot(73, 5);
    const ageResponse = await old.retract();
    assert.equal(ageResponse.status, 403);
    const ageBody = await ageResponse.json();
    assert.deepEqual(ageBody.exceeded.map((e: { code: string }) => e.code), ["retraction-age-limit-exceeded"]);
    assert.equal(ageBody.window.ageHours, 73);
    assert.equal(ageBody.window.cumulativeDownloads, 5);
    assert.deepEqual(old.privateStore.retractionWindowHits(), { age: 1, downloads: 0, both: 0 });
    assert.equal((await (await fetch(`${old.base}/-/retractions`)).json()).windowHits.age, 1);

    const popular = await boot(2, 1_001);
    const downloadResponse = await popular.retract();
    assert.equal(downloadResponse.status, 403);
    const downloadBody = await downloadResponse.json();
    assert.deepEqual(downloadBody.exceeded.map((e: { code: string }) => e.code), ["retraction-download-limit-exceeded"]);
    assert.equal(downloadBody.window.ageHours, 2);
    assert.equal(downloadBody.window.cumulativeDownloads, 1_001);
    assert.deepEqual(popular.privateStore.retractionWindowHits(), { age: 0, downloads: 1, both: 0 });
  });

  test("the exclusive boundaries reject at exactly 72 hours or 1,000 downloads", async () => {
    const ageBoundary = await boot(72, 0);
    assert.deepEqual((await (await ageBoundary.retract()).json()).exceeded.map((e: { code: string }) => e.code),
      ["retraction-age-limit-exceeded"]);
    const downloadBoundary = await boot(1, 1_000);
    assert.deepEqual((await (await downloadBoundary.retract()).json()).exceeded.map((e: { code: string }) => e.code),
      ["retraction-download-limit-exceeded"]);
  });

  test("audit-tree immediately flags the local advisory while the stored score remains immutable", async () => {
    const ctx = await boot(2, 0);
    await fetch(`${ctx.base}/@acme%2Fwidget/-/widget-2.0.0.tgz`);
    const integrity = integrityOf(Buffer.from("tarball-2.0.0"));
    const storedBefore = JSON.stringify(ctx.store.get(integrity)?.report);
    assert.equal((await ctx.retract("security")).status, 201);

    const tree = await (await fetch(`${ctx.base}/-/audit-tree`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ packages: [{ name: "@acme/widget", version: "2.0.0", integrity }] }),
    })).json();
    assert.equal(tree.packages[0].status, "block");
    assert.equal(tree.packages[0].topFindingRuleId, "known-advisory");
    assert.match(tree.packages[0].topFinding, /retracted/i);
    assert.equal(JSON.stringify(ctx.store.get(integrity)?.report), storedBefore);
  });

  test("explain never recommends a retracted prior version", async () => {
    const ctx = await boot(2, 0);
    ctx.privateStore.retract({ name: "@acme/widget", version: "1.0.0", reason: "broken",
      retractedAt: "2026-07-13T12:00:00.000Z", advisoryId: "SENTINEL-RETRACT-prior" });
    const explained = await (await fetch(`${ctx.base}/-/explain/${encodeURIComponent("@acme/widget")}/2.0.0`)).json();
    assert.equal(explained.lastKnownGood, null);
  });

  test("successful native tarball responses count downloads; blocked retracted requests do not", async () => {
    const ctx = await boot(1, 0, policy({ maxAgeHours: 72, maxDownloads: 2 }));
    const tarballUrl = `${ctx.base}/@acme%2Fwidget/-/widget-2.0.0.tgz`;
    assert.equal((await fetch(tarballUrl)).status, 200);
    assert.equal(ctx.privateStore.downloadCount("@acme/widget", "2.0.0"), 1);
    assert.equal((await ctx.retract("broken")).status, 201);
    const report = await (await fetch(`${ctx.base}/-/audit/${encodeURIComponent("@acme/widget")}/2.0.0`)).json();
    assert.equal(report.verdict, "warn");
    assert.equal(report.findings[0].severity, "medium");
    assert.equal((await fetch(tarballUrl)).status, 410);
    assert.equal(ctx.privateStore.downloadCount("@acme/widget", "2.0.0"), 1);
  });

  test("policy weights can escalate a moderate retraction to block", async () => {
    const enterprisePolicy = policy();
    enterprisePolicy.scoring = {
      ...enterprisePolicy.scoring,
      severityWeight: { ...enterprisePolicy.scoring.severityWeight, medium: 60 },
    };
    const ctx = await boot(1, 0, enterprisePolicy);
    assert.equal((await ctx.retract("withdrawn")).status, 201);
    const report = await (await fetch(`${ctx.base}/-/audit/${encodeURIComponent("@acme/widget")}/2.0.0`)).json();
    assert.equal(report.findings[0].weight, 60);
    assert.equal(report.verdict, "block");
  });

  test("an explicit policy rule disable waives the audit verdict but not the 410 tombstone", async () => {
    const enterprisePolicy = policy();
    enterprisePolicy.rules = { disabled: ["known-advisory"] };
    const ctx = await boot(1, 0, enterprisePolicy);
    assert.equal((await ctx.retract("security")).status, 201);
    const report = await (await fetch(`${ctx.base}/-/audit/${encodeURIComponent("@acme/widget")}/2.0.0`)).json();
    assert.equal(report.findings[0].waived, true);
    assert.equal(report.verdict, "allow");
    assert.equal((await fetch(`${ctx.base}/@acme%2Fwidget/-/widget-2.0.0.tgz`)).status, 410);
  });

  test("enabling a fresh history DB cannot reset the fallback cumulative count", async () => {
    const history = new HistoryDb(":memory:");
    const ctx = await boot(1, 999, policy(), undefined, undefined, history);
    assert.equal((await fetch(`${ctx.base}/@acme%2Fwidget/-/widget-2.0.0.tgz`, { headers: { "npm-session": "new-session" } })).status, 200);
    const response = await ctx.retract();
    assert.equal(response.status, 403);
    assert.equal((await response.json()).window.cumulativeDownloads, 1_000);
    history.close();
  });

  test("a retraction decision mirrors a pre-existing history floor before rejecting", async () => {
    const history = new HistoryDb(":memory:");
    for (const npmSession of ["old-a", "old-b"]) {
      history.recordDownload({ name: "@acme/widget", version: "2.0.0", integrity: integrityOf(Buffer.from("tarball-2.0.0")),
        npmSession, servedAt: "2026-07-13T10:00:00.000Z" });
    }
    const ctx = await boot(1, 0, policy({ maxAgeHours: 72, maxDownloads: 2 }), undefined, undefined, history);
    assert.equal((await ctx.retract()).status, 403);
    assert.equal(ctx.privateStore.downloadCount("@acme/widget", "2.0.0"), 2);
    history.close();
  });

  test("the same signed-corpus version applies the same tombstone overlay on another instance", async () => {
    const origin = await boot(1, 0);
    assert.equal((await origin.retract("security")).status, 201);
    const advisory = origin.privateStore.retractionAdvisories()[0]!;
    const corpus: RetractionCorpus = {
      schema: 1, version: "fleet-2026-07-13", issuedAt: "2026-07-13T12:00:00.000Z", advisories: [advisory],
    };
    const fleet = await boot(1, 0, policy(), corpus);

    const packument = await (await fetch(`${fleet.base}/@acme%2Fwidget`)).json();
    assert.equal(packument.versions["2.0.0"], undefined);
    assert.equal(packument._sentinel.retractions["2.0.0"].advisoryId, advisory.id);
    assert.equal((await fetch(`${fleet.base}/@acme%2Fwidget/-/widget-2.0.0.tgz`)).status, 410);
    assert.equal((await fetch(`${fleet.base}/@acme%2Fwidget/-/widget-1.0.0.tgz`)).status, 200);

    const tree = await (await fetch(`${fleet.base}/-/audit-tree`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ packages: [{ name: "@acme/widget", version: "2.0.0" }] }),
    })).json();
    assert.deepEqual(tree.retractionCorpus, {
      version: corpus.version, hash: retractionCorpusHashOfBytes(Buffer.from(JSON.stringify(corpus))),
    });
    assert.equal(tree.packages[0].status, "block");
  });

  test("retraction is operator-only when role-token auth is enabled", async () => {
    const keys = generateKeypair();
    const ctx = await boot(1, 0, policy(), undefined, keys.publicKey);
    assert.equal((await ctx.retract()).status, 401);
    const agent = signToken({ role: "agent", sub: "test", ttlSeconds: 3_600 }, keys.privateKey);
    assert.equal((await ctx.retract("security", `Bearer ${agent}`)).status, 403);
    const operator = signToken({ role: "operator", sub: "test", ttlSeconds: 3_600 }, keys.privateKey);
    assert.equal((await ctx.retract("security", `Bearer ${operator}`)).status, 201);
  });
});
