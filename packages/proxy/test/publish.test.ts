import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { gzipSync } from "node:zlib";
import { c as createTar, r as replaceTar, x as extractTar } from "tar";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import type { ClaimCorpus } from "../src/resolution.js";
import { DEFAULT_POLICY, generateKeypair, integrityOf, type EnterprisePolicy } from "@git-agentic/sentinel-core";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "..", "..", "fixtures");
function ensure() { if (!existsSync(join(FIXTURES, "registry.json")) || !existsSync(join(FIXTURES, ".tarballs")))
  execFileSync("npx", ["tsx", join(HERE, "..", "..", "..", "scripts", "make-fixtures.ts")], { stdio: "ignore" }); }

const policy = (ns: string[]): EnterprisePolicy => ({ ...DEFAULT_POLICY, privateNamespaces: ns });
const CLAIMANT_KEY = generateKeypair().publicKey;

function verifiedCorpus(namespaces: string[]): ClaimCorpus {
  return { schema: 1, version: "test", issuedAt: "2026-07-02T00:00:00.000Z", claims: namespaces.map((namespace, i) => ({
    namespace, domain: `claim${i}.example`, claimantPublicKey: CLAIMANT_KEY, status: "active",
    challenge: { method: "dns-txt", id: `c-${i}`, verifiedAt: "2026-07-01T00:00:00.000Z" },
    renewalDueAt: "2027-07-01T00:00:00.000Z",
  })) };
}

function bindPackageIdentity(tgz: Buffer, name: string, version: string): Buffer {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-publish-identity-"));
  const extracted = join(dir, "extracted");
  const input = join(dir, "input.tgz");
  const output = join(dir, "output.tgz");
  try {
    mkdirSync(extracted);
    writeFileSync(input, tgz);
    extractTar({ cwd: extracted, file: input, sync: true });
    const manifestPath = join(extracted, "package", "package.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    writeFileSync(manifestPath, JSON.stringify({ ...manifest, name, version }));
    createTar({ cwd: extracted, file: output, gzip: true, sync: true }, ["package"]);
    return readFileSync(output);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function duplicateManifestTarball(name: string, version: string): Buffer {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-publish-duplicate-manifest-"));
  const manifestPath = join(dir, "package", "package.json");
  const archive = join(dir, "package.tar");
  try {
    mkdirSync(dirname(manifestPath), { recursive: true });
    writeFileSync(manifestPath, JSON.stringify({ name, version }));
    createTar({ cwd: dir, file: archive, sync: true }, ["package/package.json"]);
    writeFileSync(manifestPath, JSON.stringify({ name: "attacker-decoy", version: "9.9.9" }));
    replaceTar({ cwd: dir, file: archive, sync: true }, ["package/package.json"]);
    return gzipSync(readFileSync(archive));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// A fixture tarball, rebound to the coordinate carried by an npm publish payload.
function publishPayload(name: string, version: string, tgz: Buffer, bindIdentity = true) {
  if (bindIdentity) {
    try { tgz = bindPackageIdentity(tgz, name, version); }
    catch { /* Preserve malformed input so the HTTP boundary can reject it. */ }
  }
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
      violations: new ViolationStore(),
      approvalRequests: new ApprovalRequestStore(),
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
    assert.ok((priv.getTarball("@acme/widget", "1.0.0")?.length ?? 0) > 0);
  });

  test("409 on a duplicate version", async () => {
    const res = await put("@acme/widget", publishPayload("@acme/widget", "1.0.0", benign()), { authorization: "Bearer tok-1" });
    assert.equal(res.status, 409);
  });

  test("403 publish is rejected when the audit verdict is block", async () => {
    const res = await put("@acme/evil", publishPayload("@acme/evil", "1.0.0", malicious()), { authorization: "Bearer tok-1" });
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.match(body.error, /block/i);
    assert.equal(body.report.schema, 3, "rejection carries the complete AuditReport");
    assert.equal(body.report.verdict, "block");
    assert.ok(Array.isArray(body.report.capabilities));
    assert.ok(body.report.policy.hash);
    assert.equal(priv.has("@acme/evil"), false); // not stored
  });

  test("400 on a declared-integrity mismatch", async () => {
    const body = JSON.parse(publishPayload("@acme/mismatch", "1.0.0", benign()));
    body.versions["1.0.0"].dist.integrity = "sha512-deadbeef";
    const res = await put("@acme/mismatch", JSON.stringify(body), { authorization: "Bearer tok-1" });
    assert.equal(res.status, 400);
  });

  test("400 when the tarball manifest identity differs from the publish target", async () => {
    const res = await put(
      "@acme/tarball-mismatch",
      publishPayload("@acme/tarball-mismatch", "1.0.0", benign(), false),
      { authorization: "Bearer tok-1" },
    );
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /does not match publish target/);
    assert.equal(priv.has("@acme/tarball-mismatch"), false);
  });

  test("400 when the tarball contains duplicate package manifests", async () => {
    const name = "@acme/duplicate-manifest";
    const version = "1.0.0";
    const res = await put(
      name,
      publishPayload(name, version, duplicateManifestTarball(name, version), false),
      { authorization: "Bearer tok-1" },
    );
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /duplicate package\/package\.json/);
    assert.equal(priv.has(name), false);
  });
});

describe("Phase 30 authoritative publish path", () => {
  const benign = () => readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
  const malicious = () => readFileSync(join(FIXTURES, ".tarballs", "color-stream-1.4.1.tgz"));

  async function boot(opts: {
    enterprisePolicy?: EnterprisePolicy;
    claimCorpus?: ClaimCorpus;
    privateStore?: PrivatePackageStore;
    maxPublishBytes?: number;
    extractLimits?: { maxUnpackedBytes?: number; maxFileCount?: number };
    publishAudit?: Parameters<typeof createServer>[0]["publishAudit"];
    publishRateLimit?: { limit: number; windowMs: number };
  } = {}) {
    ensure();
    const privateStore = opts.privateStore ?? new PrivatePackageStore();
    const store = new AuditStore();
    const serverOptions = {
      upstream: new LocalFixtureUpstream(FIXTURES), store,
      approvals: new ApprovalStore(), privateStore,
      enterprisePolicy: opts.enterprisePolicy ?? policy(["@acme/*"]),
      claimCorpus: opts.claimCorpus, publishTokens: ["tok-1"], policy: "block",
      violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(),
      maxPublishBytes: opts.maxPublishBytes, extractLimits: opts.extractLimits,
      publishAudit: opts.publishAudit,
      publishRateLimit: opts.publishRateLimit,
    };
    const app = createServer(serverOptions);
    const server = await new Promise<Server>((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const put = (name: string, version: string, tgz = benign(), bindIdentity = true) => fetch(`${base}/${encodeURIComponent(name)}`, {
      method: "PUT", headers: { "content-type": "application/json", authorization: "Bearer tok-1" },
      body: publishPayload(name, version, tgz, bindIdentity),
    });
    return { server, base, privateStore, store, put };
  }

  test("unclaimed publish returns 403 with zero storage or audit side effects", async () => {
    const ctx = await boot({ enterprisePolicy: policy([]), claimCorpus: verifiedCorpus([]) });
    try {
      const res = await ctx.put("unclaimed", "1.0.0");
      assert.equal(res.status, 403);
      assert.equal(ctx.privateStore.has("unclaimed"), false);
      assert.equal(ctx.store.stats().total, 0);
    } finally { ctx.server.close(); }
  });

  test("empty claim corpus still permits policy-private publishing", async () => {
    const ctx = await boot({ claimCorpus: verifiedCorpus([]) });
    try {
      assert.equal((await ctx.put("@acme/empty-corpus", "1.0.0")).status, 201);
      assert.equal(ctx.privateStore.has("@acme/empty-corpus"), true);
    } finally { ctx.server.close(); }
  });

  test("a supplied verified claim permits native publishing", async () => {
    const ctx = await boot({ enterprisePolicy: policy([]), claimCorpus: verifiedCorpus(["claimed-name"]) });
    try {
      assert.equal((await ctx.put("claimed-name", "1.0.0")).status, 201);
      assert.equal(ctx.privateStore.has("claimed-name"), true);
      assert.deepEqual(ctx.privateStore.getVersion("claimed-name", "1.0.0")?.claimAtPublication, {
        namespace: "claimed-name", domain: "claim0.example", claimantPublicKey: CLAIMANT_KEY,
      });
    } finally { ctx.server.close(); }
  });

  test("publish is rate-limited even when the optional general limiter is absent", async () => {
    const ctx = await boot({ enterprisePolicy: policy([]), claimCorpus: verifiedCorpus(["rate-limited"]),
      publishRateLimit: { limit: 1, windowMs: 60_000 } });
    try {
      assert.equal((await ctx.put("rate-limited", "1.0.0")).status, 201);
      const limited = await ctx.put("rate-limited", "1.0.1");
      assert.equal(limited.status, 429);
      assert.ok(Number(limited.headers.get("retry-after")) >= 1);
    } finally { ctx.server.close(); }
  });

  test("publishGate outcomes cover allow, warn, and block reports", async () => {
    const cases: Array<{ name: string; policy: EnterprisePolicy; tarball: Buffer; verdict: string; status: number }> = [
      { name: "allow", policy: { ...policy(["@acme/*"]), publishGate: "block" }, tarball: benign(), verdict: "allow", status: 201 },
      { name: "warn", policy: { ...policy(["@acme/*"]), publishGate: "warn", scoring: { ...DEFAULT_POLICY.scoring, thresholds: { allow: 97, warn: 50 } } }, tarball: benign(), verdict: "warn", status: 403 },
      { name: "block", policy: { ...policy(["@acme/*"]), publishGate: "block" }, tarball: malicious(), verdict: "block", status: 403 },
    ];
    for (const c of cases) {
      const ctx = await boot({ enterprisePolicy: c.policy });
      try {
        const res = await ctx.put(`@acme/${c.name}`, "1.0.0", c.tarball);
        assert.equal(res.status, c.status, c.name);
        if (res.status === 403) {
          const body = await res.json();
          assert.equal(body.report.verdict, c.verdict);
        }
      } finally { ctx.server.close(); }
    }
  });

  test("publishGate=allow rejects even an allow verdict with the full report", async () => {
    const ctx = await boot({ enterprisePolicy: { ...policy(["@acme/*"]), publishGate: "allow" } });
    try {
      const res = await ctx.put("@acme/strict", "1.0.0");
      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.report.verdict, "allow");
      assert.deepEqual(Object.keys(body.report).sort(), [
        "auditedAt", "capabilities", "capabilityDelta", "durationMs", "engine", "findings",
        "llmSummary", "meta", "policy", "schema", "score", "verdict",
      ]);
    } finally { ctx.server.close(); }
  });

  test("identical publication inputs produce the same outcome and verdict", async () => {
    const enterprisePolicy = { ...policy(["@acme/*"]), publishGate: "allow" as const };
    const name = "@acme/repeat";
    const version = "1.0.0";
    const tarball = bindPackageIdentity(benign(), name, version);
    const aCtx = await boot({ enterprisePolicy });
    const bCtx = await boot({ enterprisePolicy });
    try {
      const aRes = await aCtx.put(name, version, tarball, false);
      const bRes = await bCtx.put(name, version, tarball, false);
      assert.equal(aRes.status, bRes.status);
      const a = await aRes.json();
      const b = await bRes.json();
      assert.equal(a.report.verdict, b.report.verdict);
      assert.equal(a.report.score, b.report.score);
      assert.equal(a.error, b.error);
    } finally {
      aCtx.server.close();
      bCtx.server.close();
    }
  });

  test("malformed tarball and extraction-over-limit tarball both fail closed", async () => {
    const malformed = await boot();
    try {
      const res = await malformed.put("@acme/malformed", "1.0.0", Buffer.from("not a tarball"));
      assert.ok(res.status >= 400);
      assert.equal(malformed.privateStore.has("@acme/malformed"), false);
    } finally { malformed.server.close(); }

    const limited = await boot({ extractLimits: { maxUnpackedBytes: 1, maxFileCount: 1 } });
    try {
      const res = await limited.put("@acme/over-limit", "1.0.0");
      assert.equal(res.status, 403);
      assert.equal((await res.json()).report.verdict, "block");
      assert.equal(limited.privateStore.has("@acme/over-limit"), false);
    } finally { limited.server.close(); }
  });

  test("request body cap rejects before publication", async () => {
    const ctx = await boot({ maxPublishBytes: 512 });
    try {
      const res = await ctx.put("@acme/body-limit", "1.0.0");
      assert.equal(res.status, 413);
      assert.equal(ctx.privateStore.has("@acme/body-limit"), false);
    } finally { ctx.server.close(); }
  });

  test("failed atomic persistence never becomes visible", async () => {
    const ctx = await boot({ privateStore: new PrivatePackageStore("/dev/null/sentinel-publish") });
    try {
      const res = await ctx.put("@acme/io-failure", "1.0.0");
      assert.equal(res.status, 500);
      assert.equal(ctx.privateStore.has("@acme/io-failure"), false);
      assert.equal((await fetch(`${ctx.base}/@acme%2fio-failure`)).status, 404);
    } finally { ctx.server.close(); }
  });

  test("scanner failure or timeout error fails closed with no publication", async () => {
    const ctx = await boot({ publishAudit: async () => { throw new Error("scanner timeout"); } });
    try {
      const res = await ctx.put("@acme/scanner-failure", "1.0.0");
      assert.equal(res.status, 500);
      assert.equal(ctx.privateStore.has("@acme/scanner-failure"), false);
      assert.equal(ctx.store.stats().total, 0);
    } finally { ctx.server.close(); }
  });

  test("concurrent publication cannot replace a version or lose sibling versions", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-publish-race-"));
    const ctx = await boot({ privateStore: new PrivatePackageStore(dir) });
    try {
      const same = await Promise.all([ctx.put("@acme/race", "1.0.0"), ctx.put("@acme/race", "1.0.0")]);
      assert.deepEqual(same.map((r) => r.status).sort(), [201, 409]);
      const siblings = await Promise.all(["1.0.1", "1.0.2", "1.0.3"].map((v) => ctx.put("@acme/race", v)));
      assert.deepEqual(siblings.map((r) => r.status), [201, 201, 201]);
      assert.deepEqual(ctx.privateStore.versions("@acme/race").sort(), ["1.0.0", "1.0.1", "1.0.2", "1.0.3"]);
      assert.deepEqual(new PrivatePackageStore(dir).versions("@acme/race").sort(), ["1.0.0", "1.0.1", "1.0.2", "1.0.3"]);
    } finally { ctx.server.close(); }
  });

  test("a retracted identifier can never be republished", async () => {
    const ctx = await boot();
    try {
      assert.equal((await ctx.put("@acme/spent", "1.0.0")).status, 201);
      ctx.privateStore.retract({ name: "@acme/spent", version: "1.0.0", reason: "broken",
        retractedAt: "2026-07-13T12:00:00.000Z", advisoryId: "SENTINEL-RETRACT-spent" });
      const replacement = await ctx.put("@acme/spent", "1.0.0");
      assert.equal(replacement.status, 409);
      assert.match((await replacement.json()).error, /permanently spent/i);
    } finally { ctx.server.close(); }
  });
});
