import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createSign, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, describe, test } from "node:test";
import { AUDIT_REVISION, DEFAULT_POLICY, ENGINE_VERSION, integrityOf, runAudit, type AuditReport, type EnterprisePolicy } from "@git-agentic/sentinel-core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import { LocalFixtureUpstream, type Upstream } from "../src/upstream.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "fixtures");

function report(name: string, integrity: string, engineVersion?: string, revision: number | null = AUDIT_REVISION): AuditReport {
  return {
    schema: 3, meta: { name, version: "1.0.0", integrity }, verdict: "allow", score: 100, findings: [],
    policy: { version: "t", hash: "h" },
    ...(engineVersion ? { engine: { version: engineVersion, rules: [], mode: "full", ...(revision !== null ? { revision } : {}) } } : {}),
  } as unknown as AuditReport;
}

describe("AuditStore load skips reports from another engine version", () => {
  test("a persisted report from an older engine is not served after upgrade", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-engine-"));
    const file = join(dir, "audits.json");
    const rows = [
      { name: "old", r: report("old", "sha512-old", "0.0.1-ancient") },
      { name: "cur", r: report("cur", "sha512-cur", ENGINE_VERSION) },
      { name: "none", r: report("none", "sha512-none") },
      // Same engine version, but no audit revision: rule semantics may have changed under it.
      { name: "norev", r: report("norev", "sha512-norev", ENGINE_VERSION, null) },
      { name: "oldrev", r: report("oldrev", "sha512-oldrev", ENGINE_VERSION, AUDIT_REVISION - 1) },
    ].map(({ name, r }) => ({ key: `${name}@1.0.0`, name, version: "1.0.0", report: r }));
    writeFileSync(file, JSON.stringify(rows));
    const store = new AuditStore(file);
    assert.equal(store.get("old", "1.0.0", "sha512-old"), undefined);
    assert.equal(store.get("none", "1.0.0", "sha512-none"), undefined);
    assert.equal(store.get("norev", "1.0.0", "sha512-norev"), undefined, "a missing revision counts as stale");
    assert.equal(store.get("oldrev", "1.0.0", "sha512-oldrev"), undefined, "an older revision counts as stale");
    assert.ok(store.get("cur", "1.0.0", "sha512-cur"));
  });
});

describe("AuditStore persistence is debounced", () => {
  test("many puts coalesce into one deferred write; flush() writes immediately", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-debounce-"));
    const file = join(dir, "audits.json");
    const store = new AuditStore(file);
    for (let i = 0; i < 50; i++) store.put(report(`p${i}`, `sha512-${i}`, ENGINE_VERSION));
    assert.equal(existsSync(file), false, "put must not write synchronously");
    store.flush();
    assert.equal(JSON.parse(readFileSync(file, "utf8")).length, 50);
    store.put(report("late", "sha512-late", ENGINE_VERSION));
    await new Promise((r) => setTimeout(r, 1200));
    const rows = JSON.parse(readFileSync(file, "utf8")) as unknown[];
    assert.equal(rows.length, 51, "the pending write lands on its own");
  });

  test("the timer is unref'd and a restart reloads flushed audits", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-debounce-"));
    const file = join(dir, "audits.json");
    const store = new AuditStore(file);
    store.put(report("keep", "sha512-keep", ENGINE_VERSION));
    store.flush();
    assert.ok(new AuditStore(file).get("keep", "1.0.0", "sha512-keep"));
  });
});

describe("native serve path re-audits stored bytes after an engine upgrade", () => {
  const servers: Server[] = [];
  after(() => servers.forEach((s) => s.close()));
  const policy: EnterprisePolicy = { ...DEFAULT_POLICY, privateNamespaces: ["@acme/*"] };
  const upstream: Upstream = {
    name: "must-not-be-called",
    async getPackument() { throw new Error("native names must not reach upstream"); },
    async getTarball() { throw new Error("native names must not reach upstream"); },
    async getAttestations() { throw new Error("native names must not reach upstream"); },
  };

  test("a stale clean audit of malicious bytes is recomputed, the record is untouched, upstream is never called", async () => {
    const tarball = readFileSync(join(FIXTURES, ".tarballs", "color-stream-1.4.1.tgz"));
    const integrity = integrityOf(tarball);
    const fresh = await runAudit({ meta: { name: "@acme/widget", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity }, tarball });
    assert.ok(fresh.findings.length > 0, "fixture must produce findings under the current engine");
    const stale = { ...fresh, findings: [], capabilities: [], engine: { ...fresh.engine, version: "0.0.1-ancient" } };
    assert.equal(fresh.engine.revision, AUDIT_REVISION);
    const privateStore = new PrivatePackageStore();
    privateStore.publish({ name: "@acme/widget", version: "1.0.0", integrity, tarball, manifest: { name: "@acme/widget", version: "1.0.0", dist: { integrity } }, audit: stale, actor: "t" });
    const app = createServer({ upstream, store: new AuditStore(), approvals: new ApprovalStore(), privateStore, enterprisePolicy: policy,
      violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore() });
    const server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
    servers.push(server);
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (let i = 0; i < 2; i++) {
      const body = (await (await fetch(`${base}/-/audit/@acme%2fwidget/1.0.0`)).json()) as AuditReport;
      assert.equal(body.engine.version, ENGINE_VERSION);
      assert.ok(body.findings.length > 0, "stale empty findings must not be served");
    }
    assert.equal(privateStore.getAudit("@acme/widget", "1.0.0")!.engine.version, "0.0.1-ancient", "the publication record is never rewritten");
  });

  test("a current-engine audit is served as stored (no re-run)", async () => {
    const tarball = Buffer.from("not-a-tarball-so-a-rerun-would-throw");
    const integrity = integrityOf(tarball);
    const audit = { schema: 3 as const, meta: { name: "@acme/w2", version: "1.0.0", integrity, author: null, maintainers: [], license: null, hasInstallScripts: false, signature: "unsigned" as const, provenance: "absent" as const, unpackedSize: 1, fileCount: 1 },
      findings: [], capabilities: [], capabilityDelta: null, engine: { version: ENGINE_VERSION, revision: AUDIT_REVISION, rules: [], mode: "full" as const }, auditedAt: "2026-07-13T00:00:00.000Z", durationMs: 1 };
    const privateStore = new PrivatePackageStore();
    privateStore.publish({ name: "@acme/w2", version: "1.0.0", integrity, tarball, manifest: { name: "@acme/w2", version: "1.0.0", dist: { integrity } }, audit, actor: "t" });
    const app = createServer({ upstream, store: new AuditStore(), approvals: new ApprovalStore(), privateStore, enterprisePolicy: policy,
      violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore() });
    const server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
    servers.push(server);
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    assert.equal((await fetch(`${base}/-/audit/@acme%2fw2/1.0.0`)).status, 200);
  });

  const mkServer = async (privateStore: PrivatePackageStore, extra: Partial<Parameters<typeof createServer>[0]> = {}) => {
    const app = createServer({ upstream, store: new AuditStore(), approvals: new ApprovalStore(), privateStore, enterprisePolicy: policy,
      violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(), ...extra });
    const server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
    servers.push(server);
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  };

  test("a stored audit at the current version but with no revision is re-audited", async () => {
    const tarball = readFileSync(join(FIXTURES, ".tarballs", "color-stream-1.4.1.tgz"));
    const integrity = integrityOf(tarball);
    const fresh = await runAudit({ meta: { name: "@acme/norev", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity }, tarball });
    const { revision: _r, ...engine } = fresh.engine;
    const stale = { ...fresh, findings: [], capabilities: [], engine };
    const privateStore = new PrivatePackageStore();
    privateStore.publish({ name: "@acme/norev", version: "1.0.0", integrity, tarball, manifest: { name: "@acme/norev", version: "1.0.0", dist: { integrity } }, audit: stale, actor: "t" });
    const base = await mkServer(privateStore);
    const body = (await (await fetch(`${base}/-/audit/@acme%2fnorev/1.0.0`)).json()) as AuditReport;
    assert.ok(body.findings.length > 0, "the revision-less audit must be recomputed");
    assert.equal(body.engine.revision, AUDIT_REVISION);
  });

  const signedFixture = async (name: string, actor: string) => {
    const tarball = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.0.tgz"));
    const integrity = integrityOf(tarball);
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const sig = createSign("sha256").update(`${name}@1.0.0:${integrity}`).sign(privateKey, "base64");
    const signingKeys = [{ keyid: "test-key", spkiPem: publicKey.export({ type: "spki", format: "pem" }).toString(), expires: null }];
    const stale = await runAudit({ meta: { name, version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity }, tarball, signatures: null, signingKeys });
    const { revision: _r, ...engine } = stale.engine;
    const privateStore = new PrivatePackageStore();
    privateStore.publish({ name, version: "1.0.0", integrity, tarball, actor, audit: { ...stale, engine },
      manifest: { name, version: "1.0.0", dist: { integrity, signatures: [{ keyid: "test-key", sig }] } } });
    const base = await mkServer(privateStore, { signingKeys, enterprisePolicy: { ...policy, requireSignature: ["@acme/*"] } });
    return (await (await fetch(`${base}/-/audit/${encodeURIComponent(name)}/1.0.0`)).json()) as AuditReport;
  };

  test("re-audit keeps the retained registry signatures of an IMPORTED version (still satisfies requireSignature)", async () => {
    const body = await signedFixture("@acme/signed", "imported");
    assert.equal(body.engine.revision, AUDIT_REVISION, "must have been re-audited");
    assert.equal(body.meta.signature, "verified");
    assert.equal(body.verdict, "allow");
  });

  test("a PUBLISHER-published version never gets signatures from its publisher-controlled manifest", async () => {
    const body = await signedFixture("@acme/planted", "publisher");
    assert.equal(body.engine.revision, AUDIT_REVISION, "must have been re-audited");
    assert.equal(body.meta.signature, "unsigned", "a planted dist.signatures must not verify");
    assert.notEqual(body.verdict, "allow", "requireSignature still fails for the publisher version");
  });

  describe("re-audit keeps import provenance (review round 3, item 3)", () => {
    const claim = (name: string) => ({ schema: 1 as const, version: "prov", issuedAt: "2026-07-13T00:00:00.000Z", claims: [{
      namespace: name, domain: "example.test", claimantPublicKey: generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString(), status: "active" as const,
      challenge: { method: "dns-txt" as const, id: "c", verifiedAt: "2026-07-12T00:00:00.000Z" }, renewalDueAt: "2027-07-12T00:00:00.000Z" }] });
    const reqProv: EnterprisePolicy = { ...DEFAULT_POLICY, privateNamespaces: [], requireProvenance: ["sigstore"] };
    const fixtureUpstream = new LocalFixtureUpstream(FIXTURES);
    const stale = (store: PrivatePackageStore) => { delete (store.getVersion("sigstore", "3.0.0")!.audit.engine as { revision?: number }).revision; };
    const get = async (base: string) => (await (await fetch(`${base}/-/audit/sigstore/3.0.0`)).json()) as AuditReport;

    test("(a) history import stores the attestations, so a re-audit still verifies provenance under requireProvenance", async () => {
      const privateStore = new PrivatePackageStore();
      const base = await mkServer(privateStore, { upstream: fixtureUpstream, enterprisePolicy: reqProv, claimCorpus: claim("sigstore"), publishTokens: ["tok"] });
      const imp = await fetch(`${base}/-/registry/import`, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer tok" }, body: JSON.stringify({ name: "sigstore" }) });
      assert.equal(imp.status, 201, await imp.clone().text());
      assert.ok(privateStore.getAttestations("sigstore", "3.0.0"), "the verified bundle is stored with the publication");
      stale(privateStore);
      const r = await get(base);
      assert.equal(r.engine.revision, AUDIT_REVISION, "must have been re-audited");
      assert.equal(r.meta.provenance, "verified");
      assert.notEqual(r.verdict, "block");
    });

    test("(b) a legacy imported version with no stored bundle keeps its verified provenance and identity", async () => {
      const tarball = await fixtureUpstream.getTarball("sigstore", "3.0.0");
      const attestations = await fixtureUpstream.getAttestations("sigstore", "3.0.0");
      const integrity = integrityOf(tarball);
      const original = await runAudit({ meta: { name: "sigstore", version: "3.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity }, tarball, hasProvenance: true, attestations });
      assert.equal(original.meta.provenance, "verified");
      const privateStore = new PrivatePackageStore();
      privateStore.publish({ name: "sigstore", version: "3.0.0", integrity, tarball, actor: "imported", audit: original, manifest: { name: "sigstore", version: "3.0.0", dist: { integrity } } });
      assert.equal(privateStore.getAttestations("sigstore", "3.0.0"), undefined);
      // Stale by engine VERSION only: this audit already carries a certificate-sourced identity (revision 2), so it is kept.
      (privateStore.getVersion("sigstore", "3.0.0")!.audit.engine as { version: string }).version = "0.0.1-ancient";
      const base = await mkServer(privateStore, { upstream, enterprisePolicy: reqProv, claimCorpus: claim("sigstore") });
      const r = await get(base);
      assert.equal(r.engine.revision, AUDIT_REVISION);
      assert.equal(r.meta.provenance, "verified");
      assert.equal(r.meta.provenanceIdentity?.sourceRepository, "https://github.com/sigstore/sigstore-js");
      assert.notEqual(r.verdict, "block");
    });

    const original = async () => {
      const tarball = await fixtureUpstream.getTarball("sigstore", "3.0.0");
      const integrity = integrityOf(tarball);
      const audit = await runAudit({ meta: { name: "sigstore", version: "3.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity }, tarball, hasProvenance: true, attestations: await fixtureUpstream.getAttestations("sigstore", "3.0.0") });
      return { tarball, integrity, audit };
    };
    const publishLegacy = (store: PrivatePackageStore, o: Awaited<ReturnType<typeof original>>, audit = o.audit, tarball = o.tarball) =>
      store.publish({ name: "sigstore", version: "3.0.0", integrity: integrityOf(tarball), tarball, actor: "imported", audit, manifest: { name: "sigstore", version: "3.0.0", dist: {} } });

    test("(round 4, item 2) a pre-hardening import's predicate-sourced repository and ref are not carried over", async () => {
      const o = await original();
      // Pre-hardening metadata built by hand: predicate repository/ref set, no engine.revision.
      const legacy = structuredClone(o.audit);
      legacy.meta.provenanceIdentity = { ...legacy.meta.provenanceIdentity!, sourceRepository: "https://github.com/acme/lib", ref: "refs/heads/forged" };
      delete (legacy.engine as { revision?: number }).revision;
      const privateStore = new PrivatePackageStore();
      publishLegacy(privateStore, o, legacy);
      const enterprisePolicy = { ...reqProv, provenanceIdentities: [{ pattern: "sigstore", repository: "https://github.com/acme/*" }] };
      const base = await mkServer(privateStore, { upstream, enterprisePolicy, claimCorpus: claim("sigstore") });
      const r = await get(base);
      assert.equal(r.meta.provenance, "verified");
      assert.equal(r.meta.provenanceIdentity?.sourceRepository, null);
      assert.equal(r.meta.provenanceIdentity?.ref, null);
      assert.equal(r.meta.provenanceIdentity?.workflow, o.audit.meta.provenanceIdentity?.workflow, "the certificate-sourced workflow is kept");
      assert.equal(r.meta.provenanceIdentity?.issuer, o.audit.meta.provenanceIdentity?.issuer);
      assert.equal(r.verdict, "block", "a repository-only policy requirement must not be met without certificate evidence");
    });

    test("(round 4, item 3) legacy metadata paired with DIFFERENT bytes does not inherit verified provenance", async () => {
      const o = await original();
      const other = await fixtureUpstream.getTarball("leftpad-lite", "1.0.0");
      const legacy = structuredClone(o.audit);
      delete (legacy.engine as { revision?: number }).revision;
      const privateStore = new PrivatePackageStore();
      publishLegacy(privateStore, o, legacy, other); // stored audit.meta.integrity is the sigstore bytes, the tarball is not
      const base = await mkServer(privateStore, { upstream, enterprisePolicy: reqProv, claimCorpus: claim("sigstore") });
      const r = await get(base);
      assert.equal(r.meta.provenance, "absent");
      assert.equal(r.meta.provenanceIdentity ?? null, null);
    });

    test("a publisher-actor version never inherits a stored provenance claim without a bundle", async () => {
      const tarball = await fixtureUpstream.getTarball("sigstore", "3.0.0");
      const integrity = integrityOf(tarball);
      const original = await runAudit({ meta: { name: "sigstore", version: "3.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity }, tarball, hasProvenance: true, attestations: await fixtureUpstream.getAttestations("sigstore", "3.0.0") });
      const privateStore = new PrivatePackageStore();
      privateStore.publish({ name: "sigstore", version: "3.0.0", integrity, tarball, actor: "publisher", audit: original, manifest: { name: "sigstore", version: "3.0.0", dist: { integrity } } });
      stale(privateStore);
      const base = await mkServer(privateStore, { upstream, enterprisePolicy: reqProv, claimCorpus: claim("sigstore") });
      assert.equal((await get(base)).meta.provenance, "absent");
    });
  });
});
