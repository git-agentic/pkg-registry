import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, test } from "node:test";
import { DEFAULT_POLICY, generateKeypair, integrityOf, runAudit, type ClaimCorpus, type ClaimStatus, type EnterprisePolicy, type TrustedPublisher } from "@git-agentic/sentinel-core";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ViolationStore } from "../src/violations.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(ROOT, "fixtures");
const CLAIMANT_KEY = generateKeypair().publicKey;
function ensure() { if (!existsSync(join(FIXTURES, "registry.json"))) execFileSync("npx", ["tsx", join(ROOT, "scripts/make-fixtures.ts")]); }

function corpus(namespace: string, status: ClaimStatus, trustedPublishers?: TrustedPublisher[]): ClaimCorpus {
  return { schema: 1, version: "2026.07.1", issuedAt: "2026-07-02T00:00:00.000Z", claims: [{
    namespace, domain: "sigstore.dev", claimantPublicKey: CLAIMANT_KEY, status,
    challenge: { method: "dns-txt", id: "claim-1", verifiedAt: "2026-07-01T00:00:00.000Z" },
    renewalDueAt: "2027-07-01T00:00:00.000Z", trustedPublishers,
  }] };
}

function payload(name: string, version: string, tarball: Buffer, bundle?: unknown): string {
  const data = tarball.toString("base64");
  const attachments: Record<string, unknown> = {
    [`${name}-${version}.tgz`]: { content_type: "application/octet-stream", data, length: tarball.length },
  };
  if (bundle) {
    const serialized = JSON.stringify(bundle);
    attachments[`${name}-${version}.sigstore`] = {
      content_type: "application/vnd.dev.sigstore.bundle+json;version=0.2", data: serialized, length: Buffer.byteLength(serialized),
    };
  }
  return JSON.stringify({ _id: name, name, "dist-tags": { latest: version },
    versions: { [version]: { name, version, dist: { integrity: integrityOf(tarball), tarball: "http://x" } } },
    _attachments: attachments });
}

const servers: Server[] = [];
afterEach(() => { while (servers.length) servers.pop()?.close(); });

async function boot(claimCorpus: ClaimCorpus, policy: EnterprisePolicy = { ...DEFAULT_POLICY, privateNamespaces: [] }, privateStore = new PrivatePackageStore()) {
  ensure();
  const app = createServer({ upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    privateStore, enterprisePolicy: policy, claimCorpus, claimCorpusHash: "sha256-test-corpus", publishTokens: ["tok"], policy: "block",
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore() });
  const server = await new Promise<Server>((resolve) => { const value = app.listen(0, () => resolve(value)); });
  servers.push(server);
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const put = (base: string, name: string, version: string, tarball: Buffer, bundle?: unknown) => fetch(`${base}/${encodeURIComponent(name)}`, {
  method: "PUT", headers: { "content-type": "application/json", authorization: "Bearer tok" }, body: payload(name, version, tarball, bundle),
});

describe("Phase 31 claim lifecycle", () => {
  test("a frozen claim remains authoritative and serves stored bytes, but rejects publish distinctly", async () => {
    ensure();
    const tarball = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
    const store = new PrivatePackageStore();
    const audit = await runAudit({ meta: { name: "leftpad-lite", version: "1.0.1", author: null, maintainers: [], license: null,
      hasInstallScripts: false, signature: "unsigned", provenance: "absent", integrity: integrityOf(tarball) }, tarball });
    store.put({ name: "leftpad-lite", version: "1.0.1", integrity: integrityOf(tarball), manifest: { name: "leftpad-lite", version: "1.0.1" }, tarball, audit, actor: "seed" });
    const base = await boot(corpus("leftpad-lite", "frozen"), undefined, store);

    const served = await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.1.tgz`);
    assert.equal(served.status, 200);
    assert.deepEqual(Buffer.from(await served.arrayBuffer()), tarball);
    const rejected = await put(base, "leftpad-lite", "1.0.2", tarball);
    assert.equal(rejected.status, 423);
    assert.equal((await rejected.json()).code, "claim-frozen");
    const report = await (await fetch(`${base}/-/audit/leftpad-lite/1.0.1`)).json();
    assert.deepEqual(report.policy.claimCorpus, { version: "2026.07.1", hash: "sha256-test-corpus" });
  });

  test("a disputed claim rejects publish while a policy-private override beats that claim", async () => {
    const tarball = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
    const claims = corpus("leftpad-lite", "disputed");
    const denied = await boot(claims);
    assert.equal((await put(denied, "leftpad-lite", "1.0.1", tarball)).status, 423);

    const overridden = await boot(claims, { ...DEFAULT_POLICY, privateNamespaces: ["leftpad-lite"] });
    assert.equal((await put(overridden, "leftpad-lite", "1.0.1", tarball)).status, 201);
  });

  test("trusted-publisher claims reject unattested publishes and accept a matching verified SLSA identity", async () => {
    ensure();
    const tarball = readFileSync(join(FIXTURES, ".tarballs", "sigstore-3.0.0.tgz"));
    const attestationDoc = JSON.parse(readFileSync(join(FIXTURES, "attestations", "sigstore-3.0.0.attestations.json"), "utf8"));
    const slsaBundle = attestationDoc.attestations.find((entry: { predicateType: string }) => entry.predicateType === "https://slsa.dev/provenance/v1").bundle;
    const base = await boot(corpus("sigstore", "active", [{
      issuer: "https://token.actions.githubusercontent.com", repository: "https://github.com/sigstore/sigstore-js",
    }]));

    const unattested = await put(base, "sigstore", "3.0.0", tarball);
    assert.equal(unattested.status, 403);
    assert.equal((await unattested.json()).code, "trusted-publisher-required");
    const attested = await put(base, "sigstore", "3.0.0", tarball, slsaBundle);
    assert.equal(attested.status, 201, await attested.text());
  });
});
