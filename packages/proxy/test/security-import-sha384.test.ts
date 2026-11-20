import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, describe, test } from "node:test";
import { DEFAULT_POLICY, generateKeypair, integrityOfAlgo, type ClaimCorpus } from "@git-agentic/sentinel-core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import { LocalFixtureUpstream, type Upstream } from "../src/upstream.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "fixtures");
const servers: Server[] = [];
after(() => servers.forEach((s) => s.close()));

async function importWith(declare: (bytes: Buffer) => string): Promise<{ status: number }> {
  const fixture = new LocalFixtureUpstream(FIXTURES);
  const bytes = await fixture.getTarball("leftpad-lite", "1.0.1");
  const upstream: Upstream = {
    name: "declared-integrity",
    async getPackument(name) {
      const packument = structuredClone(await fixture.getPackument(name));
      packument.doc.versions["1.0.1"]!.dist.integrity = declare(bytes);
      return packument;
    },
    getTarball: (name, version) => fixture.getTarball(name, version),
    getAttestations: (name, version) => fixture.getAttestations(name, version),
  };
  const claimCorpus: ClaimCorpus = { schema: 1, version: "c", issuedAt: "2026-07-13T00:00:00.000Z", claims: [{
    namespace: "leftpad-lite", domain: "example.test", claimantPublicKey: generateKeypair().publicKey, status: "active",
    challenge: { method: "dns-txt", id: "c", verifiedAt: "2026-07-12T00:00:00.000Z" }, renewalDueAt: "2027-07-12T00:00:00.000Z" }] };
  const app = createServer({ upstream, store: new AuditStore(), approvals: new ApprovalStore(), privateStore: new PrivatePackageStore(),
    enterprisePolicy: { ...DEFAULT_POLICY, privateNamespaces: [] }, claimCorpus, publishTokens: ["tok"],
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore() });
  const server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
  servers.push(server);
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const res = await fetch(`${base}/-/registry/import`, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer tok" }, body: JSON.stringify({ name: "leftpad-lite" }) });
  return { status: res.status };
}

describe("history import verifies every supported declared integrity algorithm (round 5, item 2)", () => {
  test("a sha384-only upstream dist.integrity imports", async () => {
    assert.equal((await importWith((b) => integrityOfAlgo(b, "sha384"))).status, 201);
  });
  test("a wrong sha384 is still refused", async () => {
    assert.equal((await importWith(() => "sha384-" + Buffer.alloc(48, 4).toString("base64"))).status, 400);
  });
});
