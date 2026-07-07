import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type EnterprisePolicy, type AuditReport } from "@sentinel/core";
import { createServer, type ServerOptions } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

function boot(overrides: Partial<ServerOptions> = {}): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(), ...overrides,
  });
  return new Promise((res) => {
    const server = app.listen(0, () => res({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }));
  });
}

async function report(base: string, pkg: string, version: string): Promise<AuditReport> {
  const r = await fetch(`${base}/-/audit/${pkg}/${version}`);
  assert.equal(r.status, 200);
  return (await r.json()) as AuditReport;
}

describe("provenance deep-verify (e2e, offline, bundled trust root)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot()); });
  after(() => server?.close());

  test("vendored real package verifies end-to-end with identity", async () => {
    const r = await report(base, "sigstore", "3.0.0");
    assert.equal(r.meta.provenance, "verified");
    assert.equal(r.meta.provenanceIdentity?.sourceRepository, "https://github.com/sigstore/sigstore-js");
  });

  test("claimed-but-unfetchable is unknown", async () => {
    assert.equal((await report(base, "prov-unknown", "1.0.0")).meta.provenance, "unknown");
  });

  test("no claim is absent", async () => {
    assert.equal((await report(base, "leftpad-lite", "1.0.0")).meta.provenance, "absent");
  });

  test("real bundle over wrong bytes is invalid and hard-blocks", async () => {
    const r = await report(base, "prov-mismatch", "1.0.0");
    assert.equal(r.meta.provenance, "invalid");
    assert.equal(r.verdict, "block");
  });

  test("x-sentinel-provenance header is set on the tarball path", async () => {
    const res = await fetch(`${base}/sigstore/-/sigstore-3.0.0.tgz`);
    assert.equal(res.headers.get("x-sentinel-provenance"), "verified");
  });
});

describe("provenance identity gate (e2e, block mode)", () => {
  let server: Server; let base: string;
  before(async () => {
    ensureFixtures();
    const policy: EnterprisePolicy = {
      ...DEFAULT_POLICY,
      provenanceIdentities: [{ pattern: "sigstore", repository: "https://github.com/evil/*" }],
    };
    ({ server, base } = await boot({ enterprisePolicy: policy, policy: "block" }));
  });
  after(() => server?.close());

  test("verified-but-wrong-identity is blocked with the identity finding", async () => {
    const res = await fetch(`${base}/sigstore/-/sigstore-3.0.0.tgz`);
    assert.equal(res.status, 403);
    const body = (await res.json()) as { findings: { ruleId: string }[] };
    assert.ok(body.findings.some((f) => f.ruleId === "provenance-identity"));
  });
});

describe("identity gate positive + requireProvenance upgrade (e2e)", () => {
  let server: Server; let base: string;
  before(async () => {
    ensureFixtures();
    const policy: EnterprisePolicy = {
      ...DEFAULT_POLICY,
      provenanceIdentities: [{ pattern: "sigstore", repository: "https://github.com/sigstore/*" }],
      requireProvenance: ["prov-unknown"],
    };
    ({ server, base } = await boot({ enterprisePolicy: policy, policy: "block" }));
  });
  after(() => server?.close());

  test("matching identity is not blocked by the gate", async () => {
    const r = await report(base, "sigstore", "3.0.0");
    assert.equal(r.findings.find((f) => f.ruleId === "provenance-identity"), undefined);
    assert.notEqual(r.verdict, "block");
  });

  test("requireProvenance blocks an unknown-provenance package", async () => {
    const res = await fetch(`${base}/prov-unknown/-/prov-unknown-1.0.0.tgz`);
    assert.equal(res.status, 403);
  });
});

describe("served-bytes tamper detection (stub upstream)", () => {
  test("bytes differing from claimed integrity block critically", async () => {
    const inner = new LocalFixtureUpstream(FIXTURES);
    const tampering = {
      name: "tamper-stub",
      getPackument: (p: string) => inner.getPackument(p),
      getAttestations: async () => null,
      // Serve DIFFERENT bytes than the packument's claimed integrity.
      getTarball: async (p: string, v: string) => (await inner.getTarball("net-fetch-lite", "1.0.0")),
    };
    const { server, base } = await boot({ upstream: tampering, policy: "block" });
    try {
      const r = await fetch(`${base}/-/audit/leftpad-lite/1.0.0`);
      const rep = (await r.json()) as AuditReport;
      assert.equal(rep.verdict, "block");
      assert.ok(rep.findings.some((f) => f.ruleId === "integrity-mismatch"));
    } finally { server.close(); }
  });
});
