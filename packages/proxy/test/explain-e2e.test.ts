import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, runAudit, integrityOf, type EnterprisePolicy } from "@agentic-sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import type { Upstream, UpstreamPackument } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const FIXTURES = join(REPO, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO, "scripts", "make-fixtures.ts")], { cwd: REPO, stdio: "ignore" });
}
function boot(): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(),
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` })); });
}

describe("GET /-/explain (e2e)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot()); });
  after(() => server?.close());

  test("blocked release returns report + remediation + last-known-good earlier version", async () => {
    const r = await (await fetch(`${base}/-/explain/hijacked-lib/2.0.0`)).json() as {
      report: { verdict: string; findings: unknown[] };
      remediation: { items: { ruleId: string }[]; waiver: unknown };
      lastKnownGood: { version: string; score: number } | null;
    };
    assert.notEqual(r.report.verdict, "allow"); // v2 is flagged
    assert.ok(r.remediation.items.length >= 1);
    assert.ok(r.remediation.waiver); // block/warn → waiver present
    assert.equal(r.lastKnownGood?.version, "1.0.0"); // v1 is the clean earlier release
  });

  test("a clean package has no last-known-good need (or itself is fine)", async () => {
    const r = await (await fetch(`${base}/-/explain/leftpad-lite/1.0.0`)).json() as {
      report: { verdict: string }; lastKnownGood: unknown;
    };
    assert.equal(r.report.verdict, "allow");
    // no earlier clean version required; lastKnownGood may be null (no priors) — just assert shape
  });
});

// A stub upstream that THROWS on any public call — proves findLastKnownGood never
// reaches it for a claimed private namespace (invariant #7: claimed names are
// authoritative private, never consulted on public npm).
class ThrowingUpstream implements Upstream {
  readonly name = "throwing-stub";
  async getPackument(_pkg: string): Promise<UpstreamPackument> {
    throw new Error("PUBLIC NPM CALLED for a claimed private namespace — invariant #7 breach");
  }
  async getTarball(_pkg: string, _version: string): Promise<Buffer> {
    throw new Error("PUBLIC NPM CALLED for a claimed private namespace — invariant #7 breach");
  }
  async getAttestations(_pkg: string, _version: string): Promise<unknown | null> {
    throw new Error("PUBLIC NPM CALLED for a claimed private namespace — invariant #7 breach");
  }
}

describe("GET /-/explain — claimed private namespace never leaks to public npm (invariant #7)", () => {
  let server: Server; let base: string; let priv: PrivatePackageStore;
  const policy: EnterprisePolicy = { ...DEFAULT_POLICY, privateNamespaces: ["@acme/*"] };

  before(async () => {
    ensureFixtures();
    priv = new PrivatePackageStore();
    const tgz = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
    const integrity = integrityOf(tgz);
    const meta = {
      name: "@acme/widget", version: "1.0.0", author: null, maintainers: [], license: null,
      hasInstallScripts: false, signature: "unsigned" as const, provenance: "absent" as const, integrity,
    };
    const audit = await runAudit({ meta, tarball: tgz });
    // v1.0.0: clean (audits allow) — the expected last-known-good.
    priv.put({
      name: "@acme/widget", version: "1.0.0", integrity,
      manifest: { name: "@acme/widget", version: "1.0.0", dist: {} }, tarball: tgz, audit, actor: "seed",
    });
    // v2.0.0: has install scripts flagged so it does not audit allow (creates a real
    // "explain a bad release, find the good one" scenario within the private store).
    const meta2 = { ...meta, version: "2.0.0", hasInstallScripts: true, integrity };
    const audit2 = await runAudit({ meta: meta2, tarball: tgz });
    priv.put({
      name: "@acme/widget", version: "2.0.0", integrity,
      manifest: { name: "@acme/widget", version: "2.0.0", dist: {} }, tarball: tgz, audit: audit2, actor: "seed",
    });

    const app = createServer({
      upstream: new ThrowingUpstream(),
      store: new AuditStore(), approvals: new ApprovalStore(), privateStore: priv,
      enterprisePolicy: policy, policy: "observe",
      violations: new ViolationStore(),
      approvalRequests: new ApprovalRequestStore(),
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  test("last-known-good for a claimed name is resolved via the private store, never public npm", async () => {
    const res = await fetch(`${base}/-/explain/@acme%2fwidget/2.0.0`);
    assert.equal(res.status, 200, "must not 500/throw from a public-upstream call");
    const body = await res.json() as {
      report: { meta: { name: string } };
      lastKnownGood: { version: string; score: number } | null;
    };
    assert.equal(body.report.meta.name, "@acme/widget");
    // Found via privateStore.versions(), not the ThrowingUpstream — if findLastKnownGood
    // had called public npm for this claimed name, ThrowingUpstream.getPackument would
    // have thrown and the route's catch would have swallowed it into a 500 or a null
    // lastKnownGood; asserting the actual private prior proves the isClaimed branch ran.
    assert.equal(body.lastKnownGood?.version, "1.0.0");
  });
});
