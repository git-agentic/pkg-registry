import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, integrityOf, type TreeAuditResult } from "@git-agentic/sentinel-core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream, type Upstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");

describe("F19: audit-tree blocks non-registry coordinates without fetching anything", () => {
  let server: Server;
  let base: string;
  const fetched: string[] = [];

  before(async () => {
    if (!existsSync(join(FIXTURES, "registry.json")) || !existsSync(join(FIXTURES, ".tarballs"))) {
      execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
    }
    const fixture = new LocalFixtureUpstream(FIXTURES);
    const spy: Upstream = {
      name: "spy",
      getPackument: (name) => { fetched.push(`packument:${name}`); return fixture.getPackument(name); },
      getTarball: (name, version) => { fetched.push(`tarball:${name}@${version}`); return fixture.getTarball(name, version); },
      getAttestations: (name, version) => fixture.getAttestations(name, version),
    };
    const app = createServer({
      upstream: spy, store: new AuditStore(), approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(), violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(),
    });
    server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  after(() => server.close());

  const post = async (packages: unknown[]) => {
    const res = await fetch(`${base}/-/audit-tree`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages }) });
    assert.equal(res.status, 200);
    return (await res.json()) as TreeAuditResult;
  };

  test("a git-resolved coordinate becomes a block row, gates the tree, and triggers no fetch", async () => {
    fetched.length = 0;
    const spec = "git+ssh://git@github.com/evil/leftpad-lite.git#abc123";
    const out = await post([{ name: "leftpad-lite", version: "1.0.0", nonRegistry: spec }]);
    assert.equal(out.packages.length, 1);
    assert.equal(out.packages[0]!.status, "block");
    assert.match(out.packages[0]!.topFinding ?? "", /cannot be audited through the proxy/);
    assert.match(out.packages[0]!.topFinding ?? "", /git source/);
    assert.equal(out.aggregate.gated, true);
    assert.deepEqual(fetched, []);
  });

  test("the block row never echoes the raw resolution (it can carry credentials or signed query strings)", async () => {
    const secrets = [
      "git+https://user:s3cr3t@github.com/evil/x.git#abc",
      "https://cdn.example/x.tgz?X-Amz-Signature=deadbeef&token=hunter2",
      "somethingelse:opaque-token-abc",
    ];
    const kinds = ["git", "url", "other"];
    for (const [i, spec] of secrets.entries()) {
      const out = await post([{ name: "leftpad-lite", version: "1.0.0", nonRegistry: spec }]);
      const text = JSON.stringify(out);
      assert.ok(!/s3cr3t|deadbeef|hunter2|opaque-token/.test(text), `leaked: ${text}`);
      assert.match(out.packages[0]!.topFinding ?? "", new RegExp(`${kinds[i]} source`));
    }
  });

  test("a clean registry row for the same name@version is not hidden by, and does not hide, the git row", async () => {
    const out = await post([
      { name: "leftpad-lite", version: "1.0.0" },
      { name: "leftpad-lite", version: "1.0.0", nonRegistry: "github:evil/leftpad-lite#abc" },
    ]);
    assert.equal(out.packages.length, 2);
    assert.notEqual(out.packages[0]!.status, "block", "the registry twin keeps its own verdict");
    assert.equal(out.packages[1]!.status, "block");
    assert.equal(out.aggregate.gated, true);
  });

  test("a non-string nonRegistry is a 400, not a silent registry audit", async () => {
    const res = await fetch(`${base}/-/audit-tree`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages: [{ name: "leftpad-lite", version: "1.0.0", nonRegistry: true }] }) });
    assert.equal(res.status, 400);
  });

  const REAL = integrityOf(readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.0.tgz")));

  test("integrity is part of the dedupe key: each distinct pin is verified against the served bytes", async () => {
    const out = await post([
      { name: "leftpad-lite", version: "1.0.0", integrity: REAL },
      { name: "leftpad-lite", version: "1.0.0", integrity: "sha512-" + Buffer.alloc(64, 1).toString("base64") },
    ]);
    assert.equal(out.packages[0]!.integrityMismatch, false);
    assert.equal(out.packages[1]!.integrityMismatch, true);
    assert.equal(out.packages[1]!.status, "block");
    assert.equal(out.aggregate.gated, true);
  });

  test("an unknown integrity algorithm is a mismatch, not silently unverified", async () => {
    const out = await post([{ name: "leftpad-lite", version: "1.0.0", integrity: "md5-AAAAAAAAAAAAAAAAAAAAAA==" }]);
    assert.equal(out.packages[0]!.integrityMismatch, true);
    assert.equal(out.packages[0]!.status, "block");
  });

  test("a multi-token SRI passes when every known-algorithm token matches", async () => {
    const out = await post([{ name: "leftpad-lite", version: "1.0.0", integrity: `${REAL} md5-ignored` }]);
    assert.equal(out.packages[0]!.integrityMismatch, false);
  });
});
