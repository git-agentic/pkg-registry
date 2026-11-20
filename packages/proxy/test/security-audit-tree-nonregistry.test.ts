import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, integrityOf, integrityOfAlgo, parseAnyLockfile, parseLockfile, type TreeAuditResult } from "@git-agentic/sentinel-core";
import { createServer, integrityClaimMismatch } from "../src/server.js";
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

  const TARBALL = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.0.tgz"));
  const mismatch = async (integrity: string) => (await post([{ name: "leftpad-lite", version: "1.0.0", integrity }])).packages[0]!.integrityMismatch;

  test("a multi-token SRI passes only when EVERY known-algorithm token matches", async () => {
    assert.equal(await mismatch(`${REAL} ${integrityOfAlgo(TARBALL, "sha1")}`), false);
    assert.equal(await mismatch(`${integrityOfAlgo(TARBALL, "sha384")} ${REAL}`), false);
    assert.equal(await mismatch(`${REAL} sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=`), true, "a wrong weaker token must still block");
    assert.equal(await mismatch(`${integrityOfAlgo(TARBALL, "sha384")} sha512-${Buffer.alloc(64, 2).toString("base64")}`), true);
  });

  test("sha384 is verified, not ignored", async () => {
    assert.equal(await mismatch(integrityOfAlgo(TARBALL, "sha384")), false);
    assert.equal(await mismatch("sha384-" + Buffer.alloc(48, 3).toString("base64")), true);
  });

  test("any unknown-algorithm token blocks, even next to a matching known one", async () => {
    assert.equal(await mismatch(`${REAL} md5-ignored`), true);
    assert.equal(await mismatch(`${REAL} garbage`), true);
  });

  test("each algorithm's digest is computed at most once per claim (1,000 repeated tokens on a big tarball)", () => {
    const big = Buffer.alloc(24 * 1024 * 1024, 5);
    const tok = integrityOfAlgo(big, "sha512");
    const t0 = Date.now();
    assert.equal(integrityClaimMismatch(big, Array(1000).fill(tok).join(" ")), false);
    assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
  });

  test("no URL, userinfo or query string from a hostile lockfile reaches the audit-tree response", async () => {
    const yarn = `# yarn lockfile v1\n\n"https://user:pw@evil.example/x.tgz?sig=abc":\n  version "1.0.0"\n  resolved "https://user:pw@evil.example/x.tgz?sig=abc"\n`;
    const pnpm = `lockfileVersion: '9.0'\n\npackages:\n\n  evil@https://user:pw@cdn.example/x.tgz?sig=abc:\n    resolution: {tarball: 'https://user:pw@cdn.example/x.tgz?sig=abc'}\n`;
    for (const [raw, filename] of [[yarn, "yarn.lock"], [pnpm, "pnpm-lock.yaml"]] as const) {
      const coords = parseAnyLockfile(raw, { filename });
      const out = await post(coords);
      assert.equal(out.packages[0]!.status, "block");
      assert.ok(!/pw|sig=abc|evil\.example|cdn\.example/.test(JSON.stringify(out)), JSON.stringify(out));
    }
  });

  test("a sha384-only pinned lockfile entry stays registry and is verified by audit-tree", async () => {
    const lock = (integrity: string) => JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/leftpad-lite": { version: "1.0.0", resolved: "https://r.example/leftpad-lite/-/leftpad-lite-1.0.0.tgz", integrity } } });
    const good = parseLockfile(lock(integrityOfAlgo(TARBALL, "sha384")));
    assert.equal(good[0]!.nonRegistry, undefined);
    const ok = await post(good);
    assert.equal(ok.packages[0]!.integrityMismatch, false);
    assert.notEqual(ok.packages[0]!.status, "block");
    const bad = await post(parseLockfile(lock("sha384-" + Buffer.alloc(48, 9).toString("base64"))));
    assert.equal(bad.packages[0]!.integrityMismatch, true);
    assert.equal(bad.packages[0]!.status, "block");
  });

  test("a pnpm v5 URL key with a credential segment leaks nothing into the audit-tree response", async () => {
    const raw = `lockfileVersion: 5.4\n\npackages:\n\n  codeload.example/user/repo/tar.gz/s3cr3t-token:\n    resolution: {tarball: 'https://codeload.example/user/repo/tar.gz/s3cr3t-token'}\n`;
    const out = await post(parseAnyLockfile(raw, { filename: "pnpm-lock.yaml" }));
    assert.equal(out.packages[0]!.status, "block");
    assert.ok(!/s3cr3t|codeload|tar\.gz/.test(JSON.stringify(out)), JSON.stringify(out));
  });

  test("a non-string integrity is a 400, not a silently skipped check", async () => {
    for (const integrity of [123, true, ["sha512-x"], { a: 1 }, null]) {
      const res = await fetch(`${base}/-/audit-tree`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages: [{ name: "leftpad-lite", version: "1.0.0", integrity }] }) });
      assert.equal(res.status, 400, JSON.stringify(integrity));
    }
  });
});
