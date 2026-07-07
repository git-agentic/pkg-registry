import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type TreeAuditResult } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

async function auditTree(base: string, packages: { name: string; version: string }[]): Promise<TreeAuditResult> {
  const res = await fetch(`${base}/-/audit-tree`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ packages }),
  });
  assert.ok(res.ok, `expected 2xx, got ${res.status}`);
  return (await res.json()) as TreeAuditResult;
}

describe("POST /-/audit-tree (local fixtures)", () => {
  let server: Server;
  let base: string;

  before(async () => {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals: new ApprovalStore(),
      enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(),
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; resolve(); });
    });
  });
  after(() => server?.close());

  test("a benign tree is allow / not gated", async () => {
    const r = await auditTree(base, [
      { name: "leftpad-lite", version: "1.0.0" },
      { name: "net-fetch-lite", version: "1.0.0" },
    ]);
    assert.equal(r.aggregate.verdict, "allow");
    assert.equal(r.aggregate.gated, false);
    assert.equal(r.packages.length, 2);
    const pv = r.aggregate.provenance;
    assert.equal(pv.verified + pv.invalid + pv.absent + pv.unknown, r.packages.length);
    for (const p of r.packages) assert.notEqual(p.provenance, undefined);
  });

  test("a tree containing the malicious fixture is block / gated and names it", async () => {
    const r = await auditTree(base, [
      { name: "leftpad-lite", version: "1.0.0" },
      { name: "color-stream", version: "1.4.1" },
    ]);
    assert.equal(r.aggregate.verdict, "block");
    assert.equal(r.aggregate.gated, true);
    const cs = r.packages.find((p) => p.name === "color-stream");
    assert.equal(cs?.status, "block");
  });

  test("an unresolvable package is an error row, not a crash", async () => {
    const r = await auditTree(base, [
      { name: "leftpad-lite", version: "1.0.0" },
      { name: "does-not-exist", version: "9.9.9" },
    ]);
    const miss = r.packages.find((p) => p.name === "does-not-exist");
    assert.equal(miss?.status, "error");
    assert.ok(miss?.error);
    assert.equal(miss?.provenance, null); // error rows never have a provenance status
    assert.equal(r.aggregate.counts.error, 1);
    assert.equal(r.aggregate.gated, false); // errors never gate
  });

  test("output is deterministic and sorted by name@version", async () => {
    const coords = [
      { name: "net-fetch-lite", version: "1.0.0" },
      { name: "leftpad-lite", version: "1.0.0" },
    ];
    const a = await auditTree(base, coords);
    const b = await auditTree(base, [...coords].reverse());
    assert.deepEqual(a, b);
    assert.deepEqual(a.packages.map((p) => p.name), ["leftpad-lite", "net-fetch-lite"]);
  });

  test("a malformed body is a 400", async () => {
    const res = await fetch(`${base}/-/audit-tree`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ nope: 1 }),
    });
    assert.equal(res.status, 400);
  });
});
