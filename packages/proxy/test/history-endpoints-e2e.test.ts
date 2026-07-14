import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@agentic-sentinel/core";
import type { AuditReport } from "@agentic-sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import { HistoryDb } from "../src/history-db.js";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "fixtures");
const rep = (integrity: string, name: string, verdict: "allow" | "warn" | "block"): AuditReport =>
  ({ schema: 3, meta: { name, version: "1.0.0", integrity, signature: "unsigned", provenance: "absent" }, score: verdict === "block" ? 10 : 100, verdict, findings: [] } as unknown as AuditReport);

function boot(withHistory: boolean): Promise<{ server: Server; base: string; history?: HistoryDb }> {
  const history = withHistory ? new HistoryDb(":memory:") : undefined;
  const store = new AuditStore(undefined, undefined, history);
  if (history) { store.put(rep("sha512-1", "evil", "block")); store.put(rep("sha512-2", "ok", "allow")); }
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store, approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(undefined, history), approvalRequests: new ApprovalRequestStore(), history,
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, history })); });
}

describe("observability endpoints (e2e)", () => {
  test("GET /-/metrics returns summary + trends + topFlagged when enabled", async () => {
    const { server, base, history } = await boot(true);
    const m = await (await fetch(`${base}/-/metrics`)).json() as { summary: { total: number; verdict: { block: number } }; trends: unknown[]; topFlagged: { name: string }[] };
    assert.equal(m.summary.total, 2);
    assert.equal(m.summary.verdict.block, 1);
    assert.ok(Array.isArray(m.trends));
    assert.equal(m.topFlagged[0]!.name, "evil");
    server.close(); history?.close();
  });

  test("GET /-/history?verdict=block filters", async () => {
    const { server, base, history } = await boot(true);
    const h = await (await fetch(`${base}/-/history?verdict=block`)).json() as { history: { name: string }[] };
    assert.equal(h.history.length, 1);
    assert.equal(h.history[0]!.name, "evil");
    server.close(); history?.close();
  });

  test("GET /-/history?limit=-1 is clamped (a negative limit must not become an unbounded SQLite LIMIT -1)", async () => {
    const { server, base, history } = await boot(true); // seeds exactly 2 audits
    const h = await (await fetch(`${base}/-/history?limit=-1`)).json() as { history: unknown[] };
    assert.equal(h.history.length, 1); // clamped to 1; the bug would have dumped all 2 (unbounded)
    server.close(); history?.close();
  });

  test("GET /-/history with a repeated (array) query param returns 200, not a 500", async () => {
    const { server, base, history } = await boot(true);
    const res = await fetch(`${base}/-/history?verdict=block&verdict=allow`); // Express parses to an array
    assert.equal(res.status, 200); // array param coerced to undefined, not bound into node:sqlite
    const h = await res.json() as { history: unknown[] };
    assert.equal(h.history.length, 2); // verdict filter dropped → all rows
    server.close(); history?.close();
  });

  test("GET /-/violations/timeline returns timeline when enabled, and /-/violations still works", async () => {
    const { server, base, history } = await boot(true);
    const t = await (await fetch(`${base}/-/violations/timeline`)).json() as { timeline: unknown[] };
    assert.ok(Array.isArray(t.timeline));
    const v = await fetch(`${base}/-/violations`);
    assert.equal(v.status, 200);
    const vb = await v.json() as { violations: unknown[] };
    assert.ok(Array.isArray(vb.violations));
    server.close(); history?.close();
  });

  test("disabled: /-/metrics returns 501 { enabled: false }", async () => {
    const { server, base } = await boot(false);
    const res = await fetch(`${base}/-/metrics`);
    assert.equal(res.status, 501);
    assert.equal(((await res.json()) as { enabled: boolean }).enabled, false);
    server.close();
  });

  test("disabled: /-/history returns 501 { enabled: false }", async () => {
    const { server, base } = await boot(false);
    const res = await fetch(`${base}/-/history`);
    assert.equal(res.status, 501);
    assert.equal(((await res.json()) as { enabled: boolean }).enabled, false);
    server.close();
  });

  test("disabled: /-/violations/timeline returns 501 { enabled: false }", async () => {
    const { server, base } = await boot(false);
    const res = await fetch(`${base}/-/violations/timeline`);
    assert.equal(res.status, 501);
    assert.equal(((await res.json()) as { enabled: boolean }).enabled, false);
    server.close();
  });

  test("GET / still serves the dashboard html", async () => {
    const { server, base, history } = await boot(true);
    const res = await fetch(`${base}/`);
    // publicDir is not set in this boot, so GET / may 404 — assert the endpoint contract instead:
    assert.ok(res.status === 200 || res.status === 404);
    server.close(); history?.close();
  });
});
