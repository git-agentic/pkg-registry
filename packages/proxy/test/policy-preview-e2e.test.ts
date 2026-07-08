import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, score } from "@sentinel/core";
import type { Audit, AuditReport, EnterprisePolicy } from "@sentinel/core";
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

// Seed reports whose stored `verdict` is CONSISTENT with what DEFAULT_POLICY scores, so that an
// identical candidate replays to "unchanged". A single high finding scores 100−25=75 → "warn" under
// DEFAULT (weights {high:25}, thresholds {allow:80,warn:50}, hardBlockSeverity "critical"); no findings
// → 100 → "allow".
function reportWith(name: string, integrity: string, severity: "high" | "info"): AuditReport {
  const hasFinding = severity === "high";
  return {
    schema: 3,
    meta: { name, version: "1.0.0", integrity, signature: "unsigned", provenance: "absent", author: null, maintainers: [], license: "MIT", hasInstallScripts: false, unpackedSize: 1, fileCount: 1 },
    score: hasFinding ? 75 : 100,
    verdict: hasFinding ? "warn" : "allow",
    findings: hasFinding ? [{ ruleId: "network-egress", category: "network", severity: "high", message: "x", onChangedFile: false, evidence: [], weight: 25, waived: false }] : [],
    capabilities: [], capabilityDelta: null,
    engine: { version: "0.1.0", rules: [], llm: null, mode: "full" }, llmSummary: null,
    auditedAt: "2026-07-01T00:00:00Z", durationMs: 0, policy: { version: "default", hash: "h" },
  } as unknown as AuditReport;
}

function boot(withHistory: boolean): Promise<{ server: Server; base: string; history?: HistoryDb }> {
  const history = withHistory ? new HistoryDb(":memory:") : undefined;
  if (history) {
    // seed: one clean (no findings → allow under any sane policy) + one with a high finding.
    history.recordAudit(reportWith("clean", "sha512-a", "info"), "2026-07-01T00:00:00Z");
    history.recordAudit(reportWith("risky", "sha512-b", "high"), "2026-07-02T00:00:00Z");
  }
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: DEFAULT_POLICY, privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(), history,
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, history })); });
}
const preview = async (base: string, policy: unknown) =>
  (await fetch(`${base}/-/policy/preview`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ policy }) }));

describe("POST /-/policy/preview (e2e)", () => {
  test("a stricter candidate flips the risky audit's verdict; the clean one is unchanged", async () => {
    const { server, base, history } = await boot(true);
    // Stricter: hard-block on `high` (default hard-blocks only on `critical`). The risky package's
    // one high finding now triggers a hard block → "block"; it was stored as "warn". Clean stays allow.
    const strict: EnterprisePolicy = structuredClone(DEFAULT_POLICY);
    strict.scoring.hardBlockSeverity = "high";
    const r = await (await preview(base, strict)).json() as { enabled: boolean; total: number; transitions: Record<string, number>; changed: { name: string; from: string; to: string }[] };
    assert.equal(r.enabled, true);
    assert.equal(r.total, 2);
    assert.ok(r.transitions.warnToBlock >= 1);
    assert.ok(r.changed.some((c) => c.name === "risky" && c.from === "warn" && c.to === "block"));
    assert.equal(r.changed.some((c) => c.name === "clean"), false); // clean stays allow
    server.close(); history?.close();
  });

  test("an identical candidate → all unchanged, changed empty (faithful replay)", async () => {
    const { server, base, history } = await boot(true);
    const r = await (await preview(base, DEFAULT_POLICY)).json() as { total: number; transitions: { unchanged: number }; changed: unknown[] };
    assert.equal(r.transitions.unchanged, r.total);
    assert.equal(r.changed.length, 0);
    server.close(); history?.close();
  });

  test("an identical candidate with a policy-synthesized dependency-confusion finding → faithful replay (no double-count)", async () => {
    // Regression for the preview route double-counting score()-SYNTHESIZED findings (dependency-confusion,
    // provenance-identity) when it re-scores a stored AuditReport. Claim "@acme/utils"; "acme-utils" is a
    // public look-alike (normalizeName("@acme/utils") -> "acme"; canonical("acme-utils") -> "acmeutils",
    // which startsWith "acme") so score() synthesizes a `dependency-confusion` finding for it.
    const policyWithNamespaces: EnterprisePolicy = structuredClone(DEFAULT_POLICY);
    policyWithNamespaces.privateNamespaces = ["@acme/utils"];

    // A real (non-synthesized) medium finding alongside the synthesized dependency-confusion one:
    // with weights {medium:12, high:25} and thresholds {allow:80, warn:50}, a SINGLE dc finding
    // scores 100-12-25=63 ("warn"), but re-synthesizing + re-appending a SECOND dc finding (the bug)
    // scores 100-12-25-25=38 ("block") — a verdict flip that proves the double-count, unlike a bare
    // dc finding whose 25-point penalty alone straddles the warn/allow boundary without crossing warn/block.
    const audit = {
      schema: 3,
      meta: {
        name: "acme-utils", version: "1.0.0", integrity: "sha512-c",
        signature: "unsigned", provenance: "absent", author: null, maintainers: [],
        license: "MIT", hasInstallScripts: false, unpackedSize: 1, fileCount: 1,
      },
      findings: [{ ruleId: "some-other-rule", category: "metadata", severity: "medium", message: "x", onChangedFile: false, evidence: [] }],
      capabilities: [], capabilityDelta: null,
      engine: { version: "0.1.0", rules: [], mode: "full" },
      auditedAt: "2026-07-03T00:00:00Z", durationMs: 0,
    } as unknown as Audit;

    // Produce a genuinely self-consistent AuditReport via the real score() — its findings and verdict
    // already include the one-time synthesized dependency-confusion finding.
    const selfConsistentReport = score(audit, policyWithNamespaces, "seed-hash");
    assert.ok(
      selfConsistentReport.findings.some((f) => f.ruleId === "dependency-confusion"),
      "seed report must actually contain a dependency-confusion finding, or this test is vacuous",
    );
    assert.equal(selfConsistentReport.verdict, "warn");

    const history = new HistoryDb(":memory:");
    history.recordAudit(selfConsistentReport, "2026-07-03T00:00:00Z");
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
      enterprisePolicy: policyWithNamespaces, privateStore: new PrivatePackageStore(),
      violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(), history,
    });
    const server: Server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    // Identical candidate: same privateNamespaces claim → dependency-confusion should synthesize
    // identically, not double up. transitions.unchanged must equal total, changed must be empty.
    const r = await (await preview(base, policyWithNamespaces)).json() as {
      total: number; transitions: { unchanged: number }; changed: unknown[];
    };
    assert.equal(r.transitions.unchanged, r.total);
    assert.equal(r.changed.length, 0);
    server.close(); history.close();
  });

  test("no history → 501 { enabled: false }", async () => {
    const { server, base } = await boot(false);
    const res = await preview(base, DEFAULT_POLICY);
    assert.equal(res.status, 501);
    assert.equal(((await res.json()) as { enabled: boolean }).enabled, false);
    server.close();
  });

  test("a malformed candidate policy → 400", async () => {
    const { server, base, history } = await boot(true);
    const res = await preview(base, { not: "a policy" });
    assert.equal(res.status, 400);
    server.close(); history?.close();
  });
});
