import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { request as httpRequest } from "node:http";
import { before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@agentic-sentinel/core";
import { createServer } from "../src/server.js";
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

function boot(publicBaseUrl?: string): Promise<{ server: Server; port: number }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(), publicBaseUrl,
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, port: (s.address() as AddressInfo).port })); });
}

/** GET via raw node:http so we control the Host header exactly. */
function get(port: number, path: string, hostHeader?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, path, headers: hostHeader ? { host: hostHeader } : undefined },
      (res) => {
        let data = "";
        res.on("data", (c: Buffer) => (data += c.toString()));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("packument rewrite base URL vs Host header (ADR-0036)", () => {
  before(() => ensureFixtures());

  test("unset + loopback Host: request-derived base (zero-config dev unchanged)", async () => {
    const { server, port } = await boot();
    try {
      const { status, body } = await get(port, "/leftpad-lite");
      assert.equal(status, 200);
      assert.ok(body.includes(`http://127.0.0.1:${port}/leftpad-lite/-/leftpad-lite-`));
    } finally { server.close(); }
  });

  test("unset + non-loopback Host: 421 telling the operator to set SENTINEL_PUBLIC_BASE_URL", async () => {
    const { server, port } = await boot();
    try {
      const { status, body } = await get(port, "/leftpad-lite", "registry.evil.example");
      assert.equal(status, 421);
      assert.match(body, /SENTINEL_PUBLIC_BASE_URL/);
    } finally { server.close(); }
  });

  test("set: configured base wins, spoofed Host is ignored", async () => {
    const { server, port } = await boot("https://sentinel.corp.example");
    try {
      const { status, body } = await get(port, "/leftpad-lite", "registry.evil.example");
      assert.equal(status, 200);
      // Parse the packument and check the rewritten tarball URL by ORIGIN, not a
      // whole-body substring — a substring match would also pass if the spoofed
      // host merely appeared somewhere in the URL.
      const doc = JSON.parse(body) as { versions: Record<string, { dist?: { tarball?: string } }> };
      const tarballs = Object.values(doc.versions).map((v) => v.dist?.tarball ?? "");
      assert.ok(tarballs.length > 0);
      for (const t of tarballs) {
        assert.equal(new URL(t).origin, "https://sentinel.corp.example");
        assert.ok(new URL(t).pathname.startsWith("/leftpad-lite/-/leftpad-lite-"));
      }
    } finally { server.close(); }
  });
});
