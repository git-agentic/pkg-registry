import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type NpmSigningKey } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
const KEYS_FILE = join(FIXTURES, "signing-keys.json");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs")) && existsSync(KEYS_FILE)) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

async function sig(base: string, pkg: string, version: string): Promise<string> {
  const r = await fetch(`${base}/-/audit/${pkg}/${version}`);
  const report = (await r.json()) as { meta: { signature: string; provenance: string } };
  return `${report.meta.signature}/${report.meta.provenance}`;
}

describe("registry signature verification (local fixtures, test keys)", () => {
  let server: Server; let base: string;
  before(async () => {
    ensureFixtures();
    const signingKeys = JSON.parse(readFileSync(KEYS_FILE, "utf8")) as NpmSigningKey[];
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
      approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(), signingKeys,
      violations: new ViolationStore(),
    });
    await new Promise<void>((res) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; res(); }); });
  });
  after(() => server?.close());

  test("a validly-signed fixture verifies with provenance absent", async () => {
    assert.equal(await sig(base, "leftpad-lite", "1.0.0"), "verified/absent");
  });
  test("a tampered signature is invalid", async () => {
    assert.equal((await sig(base, "sig-tampered", "1.0.0")).split("/")[0], "invalid");
  });
  test("an unsigned fixture is unsigned", async () => {
    assert.equal((await sig(base, "sig-unsigned", "1.0.0")).split("/")[0], "unsigned");
  });
  test("an unknown-keyid signature is unknown", async () => {
    assert.equal((await sig(base, "sig-unknown", "1.0.0")).split("/")[0], "unknown");
  });
  test("a fixture without attestations has provenance absent", async () => {
    assert.equal((await sig(base, "prov-absent", "1.0.0")).split("/")[1], "absent");
  });
});

describe("requireSignature / requireProvenance policy gate (proxy integration)", () => {
  let server: Server; let base: string;
  before(async () => {
    ensureFixtures();
    const signingKeys = JSON.parse(readFileSync(KEYS_FILE, "utf8")) as NpmSigningKey[];
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
      approvals: new ApprovalStore(),
      enterprisePolicy: { ...DEFAULT_POLICY, requireSignature: ["sig-unsigned"], requireProvenance: ["prov-absent"] },
      policy: "block",
      privateStore: new PrivatePackageStore(), signingKeys,
      violations: new ViolationStore(),
    });
    await new Promise<void>((res) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; res(); }); });
  });
  after(() => server?.close());

  test("a package matching requireSignature but not verified is blocked", async () => {
    const res = await fetch(`${base}/sig-unsigned/-/sig-unsigned-1.0.0.tgz`);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-sentinel-verdict"), "block");
  });
  test("a package matching requireProvenance but without provenance is blocked", async () => {
    const res = await fetch(`${base}/prov-absent/-/prov-absent-1.0.0.tgz`);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("x-sentinel-verdict"), "block");
  });
  test("a verified-signature package not matching any requirement is allowed", async () => {
    const res = await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-sentinel-verdict"), "allow");
  });
});
