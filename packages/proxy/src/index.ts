#!/usr/bin/env node
import { dirname, join, resolve } from "node:path";
import { readFileSync, realpathSync } from "node:fs";
import { validateAuthPublicKey } from "./auth-config.js";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  loadPolicy,
  DEFAULT_POLICY,
  policyHashOf,
  loadTrustMaterial,
  parseAdvisoriesStrict,
  type EnterprisePolicy,
  type ProvenanceTrustMaterial,
  type Advisory,
} from "@sentinel/core";
import { createServer, type ProxyPolicy } from "./server.js";
import { AuditStore } from "./store.js";
import { ApprovalStore } from "./approvals.js";
import { LocalFixtureUpstream, NpmUpstream, type Upstream } from "./upstream.js";
import { PrivatePackageStore } from "./private-store.js";
import { ViolationStore } from "./violations.js";
import { ApprovalRequestStore } from "./approval-requests.js";
import { HistoryDb } from "./history-db.js";

export { createServer } from "./server.js";
export { AuditStore } from "./store.js";
export { ApprovalStore } from "./approvals.js";
export { PrivatePackageStore } from "./private-store.js";
export { ViolationStore } from "./violations.js";
export { ApprovalRequestStore } from "./approval-requests.js";
export * from "./upstream.js";

function env(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function buildUpstream(): Upstream {
  const mode = env("SENTINEL_UPSTREAM", "npm");
  if (mode === "fixtures" || mode.startsWith("fixtures:")) {
    const dir = mode.includes(":")
      ? resolve(mode.split(":")[1] ?? "")
      : resolve(env("SENTINEL_FIXTURES", "fixtures"));
    return new LocalFixtureUpstream(dir);
  }
  return new NpmUpstream(env("SENTINEL_REGISTRY", "https://registry.npmjs.org"));
}

function resolveEnterprisePolicy(): { policy: EnterprisePolicy; hash: string } {
  const file = process.env.SENTINEL_POLICY_FILE;
  if (!file) {
    console.log("  scoring  : built-in default policy");
    return { policy: DEFAULT_POLICY, hash: policyHashOf(DEFAULT_POLICY) };
  }
  const sig = process.env.SENTINEL_POLICY_SIG ?? `${file}.sig`;
  const pub = process.env.SENTINEL_POLICY_PUBKEY;
  if (!pub) {
    console.error("FATAL: SENTINEL_POLICY_PUBKEY is required when SENTINEL_POLICY_FILE is set");
    process.exit(1);
  }
  try {
    const { policy, hash } = loadPolicy({ file, sig, publicKeyPem: readFileSync(pub, "utf8") });
    console.log(`  scoring  : signed policy ${policy.version} (${hash.slice(0, 22)}…)`);
    return { policy, hash };
  } catch (err) {
    console.error(`FATAL: ${(err as Error).message}`);
    process.exit(1);
  }
}

export function resolveAuthPublicKey(): string | undefined {
  const path = process.env.SENTINEL_AUTH_PUBKEY;
  if (!path) return undefined; // open mode (explicitly unset)
  let content: string;
  try {
    content = readFileSync(path, "utf8");
  } catch (err) {
    console.error(`FATAL: cannot read SENTINEL_AUTH_PUBKEY: ${(err as Error).message}`);
    process.exit(1);
  }
  try {
    return validateAuthPublicKey(content);
  } catch {
    console.error(`FATAL: SENTINEL_AUTH_PUBKEY is not a valid public key PEM (${path})`);
    process.exit(1);
  }
}

function resolveAdvisories(): Advisory[] | undefined {
  const path = process.env.SENTINEL_ADVISORIES;
  if (!path) return undefined;
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    console.error(`FATAL: cannot read SENTINEL_ADVISORIES: ${(err as Error).message}`);
    process.exit(1);
  }
  let advisories: Advisory[];
  try {
    advisories = parseAdvisoriesStrict(raw);
  } catch (err) {
    console.error(`FATAL: ${(err as Error).message} (${path})`);
    process.exit(1);
  }
  console.log(`  advisories: ${advisories.length} operator-supplied (+ bundled)`);
  return advisories;
}

function resolveTrustMaterial(): ProvenanceTrustMaterial | null | undefined {
  const rootPath = process.env.SENTINEL_TRUSTED_ROOT;
  if (!rootPath) return undefined; // bundled default
  try {
    return loadTrustMaterial({ trustedRootPath: rootPath, npmKeysPath: process.env.SENTINEL_NPM_ATTESTATION_KEYS });
  } catch (err) {
    console.error(`FATAL: cannot load trust material from SENTINEL_TRUSTED_ROOT: ${(err as Error).message}`);
    process.exit(1);
  }
}

function main(): void {
  const here = dirname(fileURLToPath(import.meta.url));
  const port = Number(env("SENTINEL_PORT", "4873"));
  const policy = env("SENTINEL_POLICY", "observe") as ProxyPolicy;
  const upstream = buildUpstream();
  const { policy: enterprisePolicy, hash: policyHash } = resolveEnterprisePolicy();
  const history = process.env.SENTINEL_HISTORY_DB ? new HistoryDb(process.env.SENTINEL_HISTORY_DB) : undefined;
  const store = new AuditStore(process.env.SENTINEL_STORE, policyHash, history);
  const approvals = new ApprovalStore(process.env.SENTINEL_APPROVALS);
  const privateStore = new PrivatePackageStore(process.env.SENTINEL_PRIVATE_STORE);
  const publishTokens = (process.env.SENTINEL_PUBLISH_TOKENS ?? "").split(",").map((t) => t.trim()).filter(Boolean);
  // dist/index.js -> ../public ; src is run via tsx with the same relative layout.
  const publicDir = env("SENTINEL_PUBLIC", join(here, "..", "public"));
  const trustMaterial = resolveTrustMaterial();
  const violations = new ViolationStore(process.env.SENTINEL_VIOLATIONS, history);
  const approvalRequests = new ApprovalRequestStore(process.env.SENTINEL_APPROVAL_REQUESTS);
  const authPublicKey = resolveAuthPublicKey();
  const advisories = resolveAdvisories();

  const app = createServer({ upstream, store, approvals, enterprisePolicy, policyHash, policy, publicDir, privateStore, publishTokens, trustMaterial, violations, approvalRequests, authPublicKey, history, advisories });
  app.listen(port, () => {
    console.log(`Sentinel proxy listening on http://localhost:${port}`);
    console.log(`  upstream : ${upstream.name}`);
    console.log(`  policy   : ${policy}  (observe = audit+serve, block = 403 on block verdict)`);
    console.log(`  trust    : ${trustMaterial === undefined ? "bundled Sigstore root" : "operator-supplied root"}`);
    console.log(`  auth     : ${authPublicKey ? "enabled (signed role tokens)" : "disabled (open control plane)"}`);
    console.log(`  violations: ${process.env.SENTINEL_VIOLATIONS ? "persisted" : "in-memory"}`);
    console.log(`  approval-requests: ${process.env.SENTINEL_APPROVAL_REQUESTS ? "persisted" : "in-memory"}`);
    console.log(`  history  : ${history ? `enabled (${process.env.SENTINEL_HISTORY_DB})` : "disabled"}`);
    console.log(`  dashboard: http://localhost:${port}/`);
    const claims = enterprisePolicy.privateNamespaces ?? [];
    console.log(`  private  : ${claims.length ? claims.join(", ") : "none"}  (publish ${publishTokens.length ? "enabled" : "disabled"})`);
    console.log(`\nPoint npm at it:  npm install --registry http://localhost:${port}`);
    if (process.env.SENTINEL_BOOT_EXIT) process.exit(0);
  });
}

// Run only when invoked as the entrypoint (not when imported for its exports).
function isEntrypoint(): boolean {
  const a = process.argv[1];
  if (!a) return false;
  try { return import.meta.url === pathToFileURL(realpathSync(a)).href; } catch { return false; }
}
if (isEntrypoint()) main();
