#!/usr/bin/env node
import { dirname, join, resolve } from "node:path";
import { readFileSync, realpathSync } from "node:fs";
import { validateAuthPublicKey } from "./auth-config.js";
import { parseTarballOrigins, parsePublicBaseUrl } from "./net-config.js";
import { parsePositiveInt } from "./limits.js";
import { createRateLimiter, type RateLimiter } from "./rate-limit.js";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  loadPolicy,
  DEFAULT_POLICY,
  policyHashOf,
  loadTrustMaterial,
  parseAdvisoriesStrict,
  parseVulnAdvisoriesStrict,
  type EnterprisePolicy,
  type ProvenanceTrustMaterial,
  type Advisory,
  type VulnAdvisory,
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
export * from "./resolution.js";
export { ViolationStore } from "./violations.js";
export { ApprovalRequestStore } from "./approval-requests.js";
export * from "./upstream.js";

function env(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function buildUpstream(
  tarballOrigins: readonly string[],
  maxTarballBytes: number | undefined,
  maxPackumentBytes: number | undefined,
): Upstream {
  const mode = env("SENTINEL_UPSTREAM", "npm");
  if (mode === "fixtures" || mode.startsWith("fixtures:")) {
    const dir = mode.includes(":")
      ? resolve(mode.split(":")[1] ?? "")
      : resolve(env("SENTINEL_FIXTURES", "fixtures"));
    return new LocalFixtureUpstream(dir);
  }
  return new NpmUpstream(
    env("SENTINEL_REGISTRY", "https://registry.npmjs.org"),
    tarballOrigins,
    maxTarballBytes ?? 256 * 1024 * 1024,
    maxPackumentBytes ?? 128 * 1024 * 1024,
  );
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

function resolveVulnerabilities(): VulnAdvisory[] | undefined {
  const path = process.env.SENTINEL_VULNERABILITIES;
  if (!path) return undefined;
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    console.error(`FATAL: cannot read SENTINEL_VULNERABILITIES: ${(err as Error).message}`);
    process.exit(1);
  }
  let vulnerabilities: VulnAdvisory[];
  try {
    vulnerabilities = parseVulnAdvisoriesStrict(raw);
  } catch (err) {
    console.error(`FATAL: ${(err as Error).message} (${path})`);
    process.exit(1);
  }
  console.log(`  vulnerabilities: ${vulnerabilities.length} operator-supplied (+ bundled)`);
  return vulnerabilities;
}

function resolveTarballOrigins(): string[] {
  const raw = process.env.SENTINEL_TARBALL_ORIGINS;
  if (!raw) return [];
  try {
    return parseTarballOrigins(raw);
  } catch (err) {
    console.error(`FATAL: ${(err as Error).message}`);
    process.exit(1);
  }
}

function resolvePublicBaseUrl(): string | undefined {
  const raw = process.env.SENTINEL_PUBLIC_BASE_URL;
  if (!raw) return undefined;
  try {
    return parsePublicBaseUrl(raw);
  } catch (err) {
    console.error(`FATAL: ${(err as Error).message}`);
    process.exit(1);
  }
}

/** Parse a positive-int env var, FATAL on invalid; undefined when unset. */
function resolvePositiveInt(name: string): number | undefined {
  const raw = process.env[name];
  if (!raw) return undefined;
  try {
    return parsePositiveInt(raw, name);
  } catch (err) {
    console.error(`FATAL: ${(err as Error).message}`);
    process.exit(1);
  }
}

function resolveRateLimiter(): RateLimiter | undefined {
  const rpm = resolvePositiveInt("SENTINEL_RATE_LIMIT_RPM");
  if (rpm === undefined) return undefined;
  return createRateLimiter({ rpm, now: () => Date.now() });
}

function resolveAutoQuarantine(authEnabled: boolean): boolean {
  const on = process.env.SENTINEL_AUTO_QUARANTINE === "1";
  if (on && !authEnabled) {
    console.error("FATAL: SENTINEL_AUTO_QUARANTINE=1 requires SENTINEL_AUTH_PUBKEY (auto-quarantine must be attributable to a verified token)");
    process.exit(1);
  }
  return on;
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
  const tarballOrigins = resolveTarballOrigins();
  const publicBaseUrl = resolvePublicBaseUrl();
  const maxTarballBytes = resolvePositiveInt("SENTINEL_MAX_TARBALL_BYTES");
  const maxPackumentBytes = resolvePositiveInt("SENTINEL_MAX_PACKUMENT_BYTES");
  const maxTreePackages = resolvePositiveInt("SENTINEL_MAX_TREE_PACKAGES");
  const maxUnpackedBytes = resolvePositiveInt("SENTINEL_MAX_UNPACKED_BYTES");
  const maxFileCount = resolvePositiveInt("SENTINEL_MAX_FILE_COUNT");
  const extractLimits = (maxUnpackedBytes !== undefined || maxFileCount !== undefined)
    ? { maxUnpackedBytes, maxFileCount }
    : undefined;
  const rateLimiter = resolveRateLimiter();
  const upstream = buildUpstream(tarballOrigins, maxTarballBytes, maxPackumentBytes);
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
  const vulnerabilities = resolveVulnerabilities();
  const autoQuarantine = resolveAutoQuarantine(Boolean(authPublicKey));

  const app = createServer({ upstream, store, approvals, enterprisePolicy, policyHash, policy, publicDir, privateStore, publishTokens, trustMaterial, violations, approvalRequests, authPublicKey, history, advisories, vulnerabilities, publicBaseUrl, maxTreePackages, rateLimiter, extractLimits, autoQuarantine });
  app.listen(port, () => {
    console.log(`Sentinel proxy listening on http://localhost:${port}`);
    console.log(`  upstream : ${upstream.name}`);
    console.log(`  tarball-origins: registry origin${tarballOrigins.length ? " + " + tarballOrigins.join(", ") : " only"}`);
    console.log(`  public-url: ${publicBaseUrl ?? "loopback-derived (set SENTINEL_PUBLIC_BASE_URL for network deployments)"}`);
    console.log(`  policy   : ${policy}  (observe = audit+serve, block = 403 on block verdict)`);
    console.log(`  trust    : ${trustMaterial === undefined ? "bundled Sigstore root" : "operator-supplied root"}`);
    console.log(`  auth     : ${authPublicKey ? "enabled (signed role tokens)" : "disabled (open control plane)"}`);
    console.log(`  limits   : tree ${maxTreePackages ?? 5000} pkgs, tarball ${(maxTarballBytes ?? 256 * 1024 * 1024)} B, packument ${(maxPackumentBytes ?? 128 * 1024 * 1024)} B, unpacked ${(maxUnpackedBytes ?? 1024 * 1024 * 1024)} B, files ${(maxFileCount ?? 100000)}`);
    console.log(`  rate-limit: ${rateLimiter ? `${process.env.SENTINEL_RATE_LIMIT_RPM} rpm/source` : "disabled"}`);
    console.log(`  violations: ${process.env.SENTINEL_VIOLATIONS ? "persisted" : "in-memory"}`);
    console.log(`  auto-quarantine: ${autoQuarantine ? "on (confirmed violations quarantine; auth-gated)" : "off (violations record-only)"}`);
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
