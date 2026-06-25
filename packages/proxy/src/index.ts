#!/usr/bin/env node
import { dirname, join, resolve } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { loadPolicy, DEFAULT_POLICY, policyHashOf, type EnterprisePolicy } from "@sentinel/core";
import { createServer, type ProxyPolicy } from "./server.js";
import { AuditStore } from "./store.js";
import { ApprovalStore } from "./approvals.js";
import { LocalFixtureUpstream, NpmUpstream, type Upstream } from "./upstream.js";
import { PrivatePackageStore } from "./private-store.js";

export { createServer } from "./server.js";
export { AuditStore } from "./store.js";
export { ApprovalStore } from "./approvals.js";
export { PrivatePackageStore } from "./private-store.js";
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

function main(): void {
  const here = dirname(fileURLToPath(import.meta.url));
  const port = Number(env("SENTINEL_PORT", "4873"));
  const policy = env("SENTINEL_POLICY", "observe") as ProxyPolicy;
  const upstream = buildUpstream();
  const { policy: enterprisePolicy, hash: policyHash } = resolveEnterprisePolicy();
  const store = new AuditStore(process.env.SENTINEL_STORE, policyHash);
  const approvals = new ApprovalStore(process.env.SENTINEL_APPROVALS);
  const privateStore = new PrivatePackageStore(process.env.SENTINEL_PRIVATE_STORE);
  const publishTokens = (process.env.SENTINEL_PUBLISH_TOKENS ?? "").split(",").map((t) => t.trim()).filter(Boolean);
  // dist/index.js -> ../public ; src is run via tsx with the same relative layout.
  const publicDir = env("SENTINEL_PUBLIC", join(here, "..", "public"));

  const app = createServer({ upstream, store, approvals, enterprisePolicy, policyHash, policy, publicDir, privateStore, publishTokens });
  app.listen(port, () => {
    console.log(`Sentinel proxy listening on http://localhost:${port}`);
    console.log(`  upstream : ${upstream.name}`);
    console.log(`  policy   : ${policy}  (observe = audit+serve, block = 403 on block verdict)`);
    console.log(`  dashboard: http://localhost:${port}/`);
    const claims = enterprisePolicy.privateNamespaces ?? [];
    console.log(`  private  : ${claims.length ? claims.join(", ") : "none"}  (publish ${publishTokens.length ? "enabled" : "disabled"})`);
    console.log(`\nPoint npm at it:  npm install --registry http://localhost:${port}`);
    if (process.env.SENTINEL_BOOT_EXIT) process.exit(0);
  });
}

main();
