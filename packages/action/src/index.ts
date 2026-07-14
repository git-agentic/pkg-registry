#!/usr/bin/env node
import { readFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { NpmUpstream, LocalFixtureUpstream, type Upstream } from "@git-agentic/sentinel-proxy";
import { loadPolicy, DEFAULT_POLICY, type EnterprisePolicy } from "@git-agentic/sentinel-core";
import { runCi } from "./run.js";

function env(name: string, fallback = ""): string {
  return process.env[name] ?? fallback;
}

/** Load a signed policy when INPUT_POLICY is set (reuses core's loadPolicy); else DEFAULT_POLICY. */
function resolvePolicy(): EnterprisePolicy {
  const file = env("INPUT_POLICY");
  if (!file) return DEFAULT_POLICY;
  // Falsy fallback (not `??`): action.yml always injects INPUT_POLICY_SIG, as "" when the
  // `policy-sig` input is defaulted — so an empty string must fall through to `<policy>.sig`.
  const sig = env("INPUT_POLICY_SIG") || `${file}.sig`;
  const pub = env("INPUT_POLICY_PUBKEY");
  if (!pub) throw new Error("INPUT_POLICY requires INPUT_POLICY_PUBKEY (path to the signer's public key PEM)");
  return loadPolicy({ file, sig, publicKeyPem: readFileSync(pub, "utf8") }).policy;
}

function pickUpstream(): Upstream {
  // Test-only escape hatch: force fixtures so bin e2e stays hermetic.
  const fx = env("SENTINEL_CI_FIXTURES");
  if (fx) return new LocalFixtureUpstream(fx);
  return new NpmUpstream(env("SENTINEL_REGISTRY", "https://registry.npmjs.org"));
}

async function main(): Promise<void> {
  const failOnRaw = env("INPUT_FAIL_ON", "block");
  const failOn = (["block", "warn", "none"] as const).includes(failOnRaw as never) ? (failOnRaw as "block" | "warn" | "none") : "block";
  const cwd = env("INPUT_WORKING_DIRECTORY") || process.cwd();
  const result = await runCi({
    upstream: pickUpstream(),
    cwd,
    lockfile: env("INPUT_LOCKFILE") || undefined,
    policy: resolvePolicy(),
    sbomPath: env("INPUT_SBOM_PATH", "sentinel-sbom.json"),
    failOn,
    omitDev: env("INPUT_OMIT_DEV") === "true",
    now: new Date().toISOString(),
    env: process.env,
  });
  process.exit(result.exitCode);
}

// Run only when invoked as the entrypoint (bin shim or `node dist/index.js`),
// never on import — the same guard as @git-agentic/sentinel-proxy and @git-agentic/sentinel-mcp.
function isEntrypoint(): boolean {
  const arg = process.argv[1];
  if (!arg) return false;
  try { return import.meta.url === pathToFileURL(realpathSync(arg)).href; } catch { return false; }
}
if (isEntrypoint()) {
  main().catch((err) => {
    console.error(`::error::sentinel-ci failed: ${(err as Error).message}`);
    process.exit(1);
  });
}
