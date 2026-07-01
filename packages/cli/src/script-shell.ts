#!/usr/bin/env node
import { homedir } from "node:os";
import { createSandbox, scrubEnv } from "@sentinel/sandbox";
import type { Capability } from "@sentinel/core";
import { approvedCapsForManifest, isRootScript, commandFromArgv, EnforceError } from "./enforce.js";
import { parseApprovals } from "./index.js";
import type { Manifest } from "./format.js";

/**
 * npm invokes this as the lifecycle script-shell: `sentinel-script-shell -c "<cmd>"`, with cwd set
 * to the package's directory and the full npm env present. It runs <cmd> under createSandbox() with
 * the package's APPROVED capabilities and a scrubbed env. Fail-closed: any inability to guarantee
 * containment exits non-zero, which aborts the npm install. NEVER runs <cmd> unsandboxed.
 */
async function main(): Promise<number> {
  if (process.env.SENTINEL_ENFORCE !== "1") {
    throw new EnforceError("sentinel-script-shell invoked without SENTINEL_ENFORCE=1 (refusing to act as a shell)");
  }
  const cmd = commandFromArgv(process.argv.slice(2));
  const cwd = process.cwd();
  const name = process.env.npm_package_name;
  const version = process.env.npm_package_version;

  let approved: Capability[];
  if (isRootScript(cwd, process.env.INIT_CWD)) {
    // The install root's own scripts: operator-supplied approvals only (default: none → strict).
    approved = parseApprovals((process.env.SENTINEL_APPROVE ?? "").split(/\s+/).filter(Boolean));
  } else {
    // A dependency's script: resolve approved capabilities from its proxy manifest (fail closed if unapproved).
    const proxy = process.env.SENTINEL_PROXY;
    if (!proxy || !name || !version) {
      throw new EnforceError(`cannot resolve approvals for dependency script (proxy/name/version missing)`);
    }
    const res = await fetch(`${proxy}/-/manifest/${encodeURIComponent(name)}/${encodeURIComponent(version)}`);
    if (!res.ok) throw new EnforceError(`manifest fetch failed for ${name}@${version}: ${res.status}`);
    approved = approvedCapsForManifest((await res.json()) as Manifest);
  }

  const env = scrubEnv(process.env, approved);
  const sandbox = createSandbox();   // throws (fail closed) on unsupported platform / missing bwrap
  const r = sandbox.run(cmd, { cwd, approved, homeDir: homedir(), env });
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  return r.exitCode;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    const tag = err instanceof EnforceError ? "enforcement" : "error";
    console.error(`\x1b[31msentinel-script-shell (${tag}): ${(err as Error).message}\x1b[0m`);
    process.exit(70);   // non-zero → npm aborts the install (fail closed)
  },
);
