#!/usr/bin/env node
import { homedir } from "node:os";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { createSandbox, scrubEnv } from "@sentinel/sandbox";
import type { SandboxViolation } from "@sentinel/sandbox";
import type { Capability } from "@sentinel/core";
import { approvedCapsForManifest, isRootScript, commandFromArgv, EnforceError } from "./enforce.js";
import { parseApprovals } from "./index.js";
import type { Manifest } from "./format.js";

/**
 * Best-effort telemetry: reports a detected runtime violation to the proxy so it can be
 * surfaced/aggregated. Resolves the served integrity from the dependency's proxy manifest
 * (the shell doesn't otherwise know it). Never throws — a reporting failure (unreachable
 * proxy, non-ok response, malformed JSON) must never change the install's exit code.
 */
export async function reportViolation(
  proxy: string,
  name: string,
  version: string,
  violation: SandboxViolation,
): Promise<void> {
  try {
    const man = await fetch(`${proxy}/-/manifest/${encodeURIComponent(name)}/${encodeURIComponent(version)}`);
    if (!man.ok) return;
    const integrity = ((await man.json()) as { meta?: { integrity?: string } }).meta?.integrity;
    if (!integrity) return;
    await fetch(`${proxy}/-/violations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name, version, integrity, ...violation }),
    });
  } catch {
    /* telemetry is best-effort: a reporting failure never changes the install outcome */
  }
}

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
  if (r.violation && process.env.SENTINEL_PROXY && name && version && !isRootScript(cwd, process.env.INIT_CWD)) {
    await reportViolation(process.env.SENTINEL_PROXY, name, version, r.violation);
  }
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  return r.exitCode;
}

// Only auto-run when invoked as the CLI entrypoint (not on `import` for unit testing, e.g.
// reportViolation above) — argv[1] is the invoked script path; compare it to this module's URL.
// Both sides are resolved through the real path first so a bin-symlink invocation (npx /
// node_modules/.bin) — where argv[1] is the symlink but import.meta.url resolves to the real
// file — still compares equal, instead of silently failing to run (fail-open).
function isMainModule(): boolean {
  const arg = process.argv[1];
  if (!arg) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(arg)).href;
  } catch {
    return false;
  }
}

if (isMainModule()) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      const tag = err instanceof EnforceError ? "enforcement" : "error";
      console.error(`\x1b[31msentinel-script-shell (${tag}): ${(err as Error).message}\x1b[0m`);
      process.exit(70);   // non-zero → npm aborts the install (fail closed)
    },
  );
}
