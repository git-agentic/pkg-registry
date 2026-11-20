import { chmodSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { Capability } from "@git-agentic/sentinel-core";

/**
 * The node-gyp header caches (`~/.node-gyp`, `~/.cache/node-gyp`) are READ-ONLY in the sandbox: a
 * writable shared cache lets one package plant headers that a later build trusts. A cold-cache
 * build still needs somewhere to download headers, but only when `network` is approved — then
 * point node-gyp at a fresh per-run dir and grant read-write on THAT dir alone, through the same
 * filesystem-grant mechanism approvals use (so it works identically under Seatbelt and bwrap).
 *
 * The dir lives under a host-owned `<home>/.cache/sentinel-gyp` (mode 0700), NOT under tmpdir:
 * tmpdir is in every sandbox's write floor, so a process left over from an earlier run could still
 * write into (poison) a dir created there. Outside every floor, only this run's grant can write it.
 * Without a network approval — or if the dir cannot be created — the env and grants are returned
 * unchanged (the build then falls back to the read-only caches). Trade-off: a network-approved
 * native build re-downloads headers every run.
 */
export function withPerRunDevdir(
  env: NodeJS.ProcessEnv, approved: Capability[], homeDir: string,
): { env: NodeJS.ProcessEnv; approved: Capability[]; cleanup: () => void } {
  const none = { env, approved, cleanup: () => {} };
  if (!approved.some((c) => c.kind === "network")) return none;
  try {
    const parent = join(homeDir, ".cache", "sentinel-gyp");
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    chmodSync(parent, 0o700);
    const dir = mkdtempSync(join(parent, "run-"));   // mkdtemp creates 0700
    return {
      env: { ...env, npm_config_devdir: dir },
      approved: [...approved, { kind: "filesystem", target: dir, evidence: [] }],
      cleanup: () => rmSync(dir, { recursive: true, force: true }),
    };
  } catch {
    return none;
  }
}
