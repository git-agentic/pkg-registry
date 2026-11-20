import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Capability } from "@git-agentic/sentinel-core";

/**
 * The node-gyp header caches (`~/.node-gyp`, `~/.cache/node-gyp`) are READ-ONLY in the sandbox: a
 * writable shared cache lets one package plant headers that a later build trusts. A cold-cache
 * build still needs somewhere to download headers, but only when `network` is approved — then
 * point node-gyp at a fresh per-run dir under tmpdir (inside the write floor, discarded after the
 * run). Without a network approval the env is returned untouched. Trade-off: a network-approved
 * native build re-downloads headers every run instead of reusing the shared cache.
 */
export function withPerRunDevdir(env: NodeJS.ProcessEnv, approved: Capability[]): { env: NodeJS.ProcessEnv; cleanup: () => void } {
  if (!approved.some((c) => c.kind === "network")) return { env, cleanup: () => {} };
  const dir = mkdtempSync(join(tmpdir(), "sentinel-gyp-"));
  return { env: { ...env, npm_config_devdir: dir }, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}
