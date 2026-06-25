import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
/** packages/core/test -> repo root */
export const REPO_ROOT = join(HERE, "..", "..", "..");
export const FIXTURES = join(REPO_ROOT, "fixtures");

/**
 * Ensure the fixture tarballs + registry.json exist. Rebuilds when EITHER the
 * registry doc or the (gitignored) `.tarballs` are absent — e.g. a fresh clone has
 * the committed registry.json but no tarballs. The build is deterministic
 * (see scripts/make-fixtures.ts), so a rebuild reproduces the committed integrities.
 */
export function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], {
    cwd: REPO_ROOT,
    stdio: "ignore",
  });
}

export function tarball(name: string, version: string): Buffer {
  return readFileSync(join(FIXTURES, ".tarballs", `${name}-${version}.tgz`));
}
