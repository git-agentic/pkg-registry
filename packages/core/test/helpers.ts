import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
/** packages/core/test -> repo root */
export const REPO_ROOT = join(HERE, "..", "..", "..");
export const FIXTURES = join(REPO_ROOT, "fixtures");

/** Ensure the fixture tarballs + registry.json exist (build once if needed). */
export function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], {
    cwd: REPO_ROOT,
    stdio: "ignore",
  });
}

export function tarball(name: string, version: string): Buffer {
  return readFileSync(join(FIXTURES, ".tarballs", `${name}-${version}.tgz`));
}
