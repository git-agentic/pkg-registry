import { resolve } from "node:path";

/**
 * Canonicalize the `cwd` / `projectRoot` a caller hands the sandbox. A relative or dotted value
 * (`.`, `..`) would otherwise reach the profile / mount list verbatim and could expand to
 * `$HOME` or an ancestor. `projectRoot` defaults to `cwd` and is resolved against it; a root of
 * `/` would re-allow every read and exec, so it falls back to `cwd`.
 */
export function normalizeRunPaths(o: { cwd: string; projectRoot?: string }): { cwd: string; projectRoot: string } {
  assertCwdNotRoot(o.cwd);
  const cwd = resolve(o.cwd);
  const projectRoot = resolve(cwd, o.projectRoot ?? cwd);
  return { cwd, projectRoot: projectRoot === "/" ? cwd : projectRoot };
}

/**
 * `cwd` is always in the write floor, so a working directory of `/` would open writes
 * everywhere. Refuse it with the backends' unsupported-setup error rather than run (called by
 * both entry points and by both generators, so no profile or argv is ever produced for it).
 */
export function assertCwdNotRoot(cwd: string): void {
  if (resolve(cwd) === "/") {
    throw new Error("sandbox enforcement unavailable: the working directory resolves to / (it would put the filesystem root in the write floor) — run from the project directory");
  }
}
