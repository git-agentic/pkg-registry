import { resolve } from "node:path";

/**
 * Canonicalize the `cwd` / `projectRoot` a caller hands the sandbox. A relative or dotted value
 * (`.`, `..`) would otherwise reach the profile / mount list verbatim and could expand to
 * `$HOME` or an ancestor. `projectRoot` defaults to `cwd` and is resolved against it; a root of
 * `/` would re-allow every read and exec, so it falls back to `cwd`.
 */
export function normalizeRunPaths(o: { cwd: string; projectRoot?: string }): { cwd: string; projectRoot: string } {
  const cwd = resolve(o.cwd);
  const projectRoot = resolve(cwd, o.projectRoot ?? cwd);
  return { cwd, projectRoot: projectRoot === "/" ? cwd : projectRoot };
}
