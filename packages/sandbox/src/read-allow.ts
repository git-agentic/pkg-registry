import { existsSync } from "node:fs";
import { dirname, isAbsolute, parse } from "node:path";

/**
 * The in-`$HOME` read-allow list under Phase 25 Slice 2 `$HOME`-read-deny (ADR-0038).
 * System paths stay readable via the backends' allow-default / `--ro-bind / /`; this
 * covers what lives *inside* `$HOME`: the node install prefix (so a node-under-`$HOME`
 * runtime — nvm/fnm/volta — can load its stdlib), the project root (so a lifecycle
 * script's `require()` resolves across the project tree), and the build caches. Pure;
 * callers expand `~` and canonicalize.
 */
export function readAllowList(opts: { nodePrefix: string; projectRoot: string }): string[] {
  return [opts.nodePrefix, opts.projectRoot, "~/.node-gyp", "~/.cache"];
}

/** The node runtime's install prefix: `dirname(dirname(execPath))` (…/prefix/bin/node → …/prefix). */
export function nodeInstallPrefix(execPath: string): string {
  return dirname(dirname(execPath));
}

/**
 * The project root a lifecycle script resolves `require()` against — distinct from the
 * Install directory (`cwd`, deep in `node_modules`). npm sets `INIT_CWD` to the install's
 * originating dir (the project root); trust it when it's an absolute path. Otherwise walk
 * up from `cwd` to the nearest ancestor with a `package.json`; failing that, use `cwd`.
 */
export function resolveProjectRoot(cwd: string, initCwd: string | undefined): string {
  if (initCwd && isAbsolute(initCwd)) return initCwd;
  let dir = cwd;
  for (;;) {
    if (existsSync(`${dir}/package.json`)) return dir;
    const parent = dirname(dir);
    if (parent === dir || parent === parse(dir).root) return existsSync(`${parent}/package.json`) ? parent : cwd;
    dir = parent;
  }
}
