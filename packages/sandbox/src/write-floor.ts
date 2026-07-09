/**
 * The baseline set of writable locations every sandboxed lifecycle script gets
 * under write-deny-by-default (Phase 25, ADR-0038). Pure — the caller expands
 * `~` (via homeDir) and canonicalizes. A FIXED floor, deliberately not operator-
 * configurable: widening it silently reopens the persistence class. Per-package
 * needs are met by approved `filesystem:` Grants instead.
 *
 * `/dev` is here because a blanket `file-write*` deny otherwise blocks
 * `2>/dev/null` and other device writes that ordinary scripts rely on.
 */
export function writeAllowFloor(opts: { cwd: string; tmpDir: string }): string[] {
  return [
    opts.cwd,            // the Install directory — build output lands here
    opts.tmpDir,         // os.tmpdir() — build tools stage here
    "/tmp",              // firmlink → /private/tmp on macOS (caller canonicalizes)
    "/dev",              // /dev/null, /dev/stdout, ttys
    "~/.node-gyp",       // node-gyp downloaded headers
    "~/.cache/node-gyp", // node-gyp cache (XDG)
    "~/.npm/_logs",      // npm lifecycle logs
  ];
}
