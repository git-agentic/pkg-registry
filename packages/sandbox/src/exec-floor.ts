/**
 * The fixed set of subpaths where process-exec is allowed WITHOUT a `process`
 * Grant under exec-deny-by-default (Phase 28, ADR-0042). Pure — the caller
 * canonicalizes. Deliberately NOT operator-configurable (same stance as the
 * Phase 25 write floor): widening it silently reopens the dropped-binary class.
 *
 * `projectRoot` is included by decision — `node_modules/.bin` shims and local
 * build scripts must run without approvals. The residual (a package can write
 * a binary into its own tree and exec it) is recorded in ADR-0042; what this
 * floor kills is exec from ANY writable-but-not-project location (/tmp, caches,
 * ~/Downloads, …).
 */
export function execAllowFloor(opts: { nodePrefix: string; projectRoot: string }): string[] {
  return [
    "/bin",
    "/usr/bin",
    "/usr/sbin",
    opts.nodePrefix,          // the node runtime itself (nvm/fnm/volta under $HOME included)
    opts.projectRoot,         // node_modules/.bin shims, local scripts
    "/Library/Developer",     // CommandLineTools (node-gyp → make/cc)
    "/Applications/Xcode.app",
    "/opt/homebrew",          // Homebrew (arm64)
    "/usr/local",             // Homebrew (Intel), user-installed tools
  ];
}
