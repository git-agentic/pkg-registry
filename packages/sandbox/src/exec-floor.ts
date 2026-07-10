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

/**
 * The Linux exec floor: the shared `execAllowFloor` PLUS the dynamic-linker and
 * shared-library directories. Landlock's `LANDLOCK_ACCESS_FS_EXECUTE` gates
 * `mmap(PROT_EXEC)` as well as `execve`, so a dynamically-linked binary's ELF
 * interpreter (`/lib64/ld-linux-*`) and its libraries must be exec-granted or the
 * binary can't start — verified by the Phase 2 feasibility spike (the first CI run
 * failed precisely because these were omitted). macOS does NOT need these (dylib
 * loading is file-read there, not process-exec), so they live here, not in
 * `execAllowFloor`. Pure. The macOS-only entries `execAllowFloor` returns
 * (`/Library/Developer`, …) are harmless on Linux — the helper skips an `--allow`
 * path that doesn't exist.
 */
export function linuxExecFloor(opts: { nodePrefix: string; projectRoot: string }): string[] {
  return [...execAllowFloor(opts), "/lib", "/lib64", "/usr/lib", "/usr/lib64"];
}
