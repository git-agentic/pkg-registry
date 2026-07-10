/**
 * Exfil-capable commands re-denied AFTER the exec floor allow (Phase 28,
 * ADR-0042) unless a `process` Grant lifts them — the exec analog of
 * SENSITIVE_PATHS' carve-out-after-floor. Static and fixed: candidates are
 * enumerated across the floor's bin dirs with NO PATH resolution, so the
 * profile generator stays pure and deterministic.
 */
export const SENSITIVE_EXECUTABLES: readonly string[] = [
  "curl", "wget",             // arbitrary-egress download/upload
  "nc", "ncat", "socat",      // raw sockets / reverse shells
  "osascript",                // AppleScript automation (keychain prompts, UI scripting)
  "scp", "sftp",              // file exfil over ssh
];

/** Bin dirs (all inside the exec floor) where a sensitive executable may reside. */
const EXEC_BIN_DIRS = ["/bin", "/usr/bin", "/opt/homebrew/bin", "/usr/local/bin"];

/** Fixed candidate literals for one command across the floor's bin dirs. Pure. */
export function execCarveOutPaths(cmd: string): string[] {
  return EXEC_BIN_DIRS.map((d) => `${d}/${cmd}`);
}

/**
 * A `process` Grant target's shape (spec §Grant semantics): a target containing
 * `/` (or starting with `~`) is a PATH Grant (appended to the exec allow); a
 * bare word is a COMMAND Grant (lifts that command's carve-out literals only);
 * `*` (the detector's target for a bare child_process import) lifts the entire
 * carve-out but opens no non-floor paths.
 */
export function classifyProcessTarget(target: string): "command" | "path" | "wildcard" {
  if (target === "*") return "wildcard";
  if (target.startsWith("~") || target.includes("/")) return "path";
  return "command";
}
