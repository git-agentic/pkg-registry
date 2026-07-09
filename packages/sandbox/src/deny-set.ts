import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";

/** The concrete resources the sandbox profile denies, for runtime-violation attribution. */
export interface DenySet {
  /** Expanded, canonicalized (darwin) absolute paths the profile denies. */
  deniedPaths: string[];
  /** True when the profile denies all network (no approved `network` capability). */
  networkDenied: boolean;
}

/**
 * Expand a `~`-relative path against homeDir. An absolute path passes through
 * unchanged; a bare-relative path (no leading `~` or `/`) — the convention
 * approved-capability `filesystem` targets use, e.g. `.npmrc` or `.config/app`
 * meaning `~/.npmrc` — is treated as home-relative too (Phase 25, ADR-0038:
 * needed so a Grant can become a concrete absolute `allow` path, not just a
 * segment-matched deny-canceller).
 */
export function expandHome(p: string, homeDir: string): string {
  if (p.startsWith("~")) return homeDir + p.slice(1);
  if (p.startsWith("/")) return p;
  return homeDir + "/" + p;
}

/**
 * macOS firmlinks: sandbox-exec matches the canonical /private path, not the alias.
 * /etc, /var, /tmp are firmlinks to /private/etc, /private/var, /private/tmp.
 * Pure mapping (no fs calls) — these roots are stable macOS facts.
 */
export function canonicalizeMacPath(p: string): string {
  for (const root of ["/etc", "/var", "/tmp"]) {
    if (p === root || p.startsWith(root + "/")) return "/private" + p;
  }
  return p;
}

/**
 * The deny set the sandbox profile enforces, for classifying a runtime violation.
 * Mirrors `generateProfile`/`generateBwrapArgs`: a SENSITIVE_PATHS entry is denied
 * unless an approved filesystem capability covers it; network is denied unless an
 * approved `network` capability is present. Pure: same inputs ⇒ same DenySet.
 */
export function computeDenySet(
  approved: Capability[],
  opts: { homeDir: string; platform: "darwin" | "linux" },
): DenySet {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const networkDenied = !approved.some((c) => c.kind === "network");
  const deniedPaths: string[] = [];
  for (const sp of sensitivePathsFor(opts.platform)) {
    for (const dp of sp.denyPaths) {
      if (approvedFs.some((t) => pathCovers(t, dp))) continue;
      const expanded = expandHome(dp, opts.homeDir);
      deniedPaths.push(opts.platform === "darwin" ? canonicalizeMacPath(expanded) : expanded);
    }
  }
  return { deniedPaths, networkDenied };
}
