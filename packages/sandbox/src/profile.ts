import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";
import { canonicalizeMacPath, expandHome } from "./deny-set.js";

/**
 * Generate a macOS Seatbelt (SBPL) profile from a package's APPROVED capabilities.
 * Allow-default + targeted-deny (deny-by-default SIGABRTs on dyld). Pure: same
 * inputs ⇒ same string. `homeDir` expands `~`-relative SENSITIVE_PATHS.
 */
export function generateProfile(approved: Capability[], opts: { homeDir: string }): string {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");

  const lines = ["(version 1)", "(allow default)"];
  const denyFor = (mode: "read" | "write", op: "file-read*" | "file-write*") => {
    for (const sp of sensitivePathsFor("darwin")) {
      if (!sp.modes.includes(mode)) continue;
      const uncovered = sp.denyPaths.filter((dp) => !approvedFs.some((t) => pathCovers(t, dp)));
      if (uncovered.length === 0) continue;
      const items = uncovered.map((dp) => `(${sp.denyKind} "${canonicalizeMacPath(expandHome(dp, opts.homeDir))}")`).join(" ");
      lines.push(`(deny ${op} ${items})`);
    }
  };
  denyFor("read", "file-read*");
  denyFor("write", "file-write*");
  if (!hasNetwork) lines.push("(deny network*)");
  return lines.join("\n") + "\n";
}
