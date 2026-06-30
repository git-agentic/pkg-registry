import { SENSITIVE_PATHS, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";

/**
 * macOS firmlinks: sandbox-exec matches the canonical /private path, not the alias.
 * /etc, /var, /tmp are firmlinks to /private/etc, /private/var, /private/tmp.
 * This is a pure mapping (no fs calls) — these roots are stable macOS facts.
 */
function canonicalizeMacPath(p: string): string {
  for (const root of ["/etc", "/var", "/tmp"]) {
    if (p === root || p.startsWith(root + "/")) return "/private" + p;
  }
  return p;
}

/**
 * Generate a macOS Seatbelt (SBPL) profile from a package's APPROVED capabilities.
 * Allow-default + targeted-deny (deny-by-default SIGABRTs on dyld). Pure: same
 * inputs ⇒ same string. `homeDir` expands `~`-relative SENSITIVE_PATHS.
 */
export function generateProfile(approved: Capability[], opts: { homeDir: string }): string {
  const expand = (p: string) => (p.startsWith("~") ? opts.homeDir + p.slice(1) : p);
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");

  const lines = ["(version 1)", "(allow default)"];
  const denyFor = (mode: "read" | "write", op: "file-read*" | "file-write*") => {
    for (const sp of SENSITIVE_PATHS) {
      if (!sp.modes.includes(mode)) continue;
      const uncovered = sp.denyPaths.filter((dp) => !approvedFs.some((t) => pathCovers(t, dp)));
      if (uncovered.length === 0) continue;
      const items = uncovered.map((dp) => `(${sp.denyKind} "${canonicalizeMacPath(expand(dp))}")`).join(" ");
      lines.push(`(deny ${op} ${items})`);
    }
  };
  denyFor("read", "file-read*");
  denyFor("write", "file-write*");
  if (!hasNetwork) lines.push("(deny network*)");
  return lines.join("\n") + "\n";
}
