import { SENSITIVE_PATHS, type Capability } from "@sentinel/core";

/**
 * Generate a macOS Seatbelt (SBPL) profile from a package's APPROVED capabilities.
 * Allow-default + targeted-deny (deny-by-default SIGABRTs on dyld). Pure: same
 * inputs ⇒ same string. `homeDir` expands `~`-relative SENSITIVE_PATHS.
 */
export function generateProfile(approved: Capability[], opts: { homeDir: string }): string {
  const expand = (p: string) => (p.startsWith("~") ? opts.homeDir + p.slice(1) : p);
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target.replace(/^~?\/?/, ""));
  const hasNetwork = approved.some((c) => c.kind === "network");

  const lines = ["(version 1)", "(allow default)"];
  for (const sp of SENSITIVE_PATHS) {
    // Build the set of denyPaths not covered by approved filesystem targets.
    const uncovered = sp.denyPaths.filter((dp) => {
      const norm = dp.replace(/^~?\/?/, "");
      return !approvedFs.some((t) => t.length > 0 && (norm.includes(t) || t.includes(norm)));
    });
    if (uncovered.length === 0) continue;
    const items = uncovered.map((dp) => `(${sp.denyKind} "${expand(dp)}")`).join(" ");
    lines.push(`(deny file-read* ${items})`);
  }
  if (!hasNetwork) lines.push("(deny network*)");
  return lines.join("\n") + "\n";
}
