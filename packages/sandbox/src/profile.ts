import { SENSITIVE_PATHS, type Capability } from "@sentinel/core";

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

/** Split a path into segments after stripping a leading `~/` or `/`. */
function segments(p: string): string[] {
  return p.replace(/^~?\/?/, "").split("/").filter(Boolean);
}

/**
 * Path-segment-anchored coverage: true iff an approved filesystem target and a deny
 * path share a full segment prefix up to the shorter (one is an ancestor-or-equal of
 * the other). Deliberately NOT a substring match — `ssh` does not cover `.ssh`, and
 * the dynamic `*` capability target covers nothing — so an over-broad/loose approval
 * can't silently cancel an unrelated credential deny.
 */
function pathCovers(approvedTarget: string, denyPath: string): boolean {
  const a = segments(approvedTarget);
  const d = segments(denyPath);
  if (a.length === 0) return false;
  const n = Math.min(a.length, d.length);
  for (let i = 0; i < n; i++) if (a[i] !== d[i]) return false;
  return true;
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
  for (const sp of SENSITIVE_PATHS) {
    // Build the set of denyPaths not covered by approved filesystem targets
    // (path-segment-anchored, never substring).
    const uncovered = sp.denyPaths.filter((dp) => !approvedFs.some((t) => pathCovers(t, dp)));
    if (uncovered.length === 0) continue;
    const items = uncovered.map((dp) => `(${sp.denyKind} "${canonicalizeMacPath(expand(dp))}")`).join(" ");
    lines.push(`(deny file-read* ${items})`);
  }
  if (!hasNetwork) lines.push("(deny network*)");
  return lines.join("\n") + "\n";
}
