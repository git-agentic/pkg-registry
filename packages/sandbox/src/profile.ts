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
 *
 * NOTE — descendant-covers-ancestor side-effect: an approval for a path INSIDE a
 * `subpath` deny (e.g. `--approve filesystem:.ssh/config`) currently cancels the
 * ENTIRE `~/.ssh` deny, not just the single file. This is operator-gated (an attacker
 * cannot supply `--approve`), so it is not an immediate security issue. It is a
 * candidate for future tightening: a descendant approval should not be allowed to lift
 * an ancestor `subpath` deny — only an approval for the ancestor itself (or a wider
 * path) should do so.
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
