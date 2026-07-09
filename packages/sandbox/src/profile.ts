import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";
import { canonicalizeMacPath, expandHome, isSafeGrantTarget } from "./deny-set.js";
import { writeAllowFloor } from "./write-floor.js";

/**
 * Generate a macOS Seatbelt (SBPL) profile from a package's APPROVED capabilities.
 * Reads stay allow-default minus the SENSITIVE_PATHS read-denies (Slice 2 will
 * invert reads). Writes are DENY-BY-DEFAULT (Phase 25 Slice 1): a blanket
 * `(deny file-write*)` then re-allow the write floor + approved-filesystem Grants.
 * SBPL is last-match-wins, so the allow forms follow the blanket deny. Pure:
 * same inputs ⇒ same string.
 */
export function generateProfile(
  approved: Capability[],
  opts: { homeDir: string; cwd: string; tmpDir: string; nodePrefix: string; projectRoot: string },
): string {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");
  const canon = (p: string) => canonicalizeMacPath(expandHome(p, opts.homeDir));

  const lines = ["(version 1)", "(allow default)"];

  // Reads: unchanged from before Phase 25 — deny each SENSITIVE read path not
  // covered by an approved (directional) Grant.
  for (const sp of sensitivePathsFor("darwin")) {
    if (!sp.modes.includes("read")) continue;
    const uncovered = sp.denyPaths.filter((dp) => !approvedFs.some((t) => pathCovers(t, dp)));
    if (uncovered.length === 0) continue;
    const items = uncovered.map((dp) => `(${sp.denyKind} "${canon(dp)}")`).join(" ");
    lines.push(`(deny file-read* ${items})`);
  }

  // Writes: deny by default, re-allow the floor + approved Grants, then carve
  // the SENSITIVE_PATHS write targets back OUT (SBPL last-match-wins) so a
  // persistence path is denied even if it sits under an allowed ancestor —
  // unless an approved Grant explicitly covers it. The carve-out is what makes
  // persistence protection robust (and hermetically testable, since a test's
  // fake $HOME lives under os.tmpdir(), which is in the floor).
  lines.push("(deny file-write*)");
  const floor = writeAllowFloor({ cwd: opts.cwd, tmpDir: opts.tmpDir }).map(canon);
  const grants = approvedFs.filter(isSafeGrantTarget).map(canon);
  const allowItems = [...floor, ...grants].map((p) => `(subpath "${p}")`).join(" ");
  lines.push(`(allow file-write* ${allowItems})`);
  for (const sp of sensitivePathsFor("darwin")) {
    if (!sp.modes.includes("write")) continue;
    const uncovered = sp.denyPaths.filter((dp) => !approvedFs.some((t) => pathCovers(t, dp)));
    if (uncovered.length === 0) continue;
    const items = uncovered.map((dp) => `(${sp.denyKind} "${canon(dp)}")`).join(" ");
    lines.push(`(deny file-write* ${items})`);
  }

  if (!hasNetwork) lines.push("(deny network*)");
  return lines.join("\n") + "\n";
}
