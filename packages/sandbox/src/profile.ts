import { sensitivePathsFor, type Capability } from "@agentic-sentinel/core";
import { pathCovers } from "./path-cover.js";
import { canonicalizeMacPath, expandHome, isSafeGrantTarget } from "./deny-set.js";
import { writeAllowFloor } from "./write-floor.js";
import { readAllowList } from "./read-allow.js";
import { execAllowFloor } from "./exec-floor.js";
import { SENSITIVE_EXECUTABLES, execCarveOutPaths, classifyProcessTarget } from "./sensitive-executables.js";

/**
 * Generate a macOS Seatbelt (SBPL) profile from a package's APPROVED capabilities.
 * Reads are DENY-BY-DEFAULT inside `$HOME` (Phase 25 Slice 2): a blanket
 * `(deny file-read* (subpath $HOME))`, then an `(allow file-read-metadata ...)`
 * so traversal (lstat/stat) still works, then the read-allow list re-allows data
 * reads under the node prefix / project root / build caches — with the
 * SENSITIVE_PATHS read-denies as a final carve-out. Writes are DENY-BY-DEFAULT
 * (Phase 25 Slice 1): a blanket `(deny file-write*)` then re-allow the write
 * floor + approved-filesystem Grants. SBPL is last-match-wins, so allow forms
 * follow their blanket deny. Pure: same inputs ⇒ same string.
 */
export function generateProfile(
  approved: Capability[],
  opts: { homeDir: string; cwd: string; tmpDir: string; nodePrefix: string; projectRoot: string },
): string {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");
  const canon = (p: string) => canonicalizeMacPath(expandHome(p, opts.homeDir));

  const lines = ["(version 1)", "(allow default)"];

  // Reads: deny $HOME by default (Slice 2). Then allow METADATA (lstat/stat) across
  // $HOME so node can TRAVERSE it to reach the read-allowed project tree underneath —
  // a blanket `file-read*` deny also denies lstat, which breaks require()'s path
  // resolution (probe-verified: without this line, `require()` fails EPERM lstat on
  // $HOME itself). Data reads stay denied except the read-allow list — the node
  // install prefix (node-under-$HOME loads its stdlib), the project root (require()
  // resolves the tree), and the build caches. System paths stay readable via (allow
  // default). The metadata allow is deliberately BELOW the deny and ABOVE the
  // read-allow (SBPL last-match-wins: metadata everywhere in $HOME, data only in the
  // allow-list).
  lines.push(`(deny file-read* (subpath "${canon(opts.homeDir)}"))`);
  lines.push(`(allow file-read-metadata (subpath "${canon(opts.homeDir)}"))`);
  const homeCanon = canon(opts.homeDir);
  const readAllow = readAllowList({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot }).map(canon);
  // Guard: never re-allow $HOME itself or an ancestor of $HOME (e.g. a projectRoot
  // that resolved to $HOME) — that would nullify the Slice 2 read-deny wholesale.
  const readAllowSafe = readAllow.filter((e) => e !== homeCanon && !homeCanon.startsWith(e + "/"));
  // Approved filesystem Grants confer read+write (a Grant opens exactly that
  // resource), so they belong in the read-allow too — mirrors the write section
  // below, which reuses this same `grants` declaration.
  const grants = approvedFs.filter(isSafeGrantTarget).map(canon);
  lines.push(`(allow file-read* ${[...readAllowSafe, ...grants].map((p) => `(subpath "${p}")`).join(" ")})`);

  // SENSITIVE read carve-out (last-match-wins): re-deny credential paths even if
  // they fell under a re-allow, and deny /etc/passwd + /etc/shadow (which live in
  // read-allowed /etc). A directional Grant covering the path lifts its deny.
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
  const allowItems = [...floor, ...grants].map((p) => `(subpath "${p}")`).join(" ");
  lines.push(`(allow file-write* ${allowItems})`);
  for (const sp of sensitivePathsFor("darwin")) {
    if (!sp.modes.includes("write")) continue;
    const uncovered = sp.denyPaths.filter((dp) => !approvedFs.some((t) => pathCovers(t, dp)));
    if (uncovered.length === 0) continue;
    const items = uncovered.map((dp) => `(${sp.denyKind} "${canon(dp)}")`).join(" ");
    lines.push(`(deny file-write* ${items})`);
  }

  // Exec: deny by default (Phase 28, ADR-0042) — blanket deny, re-allow the fixed
  // exec floor + approved process PATH-Grants, then re-deny the sensitive-executable
  // carve-out (SBPL last-match-wins) unless a command/wildcard/covering-path Grant
  // lifts it. process-fork stays allowed: only exec is gated. The initial
  // sandbox-exec → /bin/sh exec is itself covered by /bin in the floor.
  const procTargets = approved.filter((c) => c.kind === "process").map((c) => c.target);
  const grantedCmds = new Set(procTargets.filter((t) => classifyProcessTarget(t) === "command"));
  const execWildcard = procTargets.some((t) => classifyProcessTarget(t) === "wildcard");
  const execPathGrants = procTargets
    .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
    .map(canon);
  lines.push("(deny process-exec*)");
  const execFloor = execAllowFloor({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot }).map(canon);
  lines.push(`(allow process-exec* ${[...execFloor, ...execPathGrants].map((p) => `(subpath "${p}")`).join(" ")})`);
  const carveItems = execWildcard ? [] : SENSITIVE_EXECUTABLES
    .filter((cmd) => !grantedCmds.has(cmd))
    .flatMap((cmd) => execCarveOutPaths(cmd))
    .map(canon)
    .filter((p) => !execPathGrants.some((g) => pathCovers(g, p)));
  if (carveItems.length > 0) {
    lines.push(`(deny process-exec* ${carveItems.map((p) => `(literal "${p}")`).join(" ")})`);
  }

  if (!hasNetwork) lines.push("(deny network*)");
  return lines.join("\n") + "\n";
}
