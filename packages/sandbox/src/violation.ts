import type { DenySet } from "./deny-set.js";
import { pathCovers } from "./path-cover.js";
import type { SandboxResult, SandboxViolation } from "./types.js";

const FS_ERROR = /(?:EPERM|EACCES|ENOENT)[^\n]*?['"]([^'"\n]+)['"]/;
const NET_ERROR = /connect (?:EPERM|EACCES) ([0-9.]+):(\d+)/;
const NET_CLASS = /connect (?:EPERM|EACCES)/;
const PERM_SIGNATURE = /EPERM|EACCES|operation not permitted|permission denied/i;

function firstMatchingLine(stderr: string, re: RegExp): string | null {
  for (const line of stderr.split(/\r?\n/)) if (re.test(line)) return line.trim();
  return null;
}

function excerpt(line: string): string {
  return line.length > 200 ? line.slice(0, 199) + "…" : line;
}

/**
 * Infer a runtime violation from a sandboxed child's failure. Pure and total:
 * returns null when there is no surfacing permission-error signal. The deny set is
 * ground truth — a permission error on a resource we did NOT deny is ambient, not a
 * violation (the false-positive filter). Only detects violations that SURFACE as
 * process failure; a swallowed denial (exit 0, clean stderr) is invisible here but
 * still contained by the sandbox.
 */
export function classifyViolation(result: SandboxResult, denySet: DenySet): SandboxViolation | null {
  if (result.exitCode === 0) return null;
  const stderr = result.stderr ?? "";
  if (!PERM_SIGNATURE.test(stderr)) return null;

  // Network: attributable host:port, or class-denied suspected.
  const netLine = firstMatchingLine(stderr, NET_CLASS);
  if (netLine && denySet.networkDenied) {
    const m = NET_ERROR.exec(stderr);
    const target = m ? `${m[1]}:${m[2]}` : null;
    return {
      kind: "network", target,
      confidence: target ? "confirmed" : "suspected",
      deniedResource: target ? "network" : null,
      evidence: { exitCode: result.exitCode, stderrExcerpt: excerpt(netLine) },
    };
  }

  // Filesystem: attributable path that falls inside a denied path.
  const fsLine = firstMatchingLine(stderr, FS_ERROR);
  if (fsLine) {
    const m = FS_ERROR.exec(fsLine);
    const target = m?.[1] ?? null;
    // pathCovers is segment-anchored: true iff denied path is an ancestor-or-equal of
    // the hit target. This IS the false-positive filter — an EPERM on a non-denied path
    // matches nothing and returns null (ambient, not our sandbox).
    const matched = target ? denySet.deniedPaths.find((dp) => pathCovers(dp, target)) : undefined;
    if (target && matched) {
      return {
        kind: "filesystem", target, confidence: "confirmed", deniedResource: matched,
        evidence: { exitCode: result.exitCode, stderrExcerpt: excerpt(fsLine) },
      };
    }
    // A permission error on a path we didn't deny → ambient, not our sandbox.
    return null;
  }

  return null;
}
