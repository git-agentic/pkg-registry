import type { DenySet } from "./deny-set.js";
import { canonicalizeMacPath } from "./deny-set.js";
import { pathCovers } from "./path-cover.js";
import type { SandboxResult, SandboxViolation } from "./types.js";

// Split into two single-quantifier regexes (was one pattern with two unbounded
// same-class runs, which CodeQL flags as polynomial-ReDoS-prone): a plain
// error-code alternation, and a quoted-path extractor whose only unbounded run
// sits between two literal quotes. Both are linear; a line is an fs-error line
// iff it matches both. `QUOTED_PATH` carries the capture group.
const FS_CODE = /EPERM|EACCES|ENOENT/;
const QUOTED_PATH = /['"]([^'"\n]+)['"]/;
const NET_ERROR = /connect (?:EPERM|EACCES) ([0-9.]+):(\d+)/;
const NET_CLASS = /connect (?:EPERM|EACCES)/;
const PERM_SIGNATURE = /EPERM|EACCES|operation not permitted|permission denied/i;

// Exec-denial shapes (Phase 28, probe-verified — task-2-report.md). A denied
// process-exec* surfaces through /bin/sh in an UNQUOTED "<shell>: <path>: ..."
// line ending in "Operation not permitted" — but the plan's naive assumption that
// "Operation not permitted" sits immediately after the path is only true for a
// direct-binary exec (probe c: "sh: /usr/bin/curl: Operation not permitted"). A
// shebang-script exec (probe b) instead shows an interpreter-resolution wrapper
// BETWEEN the path and the final "Operation not permitted"
// ("sh: <path>: /bin/sh: bad interpreter: Operation not permitted") — so
// firstShExecLine only requires SH_EXEC_PREFIX AND OPERATION_NOT_PERMITTED
// somewhere on the line (checked as two separate linear tests, mirroring the
// FS_CODE + QUOTED_PATH split above — no capture group precedes an unbounded
// greedy run before a literal, avoiding the polynomial-ReDoS shape CodeQL flags),
// and SH_EXEC_PATH separately extracts the FIRST "/…" token after the prefix,
// bounded by the next colon (works for both shapes since the path itself never
// contains a colon). Node's execFileSync/spawnSync reports a denied exec as
// "spawnSync <path> EPERM" (probe d — note the label is spawnSync, not spawn).
const SH_EXEC_PREFIX = /(?:^|[/\s])(?:sh|bash|zsh): /;
const OPERATION_NOT_PERMITTED = /Operation not permitted/i;
const SH_EXEC_PATH = /(?:^|[/\s])(?:sh|bash|zsh): (\/[^:\n]+):/;
const SPAWN_EXEC_PREFIX = /(?:^|\s)spawn(?:Sync)?\s/;
const SPAWN_EXEC_CODE = /EPERM|EACCES/;
const SPAWN_EXEC_PATH = /spawn(?:Sync)?\s+(\/\S+)\s+(?:EPERM|EACCES)/;

// Linux exec-denial (Phase 29, CI-validated). ubuntu /bin/sh is dash: a masked-literal
// exec fails EACCES ("Permission denied"), printed roughly as
// "/bin/sh: <lineno>: <path>: Permission denied" (lineno optional across shells). Two
// linear tests (detect + extract), mirroring the SH_EXEC split, to stay ReDoS-safe.
const LINUX_EXEC_PERM = /[Pp]ermission denied/;
const LINUX_EXEC_PATH = /(?:^|[/\s])(?:sh|bash|dash|zsh): (?:\d+: )?(\/[^:\n]+):/;

function firstMatchingLine(stderr: string, re: RegExp): string | null {
  for (const line of stderr.split(/\r?\n/)) if (re.test(line)) return line.trim();
  return null;
}

/** First stderr line carrying BOTH an fs error code and a quoted path. */
function firstFsErrorLine(stderr: string): string | null {
  for (const line of stderr.split(/\r?\n/)) {
    if (FS_CODE.test(line) && QUOTED_PATH.test(line)) return line.trim();
  }
  return null;
}

/** First stderr line carrying BOTH a shell exec-denial prefix and "Operation not permitted". */
function firstShExecLine(stderr: string): string | null {
  for (const line of stderr.split(/\r?\n/)) {
    if (SH_EXEC_PREFIX.test(line) && OPERATION_NOT_PERMITTED.test(line)) return line.trim();
  }
  return null;
}

/** First stderr line carrying BOTH a spawn(Sync) prefix and an EPERM/EACCES code. */
function firstSpawnExecLine(stderr: string): string | null {
  for (const line of stderr.split(/\r?\n/)) {
    if (SPAWN_EXEC_PREFIX.test(line) && SPAWN_EXEC_CODE.test(line)) return line.trim();
  }
  return null;
}

/** First stderr line carrying BOTH a shell prefix and "Permission denied" (Linux exec-deny). */
function firstLinuxExecLine(stderr: string): string | null {
  for (const line of stderr.split(/\r?\n/)) {
    if (LINUX_EXEC_PATH.test(line) && LINUX_EXEC_PERM.test(line)) return line.trim();
  }
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
  const netLine = firstMatchingLine(stderr, NET_ERROR) ?? firstMatchingLine(stderr, NET_CLASS);
  if (netLine && denySet.networkDenied) {
    const m = NET_ERROR.exec(netLine);
    const target = m ? `${m[1]}:${m[2]}` : null;
    return {
      kind: "network", target,
      confidence: target ? "confirmed" : "suspected",
      deniedResource: target ? "network" : null,
      evidence: { exitCode: result.exitCode, stderrExcerpt: excerpt(netLine) },
    };
  }

  // Linux carve-out (Phase 29): no exec floor — only masked exfil-tool literals are
  // exec-denied. Distinct from the macOS exec branch below (which needs "Operation not
  // permitted" + a floor). Fires only in Linux carve-out mode (execDenied, denied
  // literals, and NO floor modeled), and only ever confirms on a known masked literal —
  // a Permission-denied on anything else falls through (no floor to guess from).
  const linuxCarveMode = !!denySet.execDenied
    && (denySet.execAllowedPaths?.length ?? 0) === 0
    && (denySet.execDeniedPaths?.length ?? 0) > 0;
  if (linuxCarveMode) {
    const line = firstLinuxExecLine(stderr);
    const target = line ? LINUX_EXEC_PATH.exec(line)?.[1] ?? null : null;
    if (line && target) {
      const carved = denySet.execDeniedPaths!.find((p) => p === target || pathCovers(p, target));
      if (carved) {
        return {
          kind: "process", target, confidence: "confirmed", deniedResource: carved,
          evidence: { exitCode: result.exitCode, stderrExcerpt: excerpt(line) },
        };
      }
    }
    // not a masked-literal exec → fall through (no floor to attribute against).
  }

  // Process/exec (Phase 28): a bare "sh: /path: ... Operation not permitted" line is
  // ambiguous between a denied exec and a denied write-redirect — disambiguate via
  // the deny/allow sets. A SENSITIVE-path hit is attributed as filesystem (fs takes
  // precedence, mirroring the fs branch below); a hit on an execDeniedPaths carve-out
  // literal is a confirmed process violation; a hit in a location where exec IS
  // allowed is ambient (null); a hit in a WRITABLE location must be the exec gate
  // (a write can't fail there), so it's confirmed; outside both floors exec-vs-write
  // is genuinely ambiguous → suspected. Only when the profile actually denies exec
  // (execDenied) — legacy/linux DenySets skip this branch entirely.
  const execLine = firstShExecLine(stderr) ?? firstSpawnExecLine(stderr);
  if (execLine && denySet.execDenied) {
    const target = SH_EXEC_PATH.exec(execLine)?.[1] ?? SPAWN_EXEC_PATH.exec(execLine)?.[1] ?? null;
    const evidence = { exitCode: result.exitCode, stderrExcerpt: excerpt(execLine) };
    if (!target) {
      return { kind: "process", target: null, confidence: "suspected", deniedResource: null, evidence };
    }
    // Deny-set path arrays are canonicalized (firmlink roots collapsed to their
    // /private/... form); the shell/node print the UNRESOLVED path in stderr
    // (e.g. /var/folders/... under $TMPDIR). Canonicalize before matching so a
    // dropped-binary exec under $TMPDIR still attributes correctly — the `target`
    // FIELD stays the raw extracted path (better evidence of what actually printed).
    const canonTarget = canonicalizeMacPath(target);
    const sensitive = (denySet.deniedPaths ?? []).find((dp) => pathCovers(dp, canonTarget));
    if (sensitive) {
      return { kind: "filesystem", target, confidence: "confirmed", deniedResource: sensitive, evidence };
    }
    const carved = (denySet.execDeniedPaths ?? []).find((p) => p === canonTarget || pathCovers(p, canonTarget));
    if (carved) {
      return { kind: "process", target, confidence: "confirmed", deniedResource: carved, evidence };
    }
    if ((denySet.execAllowedPaths ?? []).some((p) => pathCovers(p, canonTarget))) return null; // exec allowed there → ambient
    const writable = (denySet.writeAllowedPaths ?? []).some((p) => pathCovers(p, canonTarget));
    // No floor modeled at all (Linux carve-out mode has no exec/write floor to guess
    // from): a permission error outside both floors is genuinely ambient, not
    // suspected. macOS always populates execAllowedPaths, so this never fires there.
    const noFloorModeled =
      (denySet.execAllowedPaths?.length ?? 0) === 0 && (denySet.writeAllowedPaths?.length ?? 0) === 0;
    if (!writable && noFloorModeled) return null;
    return {
      kind: "process",
      target,
      confidence: writable ? "confirmed" : "suspected",
      deniedResource: writable ? "exec-default-deny" : null,
      evidence,
    };
  }

  // Filesystem: attributable path that falls inside a denied path.
  const fsLine = firstFsErrorLine(stderr);
  if (fsLine) {
    const m = QUOTED_PATH.exec(fsLine);
    const target = m?.[1] ?? null;
    // pathCovers is segment-anchored: true iff denied path is an ancestor-or-equal of
    // the hit target. This IS the false-positive filter — an EPERM on a non-denied path
    // matches nothing and returns null (ambient, not our sandbox).
    const matched = target ? (denySet.deniedPaths ?? []).find((dp) => pathCovers(dp, target)) : undefined;
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
