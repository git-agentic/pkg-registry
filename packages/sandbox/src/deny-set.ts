import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";
import { execAllowFloor, linuxExecFloor } from "./exec-floor.js";
import { SENSITIVE_EXECUTABLES, execCarveOutPaths, classifyProcessTarget } from "./sensitive-executables.js";
import { writeAllowFloor } from "./write-floor.js";

/** The concrete resources the sandbox profile denies, for runtime-violation attribution. */
export interface DenySet {
  /** Expanded, canonicalized (darwin) absolute paths the profile denies. */
  deniedPaths: string[];
  /** True when the profile denies all network (no approved `network` capability). */
  networkDenied: boolean;
  /** true when the profile denies exec by default (darwin + exec opts present) */
  execDenied?: boolean;
  /** floor + safe process path-Grants, expanded + canonicalized */
  execAllowedPaths?: string[];
  /** uncovered carve-out literals, canonicalized */
  execDeniedPaths?: string[];
  /** the write floor, expanded + canonicalized (disambiguates exec vs write denials) */
  writeAllowedPaths?: string[];
  /** "linux-landlock" when the Linux exec FLOOR is enforced (Landlock helper active); absent otherwise */
  execFloorMode?: "linux-landlock";
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
 * Guard a positive write Grant target (Phase 25, ADR-0038). Under deny-by-default an
 * approved `filesystem:` target becomes a positive allow, so a pathological target
 * would widen the writable set far beyond intent. Reject the escape/everything cases
 * fail-closed (drop the grant → the write stays denied): an empty/`*` target, a bare
 * root `/`, or any target containing a `..` path-traversal segment.
 */
export function isSafeGrantTarget(target: string): boolean {
  if (!target || target === "*" || target === "/") return false;
  return !target.split("/").includes("..");
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
  opts: { homeDir: string; platform: "darwin" | "linux"; nodePrefix?: string; projectRoot?: string; cwd?: string; tmpDir?: string; landlockFloor?: boolean },
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
  const base: DenySet = { deniedPaths, networkDenied };

  // Linux exec (Phase 29): carve-out only — no floor (bwrap can't path-gate exec,
  // ADR-0043). Mirror generateBwrapArgs's /dev/null masks: the masked exfil-tool
  // literals are the exec-deny set; execAllowedPaths/writeAllowedPaths are intentionally
  // absent so classifyViolation only ever confirms on a masked literal (never the macOS
  // floor guess). Paths are NOT firmlink-canonicalized on Linux.
  if (opts.platform === "linux") {
    const lProcTargets = approved.filter((c) => c.kind === "process").map((c) => c.target);
    const lGrantedCmds = new Set(lProcTargets.filter((t) => classifyProcessTarget(t) === "command"));
    const lWildcard = lProcTargets.some((t) => classifyProcessTarget(t) === "wildcard");
    const lPathGrants = lProcTargets
      .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
      .map((p) => expandHome(p, opts.homeDir));
    const lDenied = lWildcard ? [] : SENSITIVE_EXECUTABLES
      .filter((cmd) => !lGrantedCmds.has(cmd))
      .flatMap((cmd) => execCarveOutPaths(cmd))
      .filter((p) => !lPathGrants.some((g) => pathCovers(g, p)));
    // Phase 2: when the Landlock exec FLOOR is active, model a real floor so
    // classifyViolation can attribute a floor-outside exec denial. Otherwise the
    // exact Phase 29 shape (carve-out only, no floor).
    if (opts.landlockFloor && opts.nodePrefix && opts.projectRoot) {
      return {
        ...base,
        execDenied: true,
        execDeniedPaths: lDenied,
        execAllowedPaths: linuxExecFloor({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot }),
        execFloorMode: "linux-landlock",
      };
    }
    return { ...base, execDenied: lDenied.length > 0, execDeniedPaths: lDenied };
  }

  // Exec gating (Phase 28, darwin only) — MUST mirror generateProfile's exec
  // section exactly (the non-drift test enforces this).
  if (!opts.nodePrefix || !opts.projectRoot) return base;
  const canon = (p: string) => canonicalizeMacPath(expandHome(p, opts.homeDir));
  const procTargets = approved.filter((c) => c.kind === "process").map((c) => c.target);
  const grantedCmds = new Set(procTargets.filter((t) => classifyProcessTarget(t) === "command"));
  const execWildcard = procTargets.some((t) => classifyProcessTarget(t) === "wildcard");
  const execPathGrants = procTargets
    .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
    .map(canon);
  const execAllowedPaths = [
    ...execAllowFloor({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot }).map(canon),
    ...execPathGrants,
  ];
  const execDeniedPaths = execWildcard ? [] : SENSITIVE_EXECUTABLES
    .filter((cmd) => !grantedCmds.has(cmd))
    .flatMap((cmd) => execCarveOutPaths(cmd))
    .map(canon)
    .filter((p) => !execPathGrants.some((g) => pathCovers(g, p)));
  const writeAllowedPaths = opts.cwd && opts.tmpDir
    ? writeAllowFloor({ cwd: opts.cwd, tmpDir: opts.tmpDir }).map(canon)
    : [];
  return { ...base, execDenied: true, execAllowedPaths, execDeniedPaths, writeAllowedPaths };
}
