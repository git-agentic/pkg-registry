import { sensitivePathsFor, type Capability } from "@git-agentic/sentinel-core";
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
 * Bare `~` (and `~/`) is rejected too (#28): it expands to all of `$HOME` —
 * including the writable write-floor entries under home — re-opening nearly
 * as much as the rejected `/`.
 * A `.` or non-leading empty segment (trailing slash, `//`) is rejected for the same
 * reason as `..`: it normalizes to an ancestor and defeats the strictly-under checks.
 */
export function isSafeGrantTarget(target: string): boolean {
  if (!target || target === "*" || target === "/") return false;
  if (target === "~" || target === "~/") return false; // expands to all of $HOME (#28)
  // A `.` or empty (non-leading) segment lets the path normalize back to an
  // ancestor at mount/rule time (e.g. `~//`, `~/.`, `/home/x/` → $HOME itself),
  // defeating every strictly-under check downstream (#28) — reject fail-closed,
  // same class as `..`.
  const segs = target.split("/");
  return !segs.some((s, i) => s === ".." || s === "." || (s === "" && i > 0));
}

/**
 * The Landlock helper's full exec-allow set (Phase 2 + issue #25): the Linux
 * exec floor PLUS every safe, expanded `process:` PATH grant — the Linux
 * mirror of the darwin branch's floor+grants `execAllowedPaths`. Shared by
 * `BubblewrapSandbox.run` (the helper's `--allow` argv) and `computeDenySet`'s
 * Landlock branch, so the generator and the classifier cannot drift. Pure —
 * no realpath: the helper open()s each entry, so a symlinked grant target
 * already attaches to the resolved node (unlike #21's bind-destination masks).
 */
export function landlockAllowPaths(
  approved: Capability[],
  opts: { homeDir: string; nodePrefix: string; projectRoot: string },
): string[] {
  const grants = approved
    .filter((c) => c.kind === "process")
    .map((c) => c.target)
    .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
    .map((t) => expandHome(t, opts.homeDir));
  return [...linuxExecFloor({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot }), ...grants];
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
  opts: {
    homeDir: string; platform: "darwin" | "linux"; nodePrefix?: string; projectRoot?: string;
    cwd?: string; tmpDir?: string; landlockFloor?: boolean;
    /** resolves symlinks for the Linux path-grant coverage check ONLY (issue #21);
     *  defaults to identity (kept pure for tests). Real callers pass realpathSync-ish. */
    realpath?: (p: string) => string;
  },
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
  // execDeniedPaths stays INVOCATION-FORM literals (the shell prints the invoked
  // path in a denial line, and execCarveOutPaths already enumerates both /bin and
  // /usr/bin forms); `realpath` is used only so the grant-coverage decision agrees
  // with generateBwrapArgs's resolved masking on merged-usr systems (issue #21).
  if (opts.platform === "linux") {
    const lProcTargets = approved.filter((c) => c.kind === "process").map((c) => c.target);
    const lGrantedCmds = new Set(lProcTargets.filter((t) => classifyProcessTarget(t) === "command"));
    const lWildcard = lProcTargets.some((t) => classifyProcessTarget(t) === "wildcard");
    const lPathGrants = lProcTargets
      .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
      .map((p) => expandHome(p, opts.homeDir));
    const lResolve = opts.realpath ?? ((p: string) => p);
    const lResolvedGrants = lPathGrants.map(lResolve);
    const lDenied = lWildcard ? [] : SENSITIVE_EXECUTABLES
      .filter((cmd) => !lGrantedCmds.has(cmd))
      .flatMap((cmd) => execCarveOutPaths(cmd))
      .filter((p) => !lPathGrants.some((g) => pathCovers(g, p)))
      .filter((p) => !lResolvedGrants.some((g) => pathCovers(g, lResolve(p))));
    // Phase 2: when the Landlock exec FLOOR is active, model a real floor so
    // classifyViolation can attribute a floor-outside exec denial. Otherwise the
    // exact Phase 29 shape (carve-out only, no floor).
    if (opts.landlockFloor && opts.nodePrefix && opts.projectRoot) {
      return {
        ...base,
        execDenied: true,
        execDeniedPaths: lDenied,
        execAllowedPaths: landlockAllowPaths(approved, {
          homeDir: opts.homeDir, nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot,
        }),
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
