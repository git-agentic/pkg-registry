import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";
import { expandHome, isSafeGrantTarget } from "./deny-set.js";
import { writeAllowFloor } from "./write-floor.js";
import { readAllowList } from "./read-allow.js";
import { SENSITIVE_EXECUTABLES, execCarveOutPaths, classifyProcessTarget } from "./sensitive-executables.js";

/**
 * Generate `bwrap` argv from a package's APPROVED capabilities (Phase 25).
 * Slice 1: root read-only (`--ro-bind / /`) → writes denied by default, floor +
 * Grants re-bound read-write. Slice 2: `$HOME` reads denied by default — empty it
 * with `--tmpfs` — then re-bind the read-allow list read-only (node prefix so a
 * node-under-$HOME runtime loads its stdlib; project root so `require()` resolves)
 * and re-apply the write floor read-write ON TOP (a broad ro project bind must
 * precede the narrow rw `cwd` bind, or `cwd` becomes read-only). SENSITIVE masks
 * carve out last. `pathExists` gates masks whose mount point may be absent.
 * Pure: same inputs ⇒ same argv.
 */
export function generateBwrapArgs(
  approved: Capability[],
  opts: {
    homeDir: string; cwd: string; tmpDir: string; nodePrefix: string; projectRoot: string;
    pathExists?: (p: string) => boolean;
    /** resolves symlinks; defaults to identity (kept pure for tests). Real callers pass realpathSync-ish. */
    realpath?: (p: string) => string;
  },
): string[] {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");
  const exists = opts.pathExists ?? (() => true);
  const resolve = opts.realpath ?? ((p: string) => p);

  const home = opts.homeDir;
  // `p` is an ancestor-or-equal of $HOME (i.e. it CONTAINS $HOME) — e.g. tmpDir when a
  // hermetic test's fake $HOME lives under os.tmpdir().
  const containsHome = (p: string) => p === home || home.startsWith(p + "/");

  const args = ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"];

  // Slice 1 rw set (write floor + guarded Grants), expanded; host /dev excluded (`--dev /dev`
  // already provides an isolated writable /dev — re-binding host /dev re-exposes the device tree).
  const rw = [...writeAllowFloor({ cwd: opts.cwd, tmpDir: opts.tmpDir }), ...approvedFs.filter(isSafeGrantTarget)]
    .map((p) => expandHome(p, home))
    .filter((p) => p !== "/dev");
  // Slice 2 read-allow, expanded; guard against re-opening $HOME itself or an ancestor
  // (e.g. a projectRoot that resolved to $HOME) — that would nullify the `--tmpfs $HOME`.
  const ro = readAllowList({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot })
    .map((p) => expandHome(p, home))
    .filter((p) => p !== home && !home.startsWith(p + "/"));

  // 1. rw floor entries that CONTAIN $HOME (an ancestor like tmpDir when $HOME ⊂ tmpDir) are
  //    bound BEFORE the $HOME tmpfs, so the tmpfs wins for the home subtree. Load-bearing: a
  //    hermetic test's fake $HOME lives under os.tmpdir(), which the floor binds — binding it
  //    AFTER the tmpfs would overmount and re-expose $HOME. (In production $HOME ⊄ tmpDir, so
  //    this pass is usually empty.)
  for (const p of rw.filter(containsHome)) args.push("--bind-try", p, p);
  // 2. Slice 2: empty $HOME → deny its reads (wins over any ancestor bind above).
  args.push("--tmpfs", home);
  // 3. read-allow re-exposed READ-ONLY inside the fresh $HOME (project root, node prefix, caches).
  for (const p of ro) args.push("--ro-bind-try", p, p);
  // 4. every OTHER rw entry (cwd, caches, home Grants, and tmpDir when it isn't an ancestor of
  //    $HOME) re-bound READ-WRITE AFTER the read-allow — so the narrow rw cwd bind wins over the
  //    broad ro project bind (projectRoot ⊇ cwd) and cwd stays writable.
  for (const p of rw.filter((p) => !containsHome(p))) args.push("--bind-try", p, p);

  // SENSITIVE masks — carve-outs applied last (a bwrap tmpfs / ro-bind-devnull mask denies
  // read AND write). Skip an absent mount point (bwrap can't create it under a ro parent).
  for (const sp of sensitivePathsFor("linux")) {
    for (const dp of sp.denyPaths) {
      if (approvedFs.some((t) => pathCovers(t, dp))) continue;
      const target = expandHome(dp, opts.homeDir);
      if (!exists(target)) continue;
      if (sp.denyKind === "subpath") args.push("--tmpfs", target);
      else args.push("--ro-bind", "/dev/null", target);
    }
  }

  // Exfil-tool carve-out (Phase 29): mask each SENSITIVE_EXECUTABLES literal with
  // /dev/null so exec of it fails (execve on a non-regular file → EACCES), unless an
  // approved `process:` Grant covers it. Reuses the SENSITIVE-read mask pattern above.
  // There is NO exec FLOOR on Linux — bwrap can't path-gate exec (advisory by decision,
  // ADR-0043); only these known literals are exec-denied.
  const procTargets = approved.filter((c) => c.kind === "process").map((c) => c.target);
  const grantedCmds = new Set(procTargets.filter((t) => classifyProcessTarget(t) === "command"));
  const execWildcard = procTargets.some((t) => classifyProcessTarget(t) === "wildcard");
  const execPathGrants = procTargets
    .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
    .map((p) => expandHome(p, home));
  if (!execWildcard) {
    // Distro-merged-usr dirs (e.g. Debian/Ubuntu's `/bin` → `/usr/bin` symlink) mean a
    // literal like `/bin/nc` isn't itself a creatable bind-mount destination — bwrap
    // doesn't follow symlinked ancestors when materializing a mount point there, so
    // `--ro-bind /dev/null /bin/nc` can fail with ENOENT even though the file "exists"
    // (through the symlink). Resolve each candidate to its real path first so the mask
    // always targets an actual mount-able node, and dedupe so a merged-usr pair like
    // `/bin/nc` + `/usr/bin/nc` (same real file) isn't masked twice.
    const maskedReal = new Set<string>();
    for (const cmd of SENSITIVE_EXECUTABLES) {
      if (grantedCmds.has(cmd)) continue;
      for (const lit of execCarveOutPaths(cmd)) {
        if (execPathGrants.some((g) => pathCovers(g, lit))) continue;
        if (!exists(lit)) continue;
        const real = resolve(lit);
        if (maskedReal.has(real)) continue;
        maskedReal.add(real);
        args.push("--ro-bind", "/dev/null", real);
      }
    }
  }

  if (!hasNetwork) args.push("--unshare-net");
  return args;
}
