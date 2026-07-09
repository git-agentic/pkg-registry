import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";
import { expandHome, isSafeGrantTarget } from "./deny-set.js";
import { writeAllowFloor } from "./write-floor.js";
import { readAllowList } from "./read-allow.js";

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
  opts: { homeDir: string; cwd: string; tmpDir: string; nodePrefix: string; projectRoot: string; pathExists?: (p: string) => boolean },
): string[] {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");
  const exists = opts.pathExists ?? (() => true);

  const args = ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"];

  // Slice 2 reads: empty $HOME (deny its reads), then re-expose the read-allow list ro.
  args.push("--tmpfs", opts.homeDir);
  for (const ro of readAllowList({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot })) {
    const target = expandHome(ro, opts.homeDir);
    // Guard: never re-open $HOME itself or an ancestor of $HOME (e.g. a projectRoot
    // that resolved to $HOME) — that would nullify the Slice 2 `--tmpfs $HOME` above.
    if (target === opts.homeDir || opts.homeDir.startsWith(target + "/")) continue;
    args.push("--ro-bind-try", target, target); // -try: node-gyp/cache dirs may be absent
  }

  // Slice 1 writes: re-bind the write floor + Grants READ-WRITE on top (narrow wins over
  // the broad ro project bind above; `--dev /dev` already provides an isolated writable /dev,
  // so drop host /dev from the rw binds — re-binding it would re-expose the host device tree).
  const floor = writeAllowFloor({ cwd: opts.cwd, tmpDir: opts.tmpDir });
  const rw = [...floor, ...approvedFs.filter(isSafeGrantTarget)]
    .map((p) => expandHome(p, opts.homeDir))
    .filter((p) => p !== "/dev");
  for (const p of rw) args.push("--bind-try", p, p);

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

  if (!hasNetwork) args.push("--unshare-net");
  return args;
}
