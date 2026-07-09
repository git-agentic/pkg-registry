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

  const home = opts.homeDir;
  const underHome = (p: string) => p === home || p.startsWith(home + "/");

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

  // 1. rw floor entries NOT under $HOME (e.g. os.tmpdir() / `/tmp`) are bound BEFORE the $HOME
  //    tmpfs. This is load-bearing: if $HOME happens to sit under tmpDir (a hermetic test's fake
  //    home lives under os.tmpdir()), binding tmpDir AFTER the tmpfs would overmount it and
  //    re-expose $HOME. Binding it first lets the tmpfs win for the home subtree.
  for (const p of rw.filter((p) => !underHome(p))) args.push("--bind-try", p, p);
  // 2. Slice 2: empty $HOME → deny its reads (wins over any broad bind above that contains it).
  args.push("--tmpfs", home);
  // 3. read-allow re-exposed READ-ONLY inside the fresh $HOME (project root, node prefix, caches).
  for (const p of ro) args.push("--ro-bind-try", p, p);
  // 4. rw floor entries UNDER $HOME (cwd, ~/.node-gyp, ~/.cache/node-gyp, ~/.npm/_logs, home Grants)
  //    re-bound READ-WRITE on top — the narrow rw cwd bind wins over the broad ro project bind.
  for (const p of rw.filter(underHome)) args.push("--bind-try", p, p);

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
