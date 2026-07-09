import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";
import { expandHome, isSafeGrantTarget } from "./deny-set.js";
import { writeAllowFloor } from "./write-floor.js";

/**
 * Generate `bwrap` argv from a package's APPROVED capabilities. Phase 25 Slice 1:
 * root is mounted READ-ONLY (`--ro-bind / /`) so reads still work while writes are
 * denied by default; the write floor + approved-filesystem Grants are re-bound
 * read-write on top (`--bind-try`, tolerant of a not-yet-created cache dir).
 * Credential-read masks (unchanged from before) and `--unshare-net` follow.
 * Pure: same inputs ⇒ same argv. No firmlink canonicalization (Linux).
 *
 * `pathExists` gates which SENSITIVE_PATHS masks are emitted. Under the read-only
 * root, bwrap must CREATE each mask's mount point, which it cannot do when the
 * mask's parent dir is read-only (i.e. a real `$HOME` not under the writable
 * floor) — bwrap aborts. A path that does not exist has nothing to mask (and,
 * under write-deny, a read-denied location cannot be created during the run), so
 * we skip it. The runner injects `existsSync`; the pure argv tests omit it (⇒
 * all masks emitted, deterministic).
 */
export function generateBwrapArgs(
  approved: Capability[],
  opts: { homeDir: string; cwd: string; tmpDir: string; pathExists?: (p: string) => boolean; nodePrefix: string; projectRoot: string },
): string[] {
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");

  // Read-only root + writable floor/grants on top.
  const args = ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"];
  const floor = writeAllowFloor({ cwd: opts.cwd, tmpDir: opts.tmpDir });
  // `--dev /dev` (above) already provides a writable, ISOLATED /dev. Binding host
  // /dev here would overmount that isolated devtmpfs with the real host device
  // tree read-write (bwrap: later mount wins) — re-exposing every host device
  // node. So drop /dev from the rw binds; the floor keeps it only for Seatbelt,
  // which has no --dev equivalent (ADR-0038).
  const rw = [...floor, ...approvedFs.filter(isSafeGrantTarget)]
    .map((p) => expandHome(p, opts.homeDir))
    .filter((p) => p !== "/dev");
  for (const p of rw) args.push("--bind-try", p, p);

  // SENSITIVE_PATHS masks, applied AFTER the floor binds so they win for any
  // overlapping path (a bwrap tmpfs/ro-bind-devnull mask denies both read and
  // write). This preserves credential-read protection (Slice 1 leaves reads
  // open otherwise) AND carves persistence write targets back out of the floor —
  // so `~/.zshrc` stays denied even when the test's fake $HOME sits under the
  // floor's temp dir. A Grant covering the path skips its mask.
  const exists = opts.pathExists ?? (() => true);
  for (const sp of sensitivePathsFor("linux")) {
    for (const dp of sp.denyPaths) {
      if (approvedFs.some((t) => pathCovers(t, dp))) continue;
      const target = expandHome(dp, opts.homeDir);
      if (!exists(target)) continue; // bwrap can't create a mask mount point under a read-only parent
      if (sp.denyKind === "subpath") args.push("--tmpfs", target);
      else args.push("--ro-bind", "/dev/null", target);
    }
  }

  if (!hasNetwork) args.push("--unshare-net");
  return args;
}
