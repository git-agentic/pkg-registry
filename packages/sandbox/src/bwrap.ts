import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";

/**
 * Generate `bwrap` argv from a package's APPROVED capabilities, replicating the macOS
 * allow-default + targeted-deny model on Linux (probe-verified on Ubuntu 24.04):
 *   - allow-default read+write     → `--bind / /` (+ `--dev /dev --proc /proc`)
 *   - credential DIR  (subpath)    → `--tmpfs <path>`        (content masked, writes discarded)
 *   - credential FILE (literal)    → `--ro-bind /dev/null <path>` (read empty, write EPERM)
 *   - network deny                 → `--unshare-net`
 * Both mask mechanics are robust to a nonexistent target and cover read AND write, so the
 * read/write `modes` distinction is not needed here. An approved `filesystem`/`network`
 * capability omits the corresponding deny (same `pathCovers` semantics as the SBPL side).
 * Pure: same inputs ⇒ same argv. No firmlink canonicalization (Linux has no firmlinks).
 */
export function generateBwrapArgs(approved: Capability[], opts: { homeDir: string }): string[] {
  const expand = (p: string) => (p.startsWith("~") ? opts.homeDir + p.slice(1) : p);
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");

  const args = ["--bind", "/", "/", "--dev", "/dev", "--proc", "/proc"];
  for (const sp of sensitivePathsFor("linux")) {
    for (const dp of sp.denyPaths) {
      if (approvedFs.some((t) => pathCovers(t, dp))) continue;
      const target = expand(dp);
      if (sp.denyKind === "subpath") args.push("--tmpfs", target);
      else args.push("--ro-bind", "/dev/null", target);
    }
  }
  if (!hasNetwork) args.push("--unshare-net");
  return args;
}
