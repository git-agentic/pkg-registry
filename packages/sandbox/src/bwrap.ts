import { sensitivePathsFor, type Capability } from "@git-agentic/sentinel-core";
import { pathCovers } from "./path-cover.js";
import { expandHome, isSafeGrantTarget } from "./deny-set.js";
import { writeAllowFloor } from "./write-floor.js";
import { readAllowList } from "./read-allow.js";
import { SENSITIVE_EXECUTABLES, execCarveOutPaths, classifyProcessTarget } from "./sensitive-executables.js";

/** Pathname unix sockets that hand out host control (container runtimes, the system bus). */
const IPC_SOCKETS = [
  "/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
  "/run/podman/podman.sock", "/run/crio/crio.sock", "/run/dbus/system_bus_socket",
];

/**
 * Generate `bwrap` argv from a package's APPROVED capabilities (Phase 25).
 * Slice 1: root read-only (`--ro-bind / /`) → writes denied by default, floor +
 * Grants re-bound read-write. Slice 2: `$HOME` reads denied by default — empty it
 * with `--tmpfs` — then re-bind the read-allow list read-only (node prefix so a
 * node-under-$HOME runtime loads its stdlib; project root so `require()` resolves)
 * and re-apply the write floor read-write ON TOP (a broad ro project bind must
 * precede the narrow rw `cwd` bind, or `cwd` becomes read-only). SENSITIVE masks
 * carve out last. `pathExists` gates masks whose mount point may be absent.
 * Approved process: path grants strictly under $HOME re-bind read-only beside the
 * read-allow (issue #28).
 * Pure: same inputs ⇒ same argv.
 */
export function generateBwrapArgs(
  approved: Capability[],
  opts: {
    homeDir: string; cwd: string; tmpDir: string; nodePrefix: string; projectRoot: string;
    pathExists?: (p: string) => boolean;
    /** resolves symlinks; defaults to identity (kept pure for tests). Real callers pass realpathSync-ish. */
    realpath?: (p: string) => string;
    /** Extra read-only paths re-opened alongside the Slice 2 read-allow list — e.g. the
     * Landlock helper's own directory (Phase 2), which can land under $HOME on a CI
     * checkout and would otherwise be hidden by the `--tmpfs $HOME` deny even though
     * it's neither the node prefix nor the project root. */
    extraReadAllow?: string[];
    /** uid whose `/run/user/<uid>` is emptied; defaults to `process.getuid()`. */
    uid?: number;
    /** Names of the directories under `dir` (for the `/tmp/ssh-*` masks); defaults to none (kept pure for tests). */
    listDirs?: (dir: string) => string[];
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

  // --unshare-pid: own pid namespace, so `--proc /proc` shows only the sandbox's processes (a host
  // /proc leaks other users' env/cmdlines). --die-with-parent: no orphan outlives the run.
  // --new-session: setsid, so a script cannot inject keystrokes into the controlling tty (TIOCSTI).
  const args = ["--unshare-pid", "--die-with-parent", "--new-session", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"];

  // Slice 1 rw set (write floor + guarded Grants), expanded; host /dev excluded (`--dev /dev`
  // already provides an isolated writable /dev — re-binding host /dev re-exposes the device tree).
  const rw = [...writeAllowFloor({ cwd: opts.cwd, tmpDir: opts.tmpDir }), ...approvedFs.filter(isSafeGrantTarget)]
    .map((p) => expandHome(p, home))
    .filter((p) => p !== "/dev");

  // process: targets — computed BEFORE the mounts because path grants under $HOME
  // feed the ro re-binds below (issue #28), not just the Phase 29 mask loop.
  const procTargets = approved.filter((c) => c.kind === "process").map((c) => c.target);
  const grantedCmds = new Set(procTargets.filter((t) => classifyProcessTarget(t) === "command"));
  const execWildcard = procTargets.some((t) => classifyProcessTarget(t) === "wildcard");
  const execPathGrants = procTargets
    .filter((t) => classifyProcessTarget(t) === "path" && isSafeGrantTarget(t))
    .map((p) => expandHome(p, home));

  // Slice 2 read-allow, expanded; guard against re-opening $HOME itself or an ancestor
  // (e.g. a projectRoot that resolved to $HOME) — that would nullify the `--tmpfs $HOME`.
  const ro = [...readAllowList({ nodePrefix: opts.nodePrefix, projectRoot: opts.projectRoot }), ...(opts.extraReadAllow ?? [])]
    .map((p) => expandHome(p, home))
    .filter((p) => p !== "/" && p !== home && !home.startsWith(p + "/"));

  // issue #28: a process: path grant STRICTLY UNDER $HOME must be re-exposed inside
  // the tmpfs (read-only — exec permission is Landlock's job, and bwrap has no noexec)
  // or its exec fails ENOENT before Landlock is consulted. Outside-home grants are
  // already visible via the ro root bind; $HOME itself or an ancestor is excluded by
  // the strictly-under filter (re-binding it would nullify the tmpfs).
  const roGrants = execPathGrants.filter((p) => p.startsWith(home + "/"));

  // 1. rw floor entries that CONTAIN $HOME (an ancestor like tmpDir when $HOME ⊂ tmpDir) are
  //    bound BEFORE the $HOME tmpfs, so the tmpfs wins for the home subtree. Load-bearing: a
  //    hermetic test's fake $HOME lives under os.tmpdir(), which the floor binds — binding it
  //    AFTER the tmpfs would overmount and re-expose $HOME. (In production $HOME ⊄ tmpDir, so
  //    this pass is usually empty.)
  for (const p of rw.filter(containsHome)) args.push("--bind-try", p, p);
  // 2. Slice 2: empty $HOME → deny its reads (wins over any ancestor bind above).
  args.push("--tmpfs", home);
  // 3. read-allow re-exposed READ-ONLY inside the fresh $HOME (project root, node prefix, caches).
  for (const p of [...ro, ...roGrants]) args.push("--ro-bind-try", p, p);
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
  if (!execWildcard) {
    // Distro-merged-usr dirs (e.g. Debian/Ubuntu's `/bin` → `/usr/bin` symlink) mean a
    // literal like `/bin/nc` isn't itself a creatable bind-mount destination — bwrap
    // doesn't follow symlinked ancestors when materializing a mount point there, so
    // `--ro-bind /dev/null /bin/nc` can fail with ENOENT even though the file "exists"
    // (through the symlink). Resolve each candidate to its real path first so the mask
    // always targets an actual mount-able node, and dedupe so a merged-usr pair like
    // `/bin/nc` + `/usr/bin/nc` (same real file) isn't masked twice.
    // A PATH grant must agree with that resolution (issue #21): compare grants and
    // candidates in resolved space too, or a grant on /usr/bin/curl is defeated by
    // its ungranted /bin/curl sibling resolving back onto the same inode.
    // Accepted residual: resolution makes the lift depend on live symlink state — a
    // grant target the package can rewrite into a dir symlink would lift every mask
    // under it. Operator-gated (needs an approved writable process: grant), same
    // class as ADR-0042/0044's projectRoot-in-floor residual.
    const resolvedGrants = execPathGrants.map(resolve);
    const maskedReal = new Set<string>();
    for (const cmd of SENSITIVE_EXECUTABLES) {
      if (grantedCmds.has(cmd)) continue;
      for (const lit of execCarveOutPaths(cmd)) {
        if (execPathGrants.some((g) => pathCovers(g, lit))) continue;
        if (!exists(lit)) continue;
        const real = resolve(lit);
        if (resolvedGrants.some((g) => pathCovers(g, real))) continue;
        if (maskedReal.has(real)) continue;
        maskedReal.add(real);
        args.push("--ro-bind", "/dev/null", real);
      }
    }
  }

  // Local IPC masks. A `network` approval means the network, NOT local IPC: pathname unix
  // sockets stay reachable through the ro root bind (and --unshare-net would not hide them
  // anyway), and the container runtime socket or the user session bus (`systemd-run --user`) is
  // a full escape. So these apply with or without network; only an explicit filesystem grant
  // covering the path lifts one. Each only when present (bwrap cannot create a mount point
  // under a ro parent), and never when it would hide the cwd / project root / $HOME.
  const liftedByGrant = (p: string) => approvedFs.some((t) => pathCovers(t, p));
  const hidesWorkdir = (p: string) => [opts.cwd, opts.projectRoot, home].some((d) => pathCovers(p, d));
  const sockets = new Set<string>();
  for (const sock of IPC_SOCKETS) {
    if (liftedByGrant(sock) || !exists(sock)) continue;
    sockets.add(resolve(sock)); // /var/run is usually a symlink to /run: mask the real node once
  }
  for (const real of sockets) args.push("--ro-bind", "/dev/null", real);
  const uid = opts.uid ?? process.getuid?.();
  const runUser = uid === undefined ? undefined : `/run/user/${uid}`;
  if (runUser && exists(runUser) && !liftedByGrant(runUser) && !hidesWorkdir(runUser)) args.push("--tmpfs", runUser);
  // X11 and ssh-agent socket directories under /tmp: AFTER the rw /tmp bind above, or the
  // bind would overmount the tmpfs.
  const tmpMasks = new Set<string>();
  for (const root of new Set(["/tmp", opts.tmpDir])) {
    const names = [".X11-unix", ...(opts.listDirs?.(root) ?? []).filter((n) => n.startsWith("ssh-"))];
    for (const n of names) tmpMasks.add(`${root}/${n}`);
  }
  for (const m of tmpMasks) {
    if (exists(m) && !liftedByGrant(m) && !hidesWorkdir(m)) args.push("--tmpfs", m);
  }
  if (!hasNetwork) args.push("--unshare-net");
  return args;
}
