/**
 * Canonical credential/secret filesystem locations. The single source shared by
 * the `secret-exfil` rule (which detects reads of them in code via `detectRe`) and
 * the sandbox profile generator (which denies `denyPaths` and enforces `modes`), so detection and
 * enforcement can never drift. `~`-prefixed paths are home-relative.
 */
export interface SensitivePath {
  label: string;
  /** Absolute or `~`-relative paths the sandbox denies. */
  denyPaths: string[];
  /** Seatbelt path filter kind for these denyPaths. */
  denyKind: "literal" | "subpath";
  /** Which access is dangerous: "read" → file-read* deny, "write" → file-write* deny. */
  modes: ("read" | "write")[];
  /** Code-detection regex for `secret-exfil`; omit for deny-only paths. */
  detectRe?: RegExp;
  /** Which OS this entry applies to; absent ⇒ both. Backends filter via sensitivePathsFor(). */
  platforms?: ("darwin" | "linux")[];
}

export const SENSITIVE_PATHS: SensitivePath[] = [
  // Credential reads (also worth blocking writes — overwrite/inject is tamper):
  { label: "npm auth token (~/.npmrc)", denyPaths: ["~/.npmrc"], denyKind: "literal", modes: ["read", "write"], detectRe: /\.npmrc|_authToken/ },
  { label: "AWS credentials file", denyPaths: ["~/.aws"], denyKind: "subpath", modes: ["read", "write"], detectRe: /\.aws\/credentials|\.aws\\credentials/ },
  { label: "SSH private keys", denyPaths: ["~/.ssh"], denyKind: "subpath", modes: ["read", "write"], detectRe: /\.ssh\/id_|id_rsa|id_ed25519/ },
  { label: "system account files", denyPaths: ["/etc/passwd", "/etc/shadow"], denyKind: "literal", modes: ["read", "write"], detectRe: /\/etc\/passwd|\/etc\/shadow/ },
  { label: "GnuPG keyring", denyPaths: ["~/.gnupg"], denyKind: "subpath", modes: ["read", "write"] },
  { label: "netrc credentials", denyPaths: ["~/.netrc"], denyKind: "literal", modes: ["read", "write"] },
  { label: "git credentials", denyPaths: ["~/.git-credentials"], denyKind: "literal", modes: ["read", "write"] },
  { label: "Docker config", denyPaths: ["~/.docker/config.json"], denyKind: "literal", modes: ["read", "write"] },
  { label: "Kubernetes config", denyPaths: ["~/.kube"], denyKind: "subpath", modes: ["read", "write"] },

  // Persistence / tamper targets — write-only (no secret to read; the threat is dropping
  // an autostart payload or appending to a startup file):
  { label: "shell rc (~/.zshrc)", denyPaths: ["~/.zshrc"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.zshenv)", denyPaths: ["~/.zshenv"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.bashrc)", denyPaths: ["~/.bashrc"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.bash_profile)", denyPaths: ["~/.bash_profile"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.profile)", denyPaths: ["~/.profile"], denyKind: "literal", modes: ["write"] },
  // Linux persistence vectors are home-based: an unprivileged install script cannot write to the
  // system cron spool (/var/spool/cron/crontabs is root-owned mode 1730), and bwrap cannot create
  // that root-owned mountpoint unprivileged — attempting to do so aborts the sandbox with
  // "Can't mkdir parents … Permission denied". The meaningful Linux persistence vectors are all
  // home-dir paths (XDG autostart, systemd user units), which bwrap mounts without issue.
  { label: "XDG autostart", denyPaths: ["~/.config/autostart"], denyKind: "subpath", modes: ["write"], platforms: ["linux"] },
  { label: "systemd user units (~/.config/systemd/user)", denyPaths: ["~/.config/systemd/user"], denyKind: "subpath", modes: ["write"], platforms: ["linux"] },
  { label: "systemd user units (~/.local/share/systemd/user)", denyPaths: ["~/.local/share/systemd/user"], denyKind: "subpath", modes: ["write"], platforms: ["linux"] },
  { label: "user LaunchAgents", denyPaths: ["~/Library/LaunchAgents"], denyKind: "subpath", modes: ["write"], platforms: ["darwin"] },
  { label: "user LaunchDaemons", denyPaths: ["~/Library/LaunchDaemons"], denyKind: "subpath", modes: ["write"], platforms: ["darwin"] },
  { label: "system LaunchAgents", denyPaths: ["/Library/LaunchAgents"], denyKind: "subpath", modes: ["write"], platforms: ["darwin"] },
  { label: "system LaunchDaemons", denyPaths: ["/Library/LaunchDaemons"], denyKind: "subpath", modes: ["write"], platforms: ["darwin"] },
  { label: "crontab spool (macOS)", denyPaths: ["/var/at/tabs"], denyKind: "subpath", modes: ["write"], platforms: ["darwin"] },
];

/** SENSITIVE_PATHS applicable to `platform` (entries with no `platforms` tag apply to both). */
export function sensitivePathsFor(platform: "darwin" | "linux"): SensitivePath[] {
  return SENSITIVE_PATHS.filter((sp) => !sp.platforms || sp.platforms.includes(platform));
}
