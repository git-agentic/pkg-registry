/**
 * Canonical credential/secret filesystem locations. The single source shared by
 * the `secret-exfil` rule (which detects reads of them in code via `detectRe`) and
 * the sandbox profile generator (which denies `denyPaths`), so detection and
 * enforcement can never drift. `~`-prefixed paths are home-relative.
 */
export interface SensitivePath {
  label: string;
  /** Absolute or `~`-relative paths the sandbox denies reading. */
  denyPaths: string[];
  /** Seatbelt path filter kind for these denyPaths. */
  denyKind: "literal" | "subpath";
  /** Code-detection regex for `secret-exfil`; omit for deny-only (broader sandbox) paths. */
  detectRe?: RegExp;
}

export const SENSITIVE_PATHS: SensitivePath[] = [
  // The four with detectRe reproduce secret-exfil's historical file-path patterns:
  { label: "npm auth token (~/.npmrc)", denyPaths: ["~/.npmrc"], denyKind: "literal", detectRe: /\.npmrc|_authToken/ },
  { label: "AWS credentials file", denyPaths: ["~/.aws"], denyKind: "subpath", detectRe: /\.aws\/credentials|\.aws\\credentials/ },
  { label: "SSH private keys", denyPaths: ["~/.ssh"], denyKind: "subpath", detectRe: /\.ssh\/id_|id_rsa|id_ed25519/ },
  { label: "system account files", denyPaths: ["/etc/passwd", "/etc/shadow"], denyKind: "literal", detectRe: /\/etc\/passwd|\/etc\/shadow/ },
  // Deny-only entries (sandbox blocks; secret-exfil does not separately detect them):
  { label: "GnuPG keyring", denyPaths: ["~/.gnupg"], denyKind: "subpath" },
  { label: "netrc credentials", denyPaths: ["~/.netrc"], denyKind: "literal" },
  { label: "git credentials", denyPaths: ["~/.git-credentials"], denyKind: "literal" },
  { label: "Docker config", denyPaths: ["~/.docker/config.json"], denyKind: "literal" },
  { label: "Kubernetes config", denyPaths: ["~/.kube"], denyKind: "subpath" },
];
