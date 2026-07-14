import type { Capability } from "@git-agentic/sentinel-core";

/** Env-var names that look credential-bearing — dropped regardless of allowlist match. */
export const CREDENTIAL_ENV_RE = /_auth|authtoken|_password|passwd|token|secret|credential|api[_-]?key|access[_-]?key/i;

/**
 * Fail-closed env allowlist for sandboxed lifecycle scripts. Pass ONLY these; any other
 * var — including a novel-named credential — is dropped. Validated against a real `npm
 * install` lifecycle env (ADR-0017/0019). The load-bearing behavior is the DROP of operator-shell
 * secrets (SSH_AUTH_SOCK, AWS_*, *_TOKEN); the narrowed npm_* sub-groups carry the vars a lifecycle
 * script needs on the `install --enforce` path (npm is the invoker there), and any credential-shaped
 * `npm_config_*` is screened out by CREDENTIAL_ENV_RE (ADR-0019).
 */
export const ENV_ALLOWLIST = {
  // Narrowed npm sub-groups a lifecycle script legitimately needs (was a blanket "npm_" — ADR-0017).
  prefixes: ["npm_package_", "npm_lifecycle_", "npm_node_", "npm_config_", "LC_"],
  exact: new Set([
    "PATH", "HOME", "SHELL", "PWD", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP",
    "LANG", "TERM", "INIT_CWD",
    "NODE", "NODE_OPTIONS", "NODE_PATH", "NODE_ENV",     // exact, NOT a NODE* prefix
    "CPPFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS", "PKG_CONFIG_PATH", "PYTHON", "MAKEFLAGS",
    "npm_command", "npm_execpath",
  ]),
};

function allowed(name: string): boolean {
  if (CREDENTIAL_ENV_RE.test(name)) return false;   // credential-screen wins over any allowlist match
  return ENV_ALLOWLIST.exact.has(name) || ENV_ALLOWLIST.prefixes.some((p) => name.startsWith(p));
}

/** Return a new env containing only allowlisted vars plus those granted by an `env` approval. */
export function scrubEnv(sourceEnv: NodeJS.ProcessEnv, approvedEnv: Capability[]): NodeJS.ProcessEnv {
  const granted = new Set(approvedEnv.filter((c) => c.kind === "env").map((c) => c.target));
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(sourceEnv)) {
    if (v === undefined) continue;
    if (allowed(k) || granted.has(k)) out[k] = v;
  }
  return out;
}
