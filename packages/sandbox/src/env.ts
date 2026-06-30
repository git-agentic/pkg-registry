import type { Capability } from "@sentinel/core";

/**
 * Fail-closed env allowlist for sandboxed lifecycle scripts. Pass ONLY these; any other
 * var — including a novel-named credential — is dropped. Validated against a real `npm
 * install` lifecycle env (ADR-0017). The load-bearing behavior is the DROP of operator-shell
 * secrets (SSH_AUTH_SOCK, AWS_*, *_TOKEN); the npm_* entries are forward-looking for the
 * deferred `install --enforce` path (run-scripts itself isn't invoked by npm).
 */
export const ENV_ALLOWLIST = {
  prefixes: ["npm_", "LC_"],
  exact: new Set([
    "PATH", "HOME", "SHELL", "PWD", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP",
    "LANG", "TERM", "INIT_CWD",
    "NODE", "NODE_OPTIONS", "NODE_PATH", "NODE_ENV",     // exact, NOT a NODE* prefix
    "CPPFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS", "PKG_CONFIG_PATH", "PYTHON", "MAKEFLAGS",
  ]),
};

function allowed(name: string): boolean {
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
