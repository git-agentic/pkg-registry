import { isAbsolute } from "node:path";
import type { Capability } from "@git-agentic/sentinel-core";
import type { Manifest } from "./format.js";

/** Raised when enforcement cannot be guaranteed — the wrapper must fail closed (never run unsandboxed). */
export class EnforceError extends Error {}

/**
 * Approved capabilities for a dependency's lifecycle scripts, from its proxy manifest.
 * "approved"/"inherited" ⇒ its detected capabilities; "n-a" ⇒ none (strict sandbox);
 * "required"/"denied" ⇒ fail closed (the package is not cleared to run).
 */
export function approvedCapsForManifest(m: Manifest): Capability[] {
  switch (m.approvalState) {
    case "approved":
    case "inherited":
      return m.capabilities;
    case "n-a":
      return [];
    default: // "required" | "denied" | anything unexpected
      throw new EnforceError(`package ${m.meta.name}@${m.meta.version} is not approved (state: ${m.approvalState})`);
  }
}

/**
 * True when the lifecycle script belongs to the install root itself. `sentinelRoot` is the
 * `SENTINEL_ROOT` that `sentinel install --enforce` pinned to the realpath of the install cwd.
 * `INIT_CWD` is NOT trusted: a nested npm (a git dependency's `prepare`) resets it to the
 * dependency's own directory, which would make that dependency look like the root and hand it the
 * operator's approvals. Fail closed: a missing or non-absolute root means "not root".
 */
export function isRootScript(cwd: string, sentinelRoot: string | undefined): boolean {
  if (!sentinelRoot || !isAbsolute(sentinelRoot)) return false;
  if (cwd.includes("/node_modules/")) return false;
  return cwd === sentinelRoot;
}

/**
 * `npm_package_integrity` is only trustworthy on npm >= 7: npm 6 exports EVERY package.json field
 * as `npm_package_*` (so a package can declare its own `integrity`), while npm 7+ exports only a
 * fixed set (RFC 183, `@npmcli/run-script` package-envs) and arborist sets the integrity itself.
 * Fail closed unless `npm_config_user_agent` (set by npm, not the package) starts with `npm/<7+>`.
 */
export function assertNpmTrustsIntegrity(userAgent: string | undefined): void {
  const major = /^npm\/(\d+)\./.exec(userAgent ?? "")?.[1];
  if (major === undefined || Number(major) < 7) {
    throw new EnforceError(
      `dependency scripts under --enforce need npm >= 7 (user agent ${JSON.stringify((userAgent ?? "").slice(0, 60))}): before npm 7 a package controls npm_package_integrity`,
    );
  }
}

/**
 * Bind a dependency script to the audited package. npm's `npm_package_name`/`version` come from
 * the package's own package.json (a git/URL/file dependency controls them), so the approval lookup
 * keyed on them is only trustworthy if `npm_package_integrity` — what npm verified the installed
 * bytes against — equals the manifest's `meta.integrity` (the digest of the bytes the proxy audited).
 * Compared per algorithm: a token in another algorithm than the manifest's cannot be compared, and
 * a missing or mismatched integrity fails closed. (Limit: a legacy package that npm records only as
 * sha1 therefore cannot run an enforced script.)
 */
export function assertIntegrityBinding(m: Manifest, envIntegrity: string | undefined): void {
  const served = m.meta.integrity;
  const algo = /^(sha1|sha256|sha512)-/.exec(served)?.[1];
  const tokens = (envIntegrity ?? "").trim().split(/\s+/).filter(Boolean);
  const same = algo ? tokens.filter((t) => t.startsWith(`${algo}-`)) : [];
  if (!algo || same.length === 0 || same.some((t) => t !== served)) {
    throw new EnforceError(
      `${m.meta.name}@${m.meta.version}: npm_package_integrity ${tokens.length ? "does not match" : "is missing for"} the audited tarball integrity — refusing to apply its approvals`,
    );
  }
}

/** Extract the lifecycle command from npm's `<shell> -c "<cmd>"` invocation. */
export function commandFromArgv(argv: string[]): string {
  if (argv.length >= 2 && argv[0] === "-c" && typeof argv[1] === "string") return argv[1];
  throw new EnforceError(`sentinel-script-shell expects \`-c <command>\`, got: ${JSON.stringify(argv)}`);
}
