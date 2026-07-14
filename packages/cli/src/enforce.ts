import type { Capability } from "@agentic-sentinel/core";
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

/** True when the lifecycle script belongs to the install root itself, not a dependency under node_modules. */
export function isRootScript(cwd: string, initCwd: string | undefined): boolean {
  if (cwd.includes("/node_modules/")) return false;
  if (initCwd) return cwd === initCwd;
  return true;
}

/** Extract the lifecycle command from npm's `<shell> -c "<cmd>"` invocation. */
export function commandFromArgv(argv: string[]): string {
  if (argv.length >= 2 && argv[0] === "-c" && typeof argv[1] === "string") return argv[1];
  throw new EnforceError(`sentinel-script-shell expects \`-c <command>\`, got: ${JSON.stringify(argv)}`);
}
