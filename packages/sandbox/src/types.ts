import type { Capability } from "@sentinel/core";

export interface SandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface Sandbox {
  /** Run `cmd` (via `sh -c`) under a sandbox compiled from the APPROVED capabilities, in `cwd`. */
  run(cmd: string, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv }): SandboxResult;
}
