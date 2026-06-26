export interface SandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface Sandbox {
  /** Run `cmd` (via `sh -c`) under the given SBPL `profile`, in `cwd`. */
  run(cmd: string, opts: { cwd: string; profile: string; env?: NodeJS.ProcessEnv }): SandboxResult;
}
