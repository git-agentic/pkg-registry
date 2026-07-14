import type { Capability } from "@git-agentic/sentinel-core";

export interface SandboxViolation {
  /** The denied resource class the child hit. */
  kind: "filesystem" | "network" | "process";
  /** Extracted path or host:port from the child's error, or null if not attributable. */
  target: string | null;
  /** confirmed: target matches the deny set. suspected: class-denied but no attributable target. */
  confidence: "confirmed" | "suspected";
  /** The deny-set entry matched (a denied path, or "network"); null when suspected without a match. */
  deniedResource: string | null;
  /** Redaction-safe evidence: the child's exit code and the single matched error line (≤200 chars). */
  evidence: { exitCode: number; stderrExcerpt: string };
}

export interface SandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  /** A runtime violation inferred from a permission-error exit, when one was detected (Phase 10). */
  violation?: SandboxViolation;
}

export interface Sandbox {
  /** Run `cmd` (via `sh -c`) under a sandbox compiled from the APPROVED capabilities, in `cwd`. */
  run(cmd: string, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv; projectRoot?: string }): SandboxResult;
  /** Run `file` with `args` under the sandbox WITHOUT a shell (execFile-style; boundaries preserved). */
  runArgv(file: string, args: string[], opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv; projectRoot?: string }): SandboxResult;
}
