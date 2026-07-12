import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Capability } from "@sentinel/core";
import type { Sandbox, SandboxResult } from "./types.js";
import { generateProfile } from "./profile.js";
import { computeDenySet } from "./deny-set.js";
import { classifyViolation } from "./violation.js";
import { nodeInstallPrefix } from "./read-allow.js";

/** Enforces an SBPL profile via macOS `sandbox-exec`. Fails closed on non-darwin. */
export class SeatbeltSandbox implements Sandbox {
  run(cmd: string, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv; projectRoot?: string }): SandboxResult {
    return this.execWithTail(["/bin/sh", "-c", cmd], opts);
  }

  runArgv(file: string, args: string[], opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv; projectRoot?: string }): SandboxResult {
    return this.execWithTail([file, ...args], opts);
  }

  /** Shared by `run` and `runArgv`: build the profile, invoke `sandbox-exec` with the given
   * argv tail (either `/bin/sh -c cmd` or `file ...args`), and classify the result. */
  private execWithTail(tail: string[], opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv; projectRoot?: string }): SandboxResult {
    if (process.platform !== "darwin") {
      throw new Error(`sandbox enforcement unavailable on ${process.platform} (macOS Seatbelt required)`);
    }
    const profile = generateProfile(opts.approved, {
      homeDir: opts.homeDir, cwd: opts.cwd, tmpDir: tmpdir(),
      nodePrefix: nodeInstallPrefix(process.execPath),
      projectRoot: opts.projectRoot ?? opts.cwd,
    });
    const dir = mkdtempSync(join(tmpdir(), "sentinel-sb-"));
    const profileFile = join(dir, "profile.sb");
    writeFileSync(profileFile, profile);
    try {
      const res = spawnSync("/usr/bin/sandbox-exec", ["-f", profileFile, ...tail], {
        cwd: opts.cwd,
        env: opts.env ?? process.env,
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
      });
      if (res.error) {
        return {
          exitCode: 127,
          stdout: "",
          stderr: res.error.message,
        };
      }
      const result: SandboxResult = {
        exitCode: res.status ?? (res.signal ? 1 : 0),
        stdout: res.stdout ?? "",
        stderr: res.stderr ?? "",
      };
      const denySet = computeDenySet(opts.approved, {
        homeDir: opts.homeDir, platform: "darwin",
        nodePrefix: nodeInstallPrefix(process.execPath),
        projectRoot: opts.projectRoot ?? opts.cwd,
        cwd: opts.cwd, tmpDir: tmpdir(),
      });
      const violation = classifyViolation(result, denySet);
      return violation ? { ...result, violation } : result;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
}
