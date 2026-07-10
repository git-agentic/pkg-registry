import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { existsSync } from "node:fs";
import { generateBwrapArgs } from "./bwrap.js";
import type { Sandbox, SandboxResult } from "./types.js";
import type { Capability } from "@sentinel/core";
import { computeDenySet } from "./deny-set.js";
import { classifyViolation } from "./violation.js";
import { nodeInstallPrefix } from "./read-allow.js";

/** bwrap's own errors when the kernel refuses unprivileged user namespaces (Ubuntu 24.04 AppArmor, etc.). */
const NS_FAILURE = /Creating new namespace failed|No permissions to create new namespace|setting up uid map/i;

/** Enforces a generated bwrap profile via `bwrap`. Fails closed on non-Linux, missing bwrap, or refused namespace. */
export class BubblewrapSandbox implements Sandbox {
  run(cmd: string, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv; projectRoot?: string }): SandboxResult {
    if (process.platform !== "linux") {
      throw new Error(`bubblewrap enforcement unavailable on ${process.platform} (Linux required)`);
    }
    const args = [
      ...generateBwrapArgs(opts.approved, {
        homeDir: opts.homeDir, cwd: opts.cwd, tmpDir: tmpdir(), pathExists: existsSync,
        nodePrefix: nodeInstallPrefix(process.execPath),
        projectRoot: opts.projectRoot ?? opts.cwd,
      }),
      "/bin/sh",
      "-c",
      cmd,
    ];
    const res = spawnSync("bwrap", args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    if (res.error && (res.error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error("bubblewrap enforcement unavailable: `bwrap` not found on PATH (install the bubblewrap package)");
    }
    if (res.error) {
      throw new Error(`bubblewrap enforcement failed: ${res.error.message}`);
    }
    if (NS_FAILURE.test(res.stderr ?? "")) {
      throw new Error(`bubblewrap enforcement unavailable: kernel refused user-namespace creation — ${res.stderr?.trim()}`);
    }
    const result: SandboxResult = {
      exitCode: res.status ?? (res.signal ? 1 : 0),
      stdout: res.stdout ?? "",
      stderr: res.stderr ?? "",
    };
    const denySet = computeDenySet(opts.approved, {
      homeDir: opts.homeDir, platform: "linux",
      nodePrefix: nodeInstallPrefix(process.execPath),
      projectRoot: opts.projectRoot ?? opts.cwd,
      cwd: opts.cwd, tmpDir: tmpdir(),
    });
    const violation = classifyViolation(result, denySet);
    return violation ? { ...result, violation } : result;
  }
}
