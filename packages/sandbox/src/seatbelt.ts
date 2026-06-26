import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Sandbox, SandboxResult } from "./types.js";

/** Enforces an SBPL profile via macOS `sandbox-exec`. Fails closed on non-darwin. */
export class SeatbeltSandbox implements Sandbox {
  run(cmd: string, opts: { cwd: string; profile: string; env?: NodeJS.ProcessEnv }): SandboxResult {
    if (process.platform !== "darwin") {
      throw new Error(`sandbox enforcement unavailable on ${process.platform} (macOS Seatbelt required)`);
    }
    const dir = mkdtempSync(join(tmpdir(), "sentinel-sb-"));
    const profileFile = join(dir, "profile.sb");
    writeFileSync(profileFile, opts.profile);
    try {
      const res = spawnSync("/usr/bin/sandbox-exec", ["-f", profileFile, "/bin/sh", "-c", cmd], {
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
      return {
        exitCode: res.status ?? (res.signal ? 1 : 0),
        stdout: res.stdout ?? "",
        stderr: res.stderr ?? "",
      };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
}
