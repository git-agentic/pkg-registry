import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Sandbox } from "./types.js";

export interface ScriptResult {
  hook: string;
  command: string;
  exitCode: number;
}

const LIFECYCLE = ["preinstall", "install", "postinstall"] as const;

/** Run a package's present lifecycle scripts under the sandbox profile (cwd = packageDir). */
export function runLifecycleScripts(opts: {
  packageDir: string;
  profile: string;
  sandbox: Sandbox;
}): { results: ScriptResult[]; failed: boolean } {
  let scripts: Record<string, string> = {};
  try {
    scripts = JSON.parse(readFileSync(join(opts.packageDir, "package.json"), "utf8"))?.scripts ?? {};
  } catch {
    scripts = {};
  }
  const results: ScriptResult[] = [];
  for (const hook of LIFECYCLE) {
    const command = scripts[hook];
    if (!command) continue;
    const r = opts.sandbox.run(command, { cwd: opts.packageDir, profile: opts.profile });
    results.push({ hook, command, exitCode: r.exitCode });
  }
  return { results, failed: results.some((r) => r.exitCode !== 0) };
}
