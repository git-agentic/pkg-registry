import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Sandbox } from "./types.js";
import { scrubEnv } from "./env.js";
import type { Capability } from "@sentinel/core";

export interface ScriptResult {
  hook: string;
  command: string;
  exitCode: number;
}

const LIFECYCLE = ["preinstall", "install", "postinstall"] as const;

/** Run a package's present lifecycle scripts under the sandbox profile + scrubbed env. */
export function runLifecycleScripts(opts: {
  packageDir: string;
  profile: string;
  sandbox: Sandbox;
  approved?: Capability[];
}): { results: ScriptResult[]; failed: boolean } {
  let scripts: Record<string, string> = {};
  try {
    scripts = JSON.parse(readFileSync(join(opts.packageDir, "package.json"), "utf8"))?.scripts ?? {};
  } catch {
    scripts = {};
  }
  const env = scrubEnv(process.env, opts.approved ?? []);
  const results: ScriptResult[] = [];
  for (const hook of LIFECYCLE) {
    const command = scripts[hook];
    if (!command) continue;
    const r = opts.sandbox.run(command, { cwd: opts.packageDir, profile: opts.profile, env });
    results.push({ hook, command, exitCode: r.exitCode });
  }
  return { results, failed: results.some((r) => r.exitCode !== 0) };
}
