import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { existsSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, sep } from "node:path";
import { generateBwrapArgs } from "./bwrap.js";
import type { Sandbox, SandboxResult } from "./types.js";
import type { Capability } from "@sentinel/core";
import { computeDenySet } from "./deny-set.js";
import { classifyViolation } from "./violation.js";
import { nodeInstallPrefix } from "./read-allow.js";
import { linuxExecFloor } from "./exec-floor.js";

/** bwrap's own errors when the kernel refuses unprivileged user namespaces (Ubuntu 24.04 AppArmor, etc.). */
const NS_FAILURE = /Creating new namespace failed|No permissions to create new namespace|setting up uid map/i;

/**
 * Path to the compiled Landlock helper. `build-native.mjs` writes it ONLY to
 * `packages/sandbox/dist/landlock-exec` — never beside `src/`. In production
 * (`tsc --build`) this module itself runs from `dist/bubblewrap.js`, so the
 * helper is a same-dir sibling. Under the test suite (`node --import tsx
 * --test`) this module runs straight from `src/bubblewrap.ts` — `import.meta.url`
 * points at `src/`, not `dist/` — so a naive `./landlock-exec` sibling lookup
 * would silently miss the built helper and fall through to the (wrong, for a
 * built-helper CI run) advisory path. Detect which directory we're executing
 * from and always resolve into the package's `dist/`.
 */
function landlockHelperPath(): string {
  const here = fileURLToPath(import.meta.url);
  const dir = dirname(here);
  const distDir = dir.endsWith(`${sep}dist`) ? dir : join(dir, "..", "dist");
  return join(distDir, "landlock-exec");
}

let landlockActiveCache: boolean | undefined;
let advisoryNoticeShown = false;

/** Fail-open, pre-checked: the helper is active iff it exists AND `--check` (ABI probe)
 * exits 0. Cached once. Any negative ⇒ Phase 29 advisory path. Never prepend the helper
 * unverified — it exits 3 and would fail every lifecycle script on a Landlock-less host. */
function landlockActive(): boolean {
  if (landlockActiveCache !== undefined) return landlockActiveCache;
  const helper = landlockHelperPath();
  if (!existsSync(helper)) { landlockActiveCache = false; return false; }
  const r = spawnSync(helper, ["--check"], { encoding: "utf8" });
  landlockActiveCache = !r.error && r.status === 0;
  return landlockActiveCache;
}

/** realpathSync with an identity fallback (missing path, permission error, …) — never throws. */
function safeRealpath(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}

/** Enforces a generated bwrap profile via `bwrap`. Fails closed on non-Linux, missing bwrap, or refused namespace. */
export class BubblewrapSandbox implements Sandbox {
  run(cmd: string, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv; projectRoot?: string }): SandboxResult {
    if (process.platform !== "linux") {
      throw new Error(`bubblewrap enforcement unavailable on ${process.platform} (Linux required)`);
    }
    const useLandlock = landlockActive();
    const nodePrefix = nodeInstallPrefix(process.execPath);
    const projectRoot = opts.projectRoot ?? opts.cwd;

    if (!useLandlock && !advisoryNoticeShown) {
      advisoryNoticeShown = true;
      process.stderr.write(
        "sentinel: Landlock exec floor unavailable on this host — advisory floor active " +
        "(a dropped binary can exec but stays filesystem+network confined). " +
        "Build with a C compiler on Linux to enable the enforced floor.\n",
      );
    }

    const inner = useLandlock
      ? [landlockHelperPath(), ...linuxExecFloor({ nodePrefix, projectRoot }).flatMap((p) => ["--allow", p]), "--", "/bin/sh", "-c", cmd]
      : ["/bin/sh", "-c", cmd];

    const args = [
      ...generateBwrapArgs(opts.approved, {
        homeDir: opts.homeDir, cwd: opts.cwd, tmpDir: tmpdir(), pathExists: existsSync, realpath: safeRealpath,
        nodePrefix, projectRoot,
        // The helper's own directory must stay visible inside the sandbox even when it
        // lands under $HOME (e.g. a CI checkout at ~/work/...) and neither the node
        // prefix nor the project root happen to cover it — bwrap execs it directly,
        // before Landlock's own ruleset is active, so it needs plain fs visibility.
        extraReadAllow: useLandlock ? [dirname(landlockHelperPath())] : undefined,
      }),
      ...inner,
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
      nodePrefix, projectRoot, cwd: opts.cwd, tmpDir: tmpdir(),
      landlockFloor: useLandlock,
    });
    const violation = classifyViolation(result, denySet);
    return violation ? { ...result, violation } : result;
  }
}
