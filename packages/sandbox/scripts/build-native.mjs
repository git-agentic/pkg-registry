// Compile the Landlock helper from source as part of `npm run build`. Linux + cc
// only; a no-op (exit 0) everywhere else so it never breaks the build. This is
// deliberately a build STEP, not a postinstall hook (adding install-time script
// execution to a tool that guards against exactly that would be a posture violation).
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, renameSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..", "native", "landlock-exec.c");
const outDir = join(here, "..", "dist");
const out = join(outDir, "landlock-exec");

try {
  if (process.platform !== "linux") {
    console.log(`[build-native] skip: not linux (${process.platform}) — advisory floor will be used`);
    process.exit(0);
  }
  const cc = spawnSync("cc", ["--version"], { encoding: "utf8" });
  if (cc.error || cc.status !== 0) {
    console.log("[build-native] skip: no cc on PATH — advisory floor will be used");
    process.exit(0);
  }
  if (!existsSync(src)) {
    console.log(`[build-native] skip: source not found at ${src}`);
    process.exit(0);
  }
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  // Compile to a temp name and rename into place: an in-place `cc -o` lets a concurrent exec of
  // the helper see a half-written or not-yet-executable file (EACCES / ETXTBSY).
  const tmp = `${out}.${process.pid}.tmp`;
  const r = spawnSync("cc", ["-O2", "-o", tmp, src], { stdio: "inherit" });
  if (r.status !== 0) {
    rmSync(tmp, { force: true });
    console.log("[build-native] skip: compile failed — advisory floor will be used");
    process.exit(0);
  }
  renameSync(tmp, out);
  console.log(`[build-native] built ${out}`);
} catch (e) {
  console.log(`[build-native] skip: unexpected error (${e?.message ?? e}) — advisory floor will be used`);
  process.exit(0);
}
