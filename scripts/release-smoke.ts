// Release smoke test: pack every publishable workspace, install the packed
// tarballs into a FRESH temp project (no monorepo/workspace resolution), and
// verify the artifacts actually work:
//   - every package imports
//   - type declarations resolve under NodeNext
//   - every declared bin starts (--help/--version where supported; controlled
//     startup/config-validation otherwise)
//   - the proxy boots, serves the dashboard, and shuts down cleanly
//   - the MCP server answers an initialize handshake
//   - the steward fail-closes on missing config and boots with full config
//   - internal @agentic-sentinel/* dependencies resolve from the packed tarballs only
//
// Requires network access (third-party deps install from the public registry).
// Usage: npx tsx scripts/release-smoke.ts [--json <out.json>] [--pack-dest <dir>]
//   --pack-dest keeps the packed tarballs in <dir> (the release workflow
//   uploads exactly the artifacts this script validated).
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORKSPACES = ["core", "proxy", "sandbox", "cli", "mcp", "action", "steward"] as const;
const VERSION = "0.1.0-alpha.1";

interface TarballInfo { name: string; file: string; bytes: number; sha256: string; files: number; unpacked: number }
const results: { tarballs: TarballInfo[]; checks: { name: string; ok: boolean; detail: string }[] } = { tarballs: [], checks: [] };

function check(name: string, fn: () => string): void {
  try {
    const detail = fn();
    results.checks.push({ name, ok: true, detail });
    console.log(`  ✓ ${name}${detail ? ` — ${detail}` : ""}`);
  } catch (e) {
    results.checks.push({ name, ok: false, detail: (e as Error).message });
    console.error(`  ✗ ${name} — ${(e as Error).message}`);
  }
}

async function checkAsync(name: string, fn: () => Promise<string>): Promise<void> {
  try {
    const detail = await fn();
    results.checks.push({ name, ok: true, detail });
    console.log(`  ✓ ${name}${detail ? ` — ${detail}` : ""}`);
  } catch (e) {
    results.checks.push({ name, ok: false, detail: (e as Error).message });
    console.error(`  ✗ ${name} — ${(e as Error).message}`);
  }
}

function run(cmd: string, args: string[], opts: { cwd: string; env?: NodeJS.ProcessEnv } = { cwd: repoRoot }): string {
  return execFileSync(cmd, args, { cwd: opts.cwd, encoding: "utf8", env: opts.env ?? process.env, stdio: ["ignore", "pipe", "pipe"] });
}

/** Run expecting a non-zero exit; returns { code, output }. Throws if it exits 0. */
function runExpectFail(cmd: string, args: string[], opts: { cwd: string; env?: NodeJS.ProcessEnv }): { code: number; output: string } {
  try {
    execFileSync(cmd, args, { cwd: opts.cwd, encoding: "utf8", env: opts.env ?? process.env, stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    return { code: err.status ?? -1, output: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
  throw new Error("expected non-zero exit, got 0");
}

/** Spawn a long-running process, wait for a stdout/stderr marker, run probe, then kill. */
async function withServer(
  file: string, args: string[], env: NodeJS.ProcessEnv, cwd: string, marker: RegExp, timeoutMs: number,
  probe: (child: ChildProcess, output: () => string) => Promise<string>,
): Promise<string> {
  const child = spawn(file, args, { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
  let out = "";
  child.stdout!.on("data", (d: Buffer) => { out += d.toString(); });
  child.stderr!.on("data", (d: Buffer) => { out += d.toString(); });
  try {
    await new Promise<void>((resolvePromise, reject) => {
      const t = setTimeout(() => reject(new Error(`timeout waiting for ${marker} — output:\n${out.slice(0, 2000)}`)), timeoutMs);
      const iv = setInterval(() => {
        if (marker.test(out)) { clearTimeout(t); clearInterval(iv); resolvePromise(); }
        if (child.exitCode !== null) { clearTimeout(t); clearInterval(iv); reject(new Error(`exited ${child.exitCode} before ${marker} — output:\n${out.slice(0, 2000)}`)); }
      }, 50);
    });
    return await probe(child, () => out);
  } finally {
    child.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 300));
    if (child.exitCode === null) child.kill("SIGKILL");
  }
}

// ---------------------------------------------------------------------------
// 1. Pack every workspace
// ---------------------------------------------------------------------------
const destIdx = process.argv.indexOf("--pack-dest");
const packDir = destIdx !== -1 && process.argv[destIdx + 1]
  ? (mkdirSync(resolve(process.argv[destIdx + 1]!), { recursive: true }), resolve(process.argv[destIdx + 1]!))
  : mkdtempSync(join(tmpdir(), "sentinel-pack-"));
console.log(`\n[1/5] packing ${WORKSPACES.length} workspaces → ${packDir}`);
for (const ws of WORKSPACES) {
  const json = run("npm", ["pack", "--json", "--pack-destination", packDir], { cwd: join(repoRoot, "packages", ws) });
  const info = (JSON.parse(json) as { filename: string; size: number; entryCount: number; unpackedSize: number }[])[0];
  const file = join(packDir, info.filename);
  const sha256 = createHash("sha256").update(readFileSync(file)).digest("hex");
  results.tarballs.push({ name: `@agentic-sentinel/${ws}`, file: info.filename, bytes: info.size, sha256, files: info.entryCount, unpacked: info.unpackedSize });
  console.log(`  ${info.filename}  ${info.size} B  ${info.entryCount} files  sha256:${sha256.slice(0, 16)}…`);
}

// ---------------------------------------------------------------------------
// 2. Fresh project: install ONLY the packed tarballs (+ registry for 3rd-party)
// ---------------------------------------------------------------------------
const proj = mkdtempSync(join(tmpdir(), "sentinel-smoke-"));
console.log(`\n[2/5] fresh install into ${proj}`);
const fileDep = (ws: string) => `file:${join(packDir, results.tarballs.find((t) => t.name === `@agentic-sentinel/${ws}`)!.file)}`;
const pkgJson = {
  name: "sentinel-release-smoke", private: true, version: "0.0.0", type: "module",
  dependencies: Object.fromEntries(WORKSPACES.map((ws) => [`@agentic-sentinel/${ws}`, fileDep(ws)])),
  // Internal deps are pinned to the (unpublished) exact prerelease version, so
  // transitive resolution must be forced to the local tarballs.
  overrides: { "@agentic-sentinel/core": fileDep("core"), "@agentic-sentinel/proxy": fileDep("proxy"), "@agentic-sentinel/sandbox": fileDep("sandbox") },
};
writeFileSync(join(proj, "package.json"), JSON.stringify(pkgJson, null, 2));
run("npm", ["install", "--no-audit", "--no-fund", "--loglevel=error"], { cwd: proj });
console.log("  installed");
check("internal deps resolved from tarballs (not registry)", () => {
  const lock = JSON.parse(readFileSync(join(proj, "package-lock.json"), "utf8")) as { packages: Record<string, { resolved?: string; version?: string }> };
  const bad = Object.entries(lock.packages).filter(([k, v]) => k.includes("@agentic-sentinel/") && v.resolved && !v.resolved.startsWith("file:"));
  if (bad.length) throw new Error(`registry-resolved: ${bad.map(([k]) => k).join(", ")}`);
  return "all @agentic-sentinel/* resolved file:";
});

// ---------------------------------------------------------------------------
// 3. Imports + type declarations
// ---------------------------------------------------------------------------
console.log(`\n[3/5] imports + types`);
for (const ws of WORKSPACES) {
  check(`import @agentic-sentinel/${ws}`, () => {
    run(process.execPath, ["-e", `import("@agentic-sentinel/${ws}").then((m)=>{ if(!m || typeof m !== "object") throw new Error("empty module") })`], { cwd: proj });
    return "";
  });
}
check("ENGINE_VERSION matches release", () => {
  const v = run(process.execPath, ["-e", `import("@agentic-sentinel/core").then((m)=>console.log(m.ENGINE_VERSION))`], { cwd: proj }).trim();
  if (v !== VERSION) throw new Error(`ENGINE_VERSION=${v}, expected ${VERSION}`);
  return v;
});
check("type declarations resolve (tsc --noEmit, NodeNext)", () => {
  run("npm", ["install", "--no-audit", "--no-fund", "--loglevel=error", "-D", "typescript@^6"], { cwd: proj });
  writeFileSync(join(proj, "typecheck.ts"), [
    `import { runAudit, score, DEFAULT_POLICY, type AuditReport, type EnterprisePolicy } from "@agentic-sentinel/core";`,
    `import { createServer, NpmUpstream, type Upstream } from "@agentic-sentinel/proxy";`,
    `import { createSandbox, scrubEnv } from "@agentic-sentinel/sandbox";`,
    `const p: EnterprisePolicy = DEFAULT_POLICY;`,
    `void p; void runAudit; void score; void createServer; void createSandbox; void scrubEnv;`,
    `const u: Upstream | null = null; void u;`,
    `const r: AuditReport | null = null; void r; void NpmUpstream;`,
  ].join("\n"));
  writeFileSync(join(proj, "tsconfig.json"), JSON.stringify({
    compilerOptions: { module: "NodeNext", moduleResolution: "NodeNext", target: "ES2023", strict: true, noEmit: true, skipLibCheck: true, types: [] },
    files: ["typecheck.ts"],
  }));
  run(join(proj, "node_modules", ".bin", "tsc"), ["-p", proj], { cwd: proj });
  return "";
});

// ---------------------------------------------------------------------------
// 4. Binaries
// ---------------------------------------------------------------------------
console.log(`\n[4/5] binaries`);
const bin = (name: string) => join(proj, "node_modules", ".bin", name);

check("sentinel --version", () => {
  const v = run(bin("sentinel"), ["--version"], { cwd: proj }).trim();
  if (v !== VERSION) throw new Error(`got ${v}, expected ${VERSION}`);
  return v;
});
check("sentinel --help prints usage", () => {
  const out = run(bin("sentinel"), ["--help"], { cwd: proj });
  if (!/Usage:/i.test(out)) throw new Error(`no usage text:\n${out.slice(0, 300)}`);
  return "";
});
check("sentinel-registry --help prints usage", () => {
  const out = run(bin("sentinel-registry"), ["--help"], { cwd: proj });
  if (!/Usage:/i.test(out)) throw new Error(`no usage text:\n${out.slice(0, 300)}`);
  return "";
});
check("sentinel-script-shell starts (controlled failure, no module errors)", () => {
  const { output } = runExpectFail(bin("sentinel-script-shell"), [], { cwd: proj });
  if (/ERR_MODULE_NOT_FOUND|Cannot find (module|package)/.test(output)) throw new Error(`module resolution failure:\n${output.slice(0, 800)}`);
  return "controlled non-zero exit";
});
check("sentinel-ci starts (controlled failure without lockfile, no module errors)", () => {
  const empty = mkdtempSync(join(tmpdir(), "sentinel-ci-empty-"));
  try {
    const { output } = runExpectFail(bin("sentinel-ci"), [], { cwd: empty, env: { ...process.env, GITHUB_OUTPUT: "", GITHUB_STEP_SUMMARY: "" } });
    if (/ERR_MODULE_NOT_FOUND|Cannot find (module|package)/.test(output)) throw new Error(`module resolution failure:\n${output.slice(0, 800)}`);
    return "controlled non-zero exit";
  } finally { rmSync(empty, { recursive: true, force: true }); }
});
check("sentinel-steward fail-closed on missing config", () => {
  const { code, output } = runExpectFail(bin("sentinel-steward"), [], { cwd: proj, env: { PATH: process.env.PATH! } });
  if (code !== 1 || !/FATAL/.test(output)) throw new Error(`expected exit 1 + FATAL, got ${code}: ${output.slice(0, 300)}`);
  return "exit 1 + FATAL";
});

const proxyPort = 40000 + Math.floor(Math.random() * 20000);
await checkAsync("sentinel-proxy boots, serves dashboard, exits cleanly", async () => {
  return withServer(bin("sentinel-proxy"), [], { ...process.env, SENTINEL_PORT: String(proxyPort) }, proj, /listening on/, 20000, async () => {
    const res = await fetch(`http://localhost:${proxyPort}/`);
    if (res.status !== 200) throw new Error(`GET / → ${res.status}`);
    const body = await res.text();
    if (!/sentinel/i.test(body)) throw new Error("dashboard body missing 'sentinel'");
    return `GET / → 200 (${body.length} B)`;
  });
});

await checkAsync("sentinel-mcp answers initialize", async () => {
  const child = spawn(bin("sentinel-mcp"), [], { cwd: proj, env: process.env, stdio: ["pipe", "pipe", "pipe"] });
  let out = "";
  child.stdout!.on("data", (d: Buffer) => { out += d.toString(); });
  try {
    child.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "smoke", version: "0.0.0" } } }) + "\n");
    await new Promise<void>((resolvePromise, reject) => {
      const t = setTimeout(() => reject(new Error(`no initialize response — output: ${out.slice(0, 500)}`)), 10000);
      const iv = setInterval(() => {
        if (out.includes('"serverInfo"') || out.includes('"result"')) { clearTimeout(t); clearInterval(iv); resolvePromise(); }
        if (child.exitCode !== null) { clearTimeout(t); clearInterval(iv); reject(new Error(`exited ${child.exitCode}: ${out.slice(0, 500)}`)); }
      }, 50);
    });
    return "initialize → result";
  } finally {
    child.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 200));
    if (child.exitCode === null) child.kill("SIGKILL");
  }
});

await checkAsync("sentinel-steward boots with full config", async () => {
  const stewardDir = mkdtempSync(join(tmpdir(), "sentinel-steward-"));
  const { privateKey } = generateKeyPairSync("ed25519");
  const keyPath = join(stewardDir, "key.pem");
  writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }));
  mkdirSync(join(stewardDir, "release"), { recursive: true });
  const port = proxyPort + 1;
  const env = {
    ...process.env,
    SENTINEL_STEWARD_TOKEN: "smoke-token",
    SENTINEL_STEWARD_STATE: join(stewardDir, "state.json"),
    SENTINEL_CLAIM_CORPUS_PRIVATE_KEY: keyPath,
    SENTINEL_CLAIM_CORPUS_RELEASE_DIR: join(stewardDir, "release"),
    SENTINEL_STEWARD_PORT: String(port),
  };
  try {
    return await withServer(bin("sentinel-steward"), [], env, proj, /steward listening/, 15000, async () => "listening");
  } finally { rmSync(stewardDir, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------------------
// 5. Summary
// ---------------------------------------------------------------------------
console.log(`\n[5/5] summary`);
const failed = results.checks.filter((c) => !c.ok);
console.log(`  tarballs: ${results.tarballs.length}; checks: ${results.checks.length - failed.length}/${results.checks.length} passed`);
const jsonIdx = process.argv.indexOf("--json");
if (jsonIdx !== -1 && process.argv[jsonIdx + 1]) {
  writeFileSync(process.argv[jsonIdx + 1]!, JSON.stringify(results, null, 2));
  console.log(`  wrote ${process.argv[jsonIdx + 1]}`);
}
if (failed.length > 0) {
  console.error(`\nFAILED checks:\n${failed.map((f) => `  - ${f.name}: ${f.detail}`).join("\n")}`);
  process.exit(1);
}
console.log("\nrelease smoke: ALL PASS");
