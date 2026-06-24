#!/usr/bin/env node
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { Command } from "commander";
import { auditTarball, type AuditReport } from "@sentinel/core";
import { formatReport, formatManifest, verdictExitCode, type Manifest } from "./format.js";

const DEFAULT_PROXY = process.env.SENTINEL_PROXY ?? "http://localhost:4873";

const program = new Command();
program
  .name("sentinel")
  .description("Agent-auditable security layer for npm — pre-install audit verdicts.")
  .version("0.1.0");

program
  .command("audit")
  .description("Audit a package version via the proxy and print the verdict (no install).")
  .argument("<package>", "package name, e.g. color-stream or @scope/name")
  .argument("[version]", "version (defaults to dist-tags.latest)")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--json", "emit the raw JSON report", false)
  .action(async (pkg: string, version: string | undefined, opts: { proxy: string; json: boolean }) => {
    try {
      const v = version ?? (await resolveLatest(opts.proxy, pkg));
      const report = await fetchAudit(opts.proxy, pkg, v);
      emit(report, opts.json);
      process.exitCode = verdictExitCode(report.verdict);
    } catch (err) {
      fail(err, opts.proxy);
    }
  });

program
  .command("scan")
  .description("Audit a local .tgz tarball directly (offline, no proxy needed).")
  .argument("<tarball>", "path to a .tgz package tarball")
  .option("--json", "emit the raw JSON report", false)
  .action(async (tarballPath: string, opts: { json: boolean }) => {
    const tarball = readFileSync(tarballPath) as Buffer;
    const name = tarballPath.split("/").pop()?.replace(/\.tgz$/, "") ?? "local";
    const report = await auditTarball({
      meta: {
        name, version: "local", author: null, maintainers: [], license: null,
        hasInstallScripts: false, signatureStatus: "unknown",
      },
      tarball,
    });
    emit(report, opts.json);
    process.exitCode = verdictExitCode(report.verdict);
  });

program
  .command("install")
  .description("Run `npm install` with resolution routed through the Sentinel proxy.")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .allowUnknownOption(true)
  .argument("[args...]", "arguments passed straight to npm install")
  .action((args: string[], opts: { proxy: string }) => runNpm("install", args, opts.proxy));

program
  .command("npx")
  .description("Run `npx` with resolution routed through the Sentinel proxy.")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .allowUnknownOption(true)
  .argument("[args...]", "arguments passed straight to npx")
  .action((args: string[], opts: { proxy: string }) => runBin("npx", args, opts.proxy));

program
  .command("manifest")
  .description("Show a package's requested capabilities and approval state (no install).")
  .argument("<package>")
  .argument("[version]")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--json", "emit raw JSON", false)
  .action(async (pkg: string, version: string | undefined, opts: { proxy: string; json: boolean }) => {
    try {
      const v = version ?? (await resolveLatest(opts.proxy, pkg));
      const m = await fetchManifest(opts.proxy, pkg, v);
      console.log(opts.json ? JSON.stringify(m, null, 2) : formatManifest(m));
    } catch (err) {
      fail(err, opts.proxy);
    }
  });

program
  .command("approve")
  .description("Record an approval (or denial) for a package version's capabilities.")
  .argument("<package>")
  .argument("<version>")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--deny", "record a denial instead of an approval", false)
  .option("--reason <reason>", "optional rationale recorded with the decision")
  .action(async (pkg: string, version: string, opts: { proxy: string; deny: boolean; reason?: string }) => {
    try {
      const m = await fetchManifest(opts.proxy, pkg, version);
      await postApproval(opts.proxy, [{ name: m.meta.name, version: m.meta.version, integrity: m.meta.integrity }], !opts.deny, opts.reason);
      console.log(`${opts.deny ? "denied" : "approved"} ${pkg}@${version}`);
    } catch (err) {
      fail(err, opts.proxy);
    }
  });

program
  .command("preflight")
  .description("Resolve a package's tree, show capabilities needing approval, and optionally approve them.")
  .argument("<package>")
  .argument("[version]")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--approve", "approve every capability the tree requires", false)
  .action(async (pkg: string, version: string | undefined, opts: { proxy: string; approve: boolean }) => {
    try {
      const v = version ?? (await resolveLatest(opts.proxy, pkg));
      const manifests = [await fetchManifest(opts.proxy, pkg, v)];
      for (const m of manifests) console.log(formatManifest(m));
      const plan = planApprovals(manifests);
      if (plan.length === 0) {
        console.log("Nothing to approve — all capabilities are inherited or already approved.");
        return;
      }
      if (opts.approve) {
        await postApproval(opts.proxy, plan, true);
        console.log(`approved ${plan.length} package version(s).`);
      } else {
        console.log(`\n${plan.length} package version(s) need approval. Re-run with --approve, or use \`sentinel approve\`.`);
      }
    } catch (err) {
      fail(err, opts.proxy);
    }
  });

if (process.argv[1]?.endsWith("index.ts") || process.argv[1]?.endsWith("index.js")) program.parseAsync();

// ---------------------------------------------------------------------------

export function planApprovals(manifests: Manifest[]): { name: string; version: string; integrity: string }[] {
  return manifests
    .filter((m) => m.approvalState === "required")
    .map((m) => ({ name: m.meta.name, version: m.meta.version, integrity: m.meta.integrity }));
}

async function fetchManifest(proxy: string, pkg: string, version: string): Promise<Manifest> {
  const res = await fetch(`${proxy}/-/manifest/${encodeURIComponent(pkg)}/${encodeURIComponent(version)}`);
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? `manifest failed: ${res.status}`);
  }
  return (await res.json()) as Manifest;
}

async function postApproval(
  proxy: string,
  decision: { name: string; version: string; integrity: string }[],
  approved: boolean,
  reason?: string,
): Promise<void> {
  const res = await fetch(`${proxy}/-/approvals`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(decision.map((d) => ({
      ...d, decision: approved ? "approved" : "denied",
      actor: { type: "agent", id: process.env.USER ?? "cli" }, reason,
    }))),
  });
  if (!res.ok) throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? `approval failed: ${res.status}`);
}

// ---------------------------------------------------------------------------

async function resolveLatest(proxy: string, pkg: string): Promise<string> {
  const res = await fetch(`${proxy}/${encodeURIComponent(pkg).replace("%40", "@")}`);
  if (!res.ok) throw new Error(`could not resolve ${pkg}: ${res.status}`);
  const doc = (await res.json()) as { "dist-tags"?: Record<string, string> };
  const latest = doc["dist-tags"]?.latest;
  if (!latest) throw new Error(`no latest dist-tag for ${pkg}`);
  return latest;
}

async function fetchAudit(proxy: string, pkg: string, version: string): Promise<AuditReport> {
  const res = await fetch(`${proxy}/-/audit/${encodeURIComponent(pkg)}/${encodeURIComponent(version)}`);
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? `audit failed: ${res.status}`);
  }
  return (await res.json()) as AuditReport;
}

function emit(report: AuditReport, json: boolean): void {
  if (json) console.log(JSON.stringify(report, null, 2));
  else console.log(formatReport(report));
}

function runNpm(sub: string, args: string[], proxy: string): void {
  runBin("npm", [sub, "--registry", proxy, ...args], proxy);
}

function runBin(bin: string, args: string[], proxy: string): void {
  const finalArgs = bin === "npx" ? ["--registry", proxy, ...args] : args;
  console.error(`\x1b[90m$ ${bin} ${finalArgs.join(" ")}\x1b[0m`);
  const child = spawn(bin, finalArgs, { stdio: "inherit", shell: false });
  child.on("exit", (code) => process.exit(code ?? 0));
  child.on("error", (err) => fail(err, proxy));
}

function fail(err: unknown, proxy: string): void {
  const msg = (err as Error)?.message ?? String(err);
  console.error(`\x1b[31msentinel: ${msg}\x1b[0m`);
  if (/ECONNREFUSED|fetch failed/i.test(msg)) {
    console.error(`\x1b[90mIs the proxy running? Start it with: npm run proxy  (expected at ${proxy})\x1b[0m`);
  }
  process.exit(2);
}
