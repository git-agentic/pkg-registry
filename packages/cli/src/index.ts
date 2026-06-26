#!/usr/bin/env node
import { Buffer } from "node:buffer";
import { lstatSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative } from "node:path";
import { spawn } from "node:child_process";
import { Command } from "commander";
import {
  auditTarball, type AuditReport,
  loadPolicy, signPolicy, generateKeypair, policyHashOfBytes,
  type EnterprisePolicy,
  extractCapabilities, capabilityAtom, type Capability, type PackageFile,
} from "@sentinel/core";
import { generateProfile, SeatbeltSandbox, runLifecycleScripts } from "@sentinel/sandbox";
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

export function summarizePolicy(p: EnterprisePolicy): string {
  const t = p.scoring.thresholds;
  return [
    `version    ${p.version}`,
    `thresholds allow ${t.allow} · warn ${t.warn} · hardBlock ${p.scoring.hardBlockSeverity}`,
    `diffMult   ${p.scoring.diffMultiplier}`,
    `disabled: ${p.rules.disabled.length ? p.rules.disabled.join(", ") : "(none)"}`,
    `allow rules: ${p.allow.length}   deny rules: ${p.deny.length}`,
  ].join("\n  ");
}

const policyCmd = program.command("policy").description("Author, sign, and verify enterprise scoring policies.");

policyCmd
  .command("keygen")
  .description("Generate an Ed25519 keypair (PEM) for signing policies.")
  .option("--out <prefix>", "write <prefix>.pub.pem and <prefix>.key.pem instead of stdout")
  .action((opts: { out?: string }) => {
    const { publicKey, privateKey } = generateKeypair();
    if (opts.out) {
      writeFileSync(`${opts.out}.pub.pem`, publicKey);
      writeFileSync(`${opts.out}.key.pem`, privateKey);
      console.log(`wrote ${opts.out}.pub.pem and ${opts.out}.key.pem`);
    } else {
      console.log(publicKey + "\n" + privateKey);
    }
  });

policyCmd
  .command("sign")
  .description("Write a detached Ed25519 signature (<file>.sig) over a policy file.")
  .argument("<file>", "path to the policy JSON")
  .requiredOption("--key <privkey>", "path to the Ed25519 private key PEM")
  .action((file: string, opts: { key: string }) => {
    const raw = readFileSync(file);
    const sig = signPolicy(raw, readFileSync(opts.key, "utf8"));
    writeFileSync(`${file}.sig`, sig);
    console.log(`wrote ${file}.sig  (${policyHashOfBytes(raw)})`);
  });

policyCmd
  .command("verify")
  .description("Verify a policy's signature and print its summary.")
  .argument("<file>", "path to the policy JSON")
  .requiredOption("--pubkey <pubkey>", "path to the Ed25519 public key PEM")
  .option("--sig <sig>", "signature file (defaults to <file>.sig)")
  .action((file: string, opts: { pubkey: string; sig?: string }) => {
    const sig = opts.sig ?? `${file}.sig`;
    try {
      const { policy, hash } = loadPolicy({ file, sig, publicKeyPem: readFileSync(opts.pubkey, "utf8") });
      console.log(`✓ signature valid  ${hash}`);
      console.log("  " + summarizePolicy(policy));
    } catch (err) {
      console.error(`✗ ${(err as Error).message}`);
      process.exit(2);
    }
  });

program
  .command("run-scripts")
  .description("Run a package's lifecycle scripts under a sandbox derived from its approved capabilities (macOS).")
  .argument("<package-dir>", "path to an unpacked package directory")
  .option("--approve <cap...>", "approved capabilities as kind:target (e.g. network:api.example.com)", [])
  .action((dir: string, opts: { approve: string[] }) => {
    if (process.platform !== "darwin") {
      console.error("\x1b[31msentinel: sandbox enforcement is only available on macOS\x1b[0m");
      process.exit(2);
    }
    let scripts: Record<string, string> = {};
    try {
      scripts = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"))?.scripts ?? {};
    } catch {
      console.error(`\x1b[31msentinel: cannot read ${join(dir, "package.json")}\x1b[0m`);
      process.exit(2);
    }
    const hooks = ["preinstall", "install", "postinstall"].filter((h) => scripts[h]);
    if (hooks.length === 0) {
      console.log("No lifecycle scripts — nothing to enforce.");
      return;
    }
    const detected = extractCapabilities({ meta: {} as never, files: readPackageFiles(dir), mode: "full" });
    const approved = parseApprovals(opts.approve);
    const profile = generateProfile(approved, { homeDir: homedir() });
    const { results, failed } = runLifecycleScripts({ packageDir: dir, profile, sandbox: new SeatbeltSandbox() });

    for (const r of results) {
      console.log(`  ${r.hook}: \`${r.command}\` -> exit ${r.exitCode}`);
    }
    if (failed) {
      const unapproved = unapprovedAtoms(detected, approved);
      console.error("\x1b[33mA lifecycle script failed under sandbox enforcement.\x1b[0m");
      if (unapproved.length) {
        console.error("Detected, un-approved capabilities (likely cause — inferred from static analysis):");
        for (const a of unapproved) console.error(`  › ${a}`);
        console.error("Approve them (--approve <kind:target>) and retry, or treat the package as malicious.");
      }
      process.exit(1);
    }
    console.log(`Ran ${results.length} lifecycle script(s) under enforcement; no denied capability needed.`);
  });

if (process.argv[1]?.endsWith("index.ts") || process.argv[1]?.endsWith("index.js")) program.parseAsync();

// ---------------------------------------------------------------------------

export function planApprovals(manifests: Manifest[]): { name: string; version: string; integrity: string }[] {
  return manifests
    .filter((m) => m.approvalState === "required")
    .map((m) => ({ name: m.meta.name, version: m.meta.version, integrity: m.meta.integrity }));
}

export function parseApprovals(flags: string[]): Capability[] {
  const out: Capability[] = [];
  for (const f of flags) {
    const i = f.indexOf(":");
    if (i <= 0) continue;
    const kind = f.slice(0, i);
    const target = f.slice(i + 1);
    if (!["network", "filesystem", "process", "native"].includes(kind) || !target) continue;
    out.push({ kind: kind as Capability["kind"], target, evidence: [] });
  }
  return out;
}

export function unapprovedAtoms(detected: Capability[], approved: Capability[]): string[] {
  const approvedSet = new Set(approved.map(capabilityAtom));
  return detected.map(capabilityAtom).filter((a) => !approvedSet.has(a));
}

/** Read a package dir into PackageFile[] using the npm `package/<path>` convention. */
export function readPackageFiles(dir: string): PackageFile[] {
  const walk = (d: string, depth = 0): string[] => {
    if (depth > 50) return [];
    let entries: string[];
    try {
      entries = readdirSync(d);
    } catch {
      return [];
    }
    return entries.flatMap((n) => {
      const p = join(d, n);
      // lstatSync does NOT follow symlinks; a symlink is not isDirectory() here
      try {
        return lstatSync(p).isDirectory() ? walk(p, depth + 1) : [p];
      } catch {
        return [];
      }
    });
  };
  return walk(dir).map((p) => ({
    path: "package/" + relative(dir, p),
    content: safeRead(p),
    size: 0,
    changed: false,
  }));
}

function safeRead(p: string): string {
  try { return readFileSync(p, "utf8"); } catch { return ""; }
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
