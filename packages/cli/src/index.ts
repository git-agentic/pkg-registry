#!/usr/bin/env node
import { Buffer } from "node:buffer";
import { lstatSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, relative } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHash, createPublicKey } from "node:crypto";
import { Command } from "commander";
import {
  auditTarball, type AuditReport,
  loadPolicy, signPolicy, generateKeypair, policyHashOfBytes,
  type EnterprisePolicy,
  extractCapabilities, capabilityAtom, type Capability, type PackageFile,
  type TreeAuditResult,
  parseAnyLockfile, type Coordinate,
  toCycloneDX,
  signToken, verifyToken, type Role,
  buildAuditStatement, signAttestation, verifyAttestation, attestationKeyid,
} from "@sentinel/core";
import { createSandbox, runLifecycleScripts } from "@sentinel/sandbox";
import { formatReport, formatManifest, verdictExitCode, formatTree, treeExitCode, formatViolations, formatStats, formatHistory, formatExplain, type Manifest, type ViolationRow, type ExplainResult } from "./format.js";

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
        hasInstallScripts: false,
      },
      tarball,
    });
    emit(report, opts.json);
    process.exitCode = verdictExitCode(report.verdict);
  });

program
  .command("audit-tree")
  .description("Audit every package in a resolved lockfile (npm/yarn/pnpm); exits non-zero when the tree is gated.")
  .argument("[lockfile]", "path to package-lock.json / yarn.lock / pnpm-lock.yaml", "package-lock.json")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--omit <type>", "omit a dependency group (only 'dev' is supported)")
  .option("--sbom <file>", "write a CycloneDX 1.6 SBOM of the audited tree to <file>")
  .option("--fail-on-error", "gate (exit non-zero) when any package fails to audit", false)
  .option("--json", "emit the raw JSON result", false)
  .action(async (lockfile: string, opts: { proxy: string; omit?: string; sbom?: string; failOnError: boolean; json: boolean }) => {
    try {
      const coords = parseAnyLockfile(readFileSync(lockfile, "utf8"), { filename: lockfile, omitDev: opts.omit === "dev" });
      const result = await fetchTree(opts.proxy, coords, opts.failOnError);
      if (opts.sbom) {
        writeFileSync(opts.sbom, JSON.stringify(toCycloneDX(result, { now: new Date().toISOString() }), null, 2));
        console.error(`\x1b[90mwrote CycloneDX SBOM → ${opts.sbom}\x1b[0m`);
      }
      if (opts.json) console.log(JSON.stringify(result, null, 2));
      else console.log(formatTree(result));
      process.exitCode = treeExitCode(result);
    } catch (err) {
      fail(err, opts.proxy);
    }
  });

program
  .command("install")
  .description("Run `npm install` with resolution routed through the Sentinel proxy (add --enforce to sandbox every lifecycle script).")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--enforce", "run every lifecycle script in the tree under the sandbox (fail-closed)", false)
  .option("--approve <cap...>", "capabilities to approve for the ROOT project's own scripts (kind:target)", [])
  .allowUnknownOption(true)
  .argument("[args...]", "arguments passed straight to npm install")
  .action((args: string[], opts: { proxy: string; enforce: boolean; approve: string[] }) => {
    if (!opts.enforce) return runNpm("install", args, opts.proxy);
    let sandbox;
    try { sandbox = createSandbox(); } catch (e) {
      console.error(`\x1b[31msentinel: --enforce unavailable: ${(e as Error).message}\x1b[0m`);
      process.exit(2);
    }
    void sandbox;   // constructed only to fail fast here; the wrapper builds its own per script
    const wrapperPath = fileURLToPath(new URL("./script-shell.js", import.meta.url));
    const env = enforceNpmEnv(process.env, { proxy: opts.proxy, wrapperPath, approve: opts.approve });
    runNpmWithEnv("install", args, opts.proxy, env);
  });

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
  .command("explain")
  .description("Explain a package's verdict and how to remediate it: per-finding actions, a suggested known-good version, and a ready waiver.")
  .argument("<package>")
  .argument("<version>")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .action(async (pkg: string, version: string, opts: { proxy: string }) => {
    try {
      const res = await fetch(`${opts.proxy}/-/explain/${encodeURIComponent(pkg)}/${encodeURIComponent(version)}`);
      if (!res.ok) return fail(new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? `explain failed: ${res.status}`), opts.proxy);
      console.log(formatExplain(await res.json() as ExplainResult));
    } catch (err) {
      fail(err, opts.proxy);
    }
  });

program
  .command("violations")
  .description("List runtime violations recorded by the proxy (quarantined builds).")
  .option("--proxy <url>", "proxy base URL", DEFAULT_PROXY)
  .option("--json", "output raw JSON", false)
  .action(async (opts: { proxy: string; json: boolean }) => {
    const res = await fetch(`${opts.proxy}/-/violations`);
    if (!res.ok) { console.error(`failed: ${res.status}`); process.exit(1); }
    const { violations } = (await res.json()) as { violations: ViolationRow[] };
    if (opts.json) console.log(JSON.stringify(violations, null, 2));
    else console.log(formatViolations(violations));
  });

program
  .command("stats")
  .description("Show durable audit/violation metrics (requires the proxy's SENTINEL_HISTORY_DB).")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .action(async (opts: { proxy: string }) => {
    const res = await fetch(`${opts.proxy}/-/metrics`);
    if (res.status === 501) { console.log("history not enabled — set SENTINEL_HISTORY_DB on the proxy"); return; }
    if (!res.ok) return fail(new Error(`metrics failed: ${res.status}`), opts.proxy);
    const m = (await res.json()) as { summary: { total: number; verdict: { allow: number; warn: number; block: number }; violations: number; quarantined: number }; trends: { date: string; allow: number; warn: number; block: number }[]; topFlagged: { name: string; warn: number; block: number }[] };
    console.log(formatStats(m));
  });

program
  .command("history")
  .description("List recorded audits (requires the proxy's SENTINEL_HISTORY_DB).")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--verdict <v>", "filter by verdict (allow|warn|block)")
  .option("--name <name>", "filter by package name")
  .option("--limit <n>", "max rows", "50")
  .action(async (opts: { proxy: string; verdict?: string; name?: string; limit: string }) => {
    const qs = new URLSearchParams();
    if (opts.verdict) qs.set("verdict", opts.verdict);
    if (opts.name) qs.set("name", opts.name);
    qs.set("limit", opts.limit);
    const res = await fetch(`${opts.proxy}/-/history?${qs}`);
    if (res.status === 501) { console.log("history not enabled — set SENTINEL_HISTORY_DB on the proxy"); return; }
    if (!res.ok) return fail(new Error(`history failed: ${res.status}`), opts.proxy);
    const { history } = (await res.json()) as { history: { name: string; version: string; verdict: string; score: number; topFinding: string | null; auditedAt: string }[] };
    console.log(formatHistory(history));
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
      writeFileSync(`${opts.out}.key.pem`, privateKey, { mode: 0o600 });
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

const tokenCmd = program.command("token").description("Mint and verify signed control-plane auth tokens.");

tokenCmd
  .command("keygen")
  .description("Generate an Ed25519 keypair (PEM) for signing auth tokens.")
  .requiredOption("--out <prefix>", "write <prefix>.pub.pem and <prefix>.key.pem")
  .action((opts: { out: string }) => {
    const { publicKey, privateKey } = generateKeypair();
    writeFileSync(`${opts.out}.pub.pem`, publicKey);
    writeFileSync(`${opts.out}.key.pem`, privateKey, { mode: 0o600 });
    console.log(`wrote ${opts.out}.pub.pem and ${opts.out}.key.pem`);
  });

tokenCmd
  .command("mint")
  .description("Mint a signed role token (prints to stdout).")
  .requiredOption("--role <role>", "operator | agent | publisher")
  .requiredOption("--sub <id>", "subject identity recorded in the token")
  .requiredOption("--ttl <seconds>", "seconds until the token expires")
  .requiredOption("--key <privkey>", "path to the Ed25519 private key PEM")
  .action((opts: { role: string; sub: string; ttl: string; key: string }) => {
    const roles = ["operator", "agent", "publisher"];
    if (!roles.includes(opts.role)) {
      console.error(`sentinel: --role must be one of ${roles.join(", ")}`);
      process.exit(2);
    }
    const token = signToken({ role: opts.role as Role, sub: opts.sub, ttlSeconds: Number(opts.ttl) }, readFileSync(opts.key, "utf8"));
    console.log(token);
  });

tokenCmd
  .command("verify")
  .description("Verify a token and print its role/sub/exp, or the rejection reason.")
  .argument("<token>")
  .requiredOption("--pubkey <pubkey>", "path to the Ed25519 public key PEM")
  .action((token: string, opts: { pubkey: string }) => {
    const r = verifyToken(token, readFileSync(opts.pubkey, "utf8"));
    if (r.ok) {
      console.log(`valid  role=${r.role}  sub=${r.sub}  exp=${new Date(r.exp * 1000).toISOString()}`);
    } else {
      console.error(`invalid: ${r.reason}`);
      process.exit(2);
    }
  });

// NOTE: commander 15 does not support a parent command that has BOTH subcommands
// AND its own default .argument/.action with requiredOptions — the parent's
// requiredOptions get enforced even when routing to a subcommand (verified via a
// minimal repro), so `attest keygen` + `attest <lockfile>` as parent+subcommand
// silently fails ("required option ... not specified" even when it *was* passed).
// Falling back to two sibling top-level commands: `attest-keygen` and `attest`.
program
  .command("attest-keygen")
  .description("Generate an Ed25519 attestation signing keypair.")
  .requiredOption("--out <prefix>", "output path prefix (writes <prefix>.pub.pem and <prefix>.key.pem)")
  .action((opts: { out: string }) => {
    const { publicKey, privateKey } = generateKeypair();
    writeFileSync(`${opts.out}.pub.pem`, publicKey);
    writeFileSync(`${opts.out}.key.pem`, privateKey, { mode: 0o600 });
    console.log(`wrote ${opts.out}.pub.pem / ${opts.out}.key.pem\nkeyid: ${attestationKeyid(publicKey)}`);
  });

program
  .command("attest")
  .description("Produce a signed Sentinel audit attestation (VSA) for a dependency tree.")
  .argument("[lockfile]", "path to the lockfile", "package-lock.json")
  .requiredOption("--key <file>", "Ed25519 private key PEM to sign with")
  .requiredOption("--out <file>", "where to write the DSSE attestation JSON")
  .option("--sbom <file>", "where to write the CycloneDX SBOM", "sentinel-sbom.json")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .action(async (lockfile: string, opts: { key: string; out: string; sbom: string; proxy: string }) => {
    try {
      const coords = parseAnyLockfile(readFileSync(lockfile, "utf8"), { filename: lockfile });
      const result = await fetchTree(opts.proxy, coords);
      const sbom = JSON.stringify(toCycloneDX(result, { now: new Date().toISOString() }), null, 2);
      writeFileSync(opts.sbom, sbom);
      const sbomDigest = createHash("sha256").update(Buffer.from(sbom)).digest("hex");
      const stmt = buildAuditStatement(result, { sbomDigest, sbomName: opts.sbom, now: new Date().toISOString() });
      const keyPem = readFileSync(opts.key, "utf8");
      const pubPem = createPublicKey(keyPem).export({ type: "spki", format: "pem" }).toString();
      const env = signAttestation(stmt, keyPem, attestationKeyid(pubPem));
      writeFileSync(opts.out, JSON.stringify(env, null, 2));
      console.log(`attested ${result.aggregate.verdict} · subject sha256:${sbomDigest.slice(0, 16)}… → ${opts.out}`);
    } catch (err) {
      fail(err, opts.proxy);
    }
  });

program
  .command("verify-attestation")
  .description("Verify a Sentinel audit attestation offline against a pinned public key (a deploy gate).")
  .argument("<attestation>", "path to the DSSE attestation JSON")
  .requiredOption("--key <file>", "pinned Ed25519 public key PEM")
  .option("--sbom <file>", "the SBOM the attestation must bind to (checks subject digest)")
  .option("--policy-hash <hash>", "require this policy hash")
  .option("--require <level>", "require verdict: allow | allow-or-warn")
  .action((attFile: string, opts: { key: string; sbom?: string; policyHash?: string; require?: string }) => {
    const env: unknown = JSON.parse(readFileSync(attFile, "utf8"));
    const expectedSbomDigest = opts.sbom ? createHash("sha256").update(readFileSync(opts.sbom)).digest("hex") : undefined;
    const requireVerdict = opts.require === "allow" || opts.require === "allow-or-warn" ? opts.require : undefined;
    const r = verifyAttestation(env, readFileSync(opts.key, "utf8"), { expectedSbomDigest, expectedPolicyHash: opts.policyHash, requireVerdict });
    if (r.valid) {
      console.log(`✓ valid · verdict ${r.predicate.verdict} · policy ${r.predicate.policyHash ?? "?"} · ${r.predicate.timestamp}`);
    } else {
      console.error(`✗ attestation rejected: ${r.reason}`);
      process.exitCode = 2;
    }
  });

program
  .command("run-scripts")
  .description("Run a package's lifecycle scripts under a sandbox derived from its approved capabilities (macOS Seatbelt / Linux bubblewrap).")
  .argument("<package-dir>", "path to an unpacked package directory")
  .option("--approve <cap...>", "approved capabilities as kind:target (e.g. network:api.example.com)", [])
  .action((dir: string, opts: { approve: string[] }) => {
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
    if (approved.some((c) => c.kind === "network")) {
      console.error("\x1b[33mNote: network approval is all-or-nothing — approving any host grants the script ALL network egress (the sandbox cannot host-filter; per-host fidelity is enforced at the proxy, not here).\x1b[0m");
    }
    if (approved.some((c) => c.kind === "env")) {
      console.error("\x1b[33mNote: credential-shaped env-vars are scrubbed; approved env capabilities are passed through.\x1b[0m");
    } else {
      console.error("\x1b[33mNote: credential-shaped env-vars are scrubbed by default (fail-closed). Grant one with --approve env:NAME.\x1b[0m");
    }
    let results: ReturnType<typeof runLifecycleScripts>["results"];
    let failed: boolean;
    try {
      const sandbox = createSandbox();
      ({ results, failed } = runLifecycleScripts({ packageDir: dir, sandbox, approved, homeDir: homedir() }));
    } catch (e) {
      console.error(`\x1b[31msentinel: ${(e as Error).message}\x1b[0m`);
      process.exit(2);
    }

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

export function enforceNpmEnv(base: NodeJS.ProcessEnv, opts: { proxy: string; wrapperPath: string; approve: string[] }): NodeJS.ProcessEnv {
  return {
    ...base,
    npm_config_script_shell: opts.wrapperPath,
    SENTINEL_ENFORCE: "1",
    SENTINEL_PROXY: opts.proxy,
    SENTINEL_APPROVE: opts.approve.join(" "),
  };
}

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
    if (!["network", "filesystem", "process", "native", "env"].includes(kind) || !target) continue;
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

async function fetchTree(proxy: string, packages: Coordinate[], failOnError = false): Promise<TreeAuditResult> {
  const res = await fetch(`${proxy}/-/audit-tree`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ packages, failOnError }),
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? `tree audit failed: ${res.status}`);
  }
  return (await res.json()) as TreeAuditResult;
}

function emit(report: AuditReport, json: boolean): void {
  if (json) console.log(JSON.stringify(report, null, 2));
  else console.log(formatReport(report));
}

function runNpm(sub: string, args: string[], proxy: string): void {
  runBin("npm", [sub, "--registry", proxy, ...args], proxy);
}

function runNpmWithEnv(sub: string, args: string[], proxy: string, env: NodeJS.ProcessEnv): void {
  const finalArgs = [sub, "--registry", proxy, ...args];
  console.error(`\x1b[90m$ npm ${finalArgs.join(" ")}  (enforced)\x1b[0m`);
  const child = spawn("npm", finalArgs, { stdio: "inherit", shell: false, env });
  child.on("exit", (code) => process.exit(code ?? 0));
  child.on("error", (err) => fail(err, proxy));
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
