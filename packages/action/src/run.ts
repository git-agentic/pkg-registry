import { existsSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import {
  createServer, AuditStore, ApprovalStore, PrivatePackageStore, ViolationStore, ApprovalRequestStore,
  type Upstream,
} from "@sentinel/proxy";
import { parseAnyLockfile, toCycloneDX, DEFAULT_POLICY, type EnterprisePolicy, type TreeAuditResult } from "@sentinel/core";
import { renderPrComment } from "./report.js";

export interface RunCiOptions {
  upstream: Upstream;
  cwd: string;
  lockfile?: string;
  policy?: EnterprisePolicy;
  sbomPath: string;
  failOn: "block" | "warn" | "none";
  omitDev: boolean;
  now: string;
  env: NodeJS.ProcessEnv;
}
export interface CiResult {
  exitCode: number;
  result: TreeAuditResult;
  sbomPath: string;
  markdown: string;
}

const LOCKFILES = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"];

function detectLockfile(cwd: string, explicit?: string): string {
  if (explicit) {
    const p = explicit.startsWith("/") ? explicit : join(cwd, explicit);
    if (!existsSync(p)) throw new Error(`lockfile not found: ${p}`);
    return p;
  }
  for (const name of LOCKFILES) {
    const p = join(cwd, name);
    if (existsSync(p)) return p;
  }
  throw new Error(`no lockfile found in ${cwd} (looked for ${LOCKFILES.join(", ")})`);
}

const VERDICT_RANK: Record<string, number> = { allow: 0, warn: 1, block: 2 };

function exitFor(agg: TreeAuditResult["aggregate"], failOn: RunCiOptions["failOn"]): number {
  if (failOn === "none") return 0;
  const need = failOn === "warn" ? 1 : 2;
  if (VERDICT_RANK[agg.verdict]! >= need) return 2;
  if (agg.gated) return 2; // server-side gate (treeGate / failOnError on error rows)
  return 0;
}

/** Run a self-contained CI tree audit: self-boot the proxy, audit the lockfile tree, write the
 *  SBOM + GitHub-native outputs, and compute the fail-on exit code. Injectable upstream + env. */
export async function runCi(opts: RunCiOptions): Promise<CiResult> {
  const lockPath = detectLockfile(opts.cwd, opts.lockfile);
  const coords = parseAnyLockfile(readFileSync(lockPath, "utf8"), { filename: lockPath, omitDev: opts.omitDev });

  const app = createServer({
    upstream: opts.upstream,
    store: new AuditStore(), approvals: new ApprovalStore(),
    enterprisePolicy: opts.policy ?? DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(),
  });
  const server: Server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
  try {
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const res = await fetch(`${base}/-/audit-tree`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ packages: coords, failOnError: opts.failOn !== "none" }),
    });
    if (!res.ok) throw new Error(`audit-tree failed: ${res.status}`);
    const result = (await res.json()) as TreeAuditResult;

    writeFileSync(opts.sbomPath, JSON.stringify(toCycloneDX(result, { now: opts.now }), null, 2));
    const markdown = renderPrComment(result, { now: opts.now });
    const exitCode = exitFor(result.aggregate, opts.failOn);

    // GitHub-native surfacing (all defensive — absent env ⇒ stdout).
    if (opts.env.GITHUB_STEP_SUMMARY) writeFileSync(opts.env.GITHUB_STEP_SUMMARY, markdown);
    else console.log(markdown);
    if (opts.env.GITHUB_OUTPUT) {
      const c = result.aggregate.counts;
      appendFileSync(opts.env.GITHUB_OUTPUT,
        `verdict=${result.aggregate.verdict}\ngated=${result.aggregate.gated}\n` +
        `blocked=${c.block}\nwarned=${c.warn}\nerrored=${c.error}\nsbom-path=${opts.sbomPath}\n`);
    }
    if (opts.env.SENTINEL_COMMENT_BODY) writeFileSync(opts.env.SENTINEL_COMMENT_BODY, markdown);
    for (const p of result.packages) {
      if (p.status === "block") console.log(`::error::${p.name}@${p.version} — ${p.topFinding ?? p.error ?? "blocked"}`);
      else if (p.status === "warn") console.log(`::warning::${p.name}@${p.version} — ${p.topFinding ?? "warn"}`);
    }

    return { exitCode, result, sbomPath: opts.sbomPath, markdown };
  } finally {
    server.close();
  }
}
