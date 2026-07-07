/**
 * Self-contained end-to-end demo. Boots the proxy in-process against the local
 * fixtures under a `block` policy, then audits a benign package and the
 * trojaned release — showing the verdict panels and the proxy 403. No network,
 * no second terminal. Run: `npm run demo`.
 */
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "../packages/proxy/src/server.js";
import { AuditStore } from "../packages/proxy/src/store.js";
import { ApprovalStore } from "../packages/proxy/src/approvals.js";
import { PrivatePackageStore } from "../packages/proxy/src/private-store.js";
import { ViolationStore } from "../packages/proxy/src/violations.js";
import { LocalFixtureUpstream } from "../packages/proxy/src/upstream.js";
import { formatReport } from "../packages/cli/src/format.js";
import type { AuditReport } from "../packages/core/src/index.js";
import { DEFAULT_POLICY } from "@sentinel/core";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

async function main(): Promise<void> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(join(ROOT, "fixtures")),
    store: new AuditStore(),
    approvals: new ApprovalStore(),
    privateStore: new PrivatePackageStore(),
    violations: new ViolationStore(),
    enterprisePolicy: DEFAULT_POLICY,
    policy: "block",
  });
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const line = (s: string) => console.log(`\x1b[1m\x1b[34m${s}\x1b[0m`);

  line("\n══ 1. Benign package — leftpad-lite@1.0.1 ═══════════════════════");
  console.log(formatReport(await audit(base, "leftpad-lite", "1.0.1")));

  line("══ 2. Same package, clean prior release — color-stream@1.4.0 ════");
  console.log(formatReport(await audit(base, "color-stream", "1.4.0")));

  line("══ 3. Trojaned patch release — color-stream@1.4.1 (diff vs 1.4.0) ═");
  console.log(formatReport(await audit(base, "color-stream", "1.4.1")));

  line("══ 4. What `npm install` sees when it fetches the bad tarball ════");
  const res = await fetch(`${base}/color-stream/-/color-stream-1.4.1.tgz`);
  console.log(`  HTTP ${res.status}  x-sentinel-verdict: ${res.headers.get("x-sentinel-verdict")}  x-sentinel-score: ${res.headers.get("x-sentinel-score")}`);
  console.log(`  install is blocked before any code executes — the postinstall never runs.\n`);

  server.close();
}

async function audit(base: string, pkg: string, version: string): Promise<AuditReport> {
  const res = await fetch(`${base}/-/audit/${pkg}/${version}`);
  return (await res.json()) as AuditReport;
}

main();
