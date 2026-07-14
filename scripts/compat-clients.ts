import { execFile } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { DEFAULT_POLICY, integrityOf, runAudit } from "@agentic-sentinel/core";
import { createServer } from "../packages/proxy/src/server.js";
import { AuditStore } from "../packages/proxy/src/store.js";
import { ApprovalStore } from "../packages/proxy/src/approvals.js";
import { PrivatePackageStore } from "../packages/proxy/src/private-store.js";
import { LocalFixtureUpstream } from "../packages/proxy/src/upstream.js";
import { ViolationStore } from "../packages/proxy/src/violations.js";
import { ApprovalRequestStore } from "../packages/proxy/src/approval-requests.js";

const run = promisify(execFile);
const root = new URL("..", import.meta.url).pathname;
const fixtures = join(root, "fixtures");
const store = new PrivatePackageStore();
const tarball = readFileSync(join(fixtures, ".tarballs", "leftpad-lite-1.0.1.tgz"));
const integrity = integrityOf(tarball);
const audit = await runAudit({ meta: { name: "leftpad-lite", version: "1.0.1", author: null, maintainers: [], license: "MIT",
  hasInstallScripts: false, integrity }, tarball });
store.publish({ name: "leftpad-lite", version: "1.0.1", integrity,
  manifest: { name: "leftpad-lite", version: "1.0.1", main: "index.js", dist: { integrity } }, tarball, audit, actor: "compat" });

const app = createServer({ upstream: new LocalFixtureUpstream(fixtures), store: new AuditStore(), approvals: new ApprovalStore(),
  privateStore: store, enterprisePolicy: { ...DEFAULT_POLICY, privateNamespaces: ["leftpad-lite", "@compat/*"] }, policy: "observe",
  publishTokens: ["publish-token"],
  violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore() });
const server = await new Promise<Server>((resolve) => { const value = app.listen(0, () => resolve(value)); });
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

const tokenLine = `//${new URL(base).host}/:_authToken=publish-token`;
const clients: { name: string; bin: string; args: string[]; publish: string[]; preparePublish?: string[]; config?: (dir: string) => void; mutations?: string[][] }[] = [
  { name: "npm", bin: "npm", args: ["install", "leftpad-lite@1.0.1", "--registry", base, "--ignore-scripts", "--no-audit", "--no-fund"],
    publish: ["publish", "--registry", base], mutations: [["dist-tag", "add", "@compat/npm@1.0.0", "stable", "--registry", base], ["unpublish", "@compat/npm@1.0.0", "--force", "--registry", base]] },
  { name: "pnpm", bin: "pnpm", args: ["add", "leftpad-lite@1.0.1", "--registry", base, "--ignore-scripts"],
    publish: ["publish", "--registry", base, "--no-git-checks"], mutations: [["dist-tag", "add", "@compat/pnpm@1.0.0", "stable", "--registry", base], ["unpublish", "@compat/pnpm@1.0.0", "--force", "--registry", base]] },
  { name: "yarn-berry", bin: "npx", args: ["--yes", "@yarnpkg/cli-dist@4.9.2", "add", "leftpad-lite@1.0.1"],
    publish: ["--yes", "@yarnpkg/cli-dist@4.9.2", "npm", "publish"],
    mutations: [["--yes", "@yarnpkg/cli-dist@4.9.2", "npm", "tag", "add", "@compat/yarn-berry@1.0.0", "stable"]],
    preparePublish: ["--yes", "@yarnpkg/cli-dist@4.9.2", "install", "--no-immutable", "--mode=skip-build"],
    config: (dir) => writeFileSync(join(dir, ".yarnrc.yml"), `npmRegistryServer: "${base}"\nnpmAuthToken: "publish-token"\nnpmAlwaysAuth: true\nunsafeHttpWhitelist:\n  - 127.0.0.1\nenableScripts: false\nenableGlobalCache: false\nglobalFolder: .yarn/global\ncacheFolder: .yarn/cache\n`) },
  { name: "bun", bin: "bun", args: ["add", "leftpad-lite@1.0.1", "--registry", base, "--ignore-scripts"], publish: ["publish", "--registry", base] },
];

try {
  const pendingMutations: { client: (typeof clients)[number]; dir: string; env: NodeJS.ProcessEnv }[] = [];
  for (const client of clients) {
    const dir = await mkdtemp(join(tmpdir(), `sentinel-${client.name}-`));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: `compat-${client.name}`, version: "1.0.0", private: true }));
    writeFileSync(join(dir, ".npmrc"), `registry=${base}/\n${tokenLine}\n`);
    client.config?.(dir);
    const env = { ...process.env, CI: "1", ...(client.name === "yarn-berry" ? { npm_config_registry: "https://registry.npmjs.org" } : {}) };
    await run(client.bin, client.args, { cwd: dir, timeout: 60_000, env });
    console.log(`compat install: ${client.name} ✓`);
    const publishDir = join(dir, "publish");
    await import("node:fs/promises").then(({ mkdir }) => mkdir(publishDir));
    writeFileSync(join(publishDir, ".npmrc"), `registry=${base}/\n${tokenLine}\n`);
    client.config?.(publishDir);
    const packageName = `@compat/${client.name === "yarn-berry" ? "yarn-berry" : client.name}`;
    writeFileSync(join(publishDir, "package.json"), JSON.stringify({ name: packageName, version: "1.0.0", main: "index.js" }));
    writeFileSync(join(publishDir, "index.js"), "export default 1;\n");
    if (client.name === "yarn-berry") writeFileSync(join(publishDir, "yarn.lock"), "");
    if (client.preparePublish) await run(client.bin, client.preparePublish, { cwd: publishDir, timeout: 60_000, env });
    await run(client.bin, client.publish, { cwd: publishDir, timeout: 60_000, env });
    const published = await fetch(`${base}/${encodeURIComponent(packageName)}`);
    if (!published.ok) throw new Error(`${client.name} publish was not readable: ${published.status}`);
    console.log(`compat publish: ${client.name} ✓`);
    if (client.mutations?.length) pendingMutations.push({ client, dir, env });
  }
  for (const { client, dir, env } of pendingMutations) {
    for (const mutation of client.mutations ?? []) await run(client.bin, mutation, { cwd: dir, timeout: 60_000, env });
    console.log(`compat client-exposed mutations: ${client.name} ✓`);
  }
  for (const client of clients.filter((candidate) => candidate.name === "npm" || candidate.name === "pnpm")) {
    const packageName = `@compat/expired-${client.name}`;
    store.publish({ name: packageName, version: "1.0.0", integrity,
      manifest: { name: packageName, version: "1.0.0", dist: { integrity } }, tarball, audit, actor: "compat",
      publishedAt: new Date(Date.now() - 73 * 3_600_000).toISOString() });
    const dir = await mkdtemp(join(tmpdir(), `sentinel-expired-${client.name}-`));
    writeFileSync(join(dir, ".npmrc"), `registry=${base}/\n${tokenLine}\n`);
    const args = ["unpublish", `${packageName}@1.0.0`, "--force", "--registry", base];
    const ageHitsBefore = store.retractionWindowHits().age;
    let rejected = false;
    try { await run(client.bin, args, { cwd: dir, timeout: 60_000, env: { ...process.env, CI: "1" } }); }
    catch (error) {
      rejected = true;
      const output = `${(error as { stdout?: string }).stdout ?? ""}\n${(error as { stderr?: string }).stderr ?? ""}`;
      const expected = client.name === "npm" ? /retraction window closed|retraction-window-closed/i : /forbidden|permission to unpublish/i;
      if (!expected.test(output)) throw error;
    }
    if (!rejected) throw new Error(`${client.name} unexpectedly unpublished a package past the retraction window`);
    if (store.retractionWindowHits().age <= ageHitsBefore) throw new Error(`${client.name} rejection did not exercise the age-window state`);
    console.log(`compat past-window rejection: ${client.name} ✓`);
  }
} finally {
  server.close();
}
