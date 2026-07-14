// packages/proxy/test/violation-enforce-e2e.test.ts
//
// Full-chain e2e: install a benign fixture whose postinstall PROPAGATES a denied filesystem
// read (unlike enforce-probe, which swallows the EPERM and exits 0), under `sentinel install
// --enforce`. The sandboxed runner classifies the denial as a violation (Task 3), the script-shell
// reports it to the proxy (Task 6), and the proxy records + quarantines the integrity and 403s any
// future serve of that build (Task 5). This test proves that whole chain end to end.
//
// Note: the fixture's postinstall exits non-zero (the propagating EPERM), so npm may report the
// install (or its postinstall) as failed. We deliberately do NOT assert on npm's exit status —
// only on the violation record existing and the re-serve 403ing. The script-shell reports the
// violation to the proxy BEFORE the non-zero exit code propagates back to npm, so the record
// exists regardless of how npm ultimately treats the failed postinstall.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, realpathSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";
import { DEFAULT_POLICY, generateKeypair, signToken, type AuditReport } from "@agentic-sentinel/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "..", "..", "fixtures");
// Use the BUILT wrapper (plain node — no tsx). The shim runs in a temp project cwd where a bare
// `tsx` specifier would NOT resolve, so pointing at compiled dist/ is what makes the shim work.
const CLI_DIST_SHELL = join(HERE, "..", "..", "cli", "dist", "script-shell.js");

function ensureFixtures() {
  if (!existsSync(join(FIXTURES, "registry.json")))
    execFileSync("npx", ["tsx", join(HERE, "..", "..", "..", "scripts", "make-fixtures.ts")], { stdio: "ignore" });
}
function ensureBuilt() {
  // The e2e test needs the compiled wrapper. `npm test` is preceded by `npm run build`, but build if missing.
  if (!existsSync(CLI_DIST_SHELL))
    execFileSync("npx", ["tsc", "--build", "--force", join(HERE, "..", "..", "cli")], { stdio: "ignore" });
}

// Sandbox availability: darwin always; linux only when bwrap can create namespaces.
const sandboxWorks = (() => {
  if (process.platform === "darwin") return true;
  if (process.platform !== "linux") return false;
  const r = spawnSync("bwrap", ["--ro-bind", "/", "/", "--dev", "/dev", "true"], { encoding: "utf8" });
  return !r.error && r.status === 0;
})();

describe("install --enforce (e2e): a propagating violation is reported and quarantines the build", {
  skip: sandboxWorks ? false : "requires a working sandbox (Seatbelt on darwin / bwrap on Linux)",
}, () => {
  let server: Server; let base: string;
  // Auto-quarantine is opt-in AND auth-gated (Task B2 / ADR-0040): boot with auth enabled so the
  // script-shell's reported violation (carrying an agent token below) can actually quarantine.
  const { publicKey, privateKey } = generateKeypair();
  const agentToken = signToken({ role: "agent", sub: "e2e", ttlSeconds: 3600 }, privateKey);

  before(async () => {
    ensureFixtures();
    ensureBuilt();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(), approvals: new ApprovalStore(),
      enterprisePolicy: DEFAULT_POLICY, policy: "block",
      violations: new ViolationStore(),
      approvalRequests: new ApprovalRequestStore(),
      authPublicKey: publicKey, autoQuarantine: true,
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  // Approve + install `pkg@1.0.0` into a temp HOME under enforcement, mirroring enforce-e2e's helper.
  async function enforcedInstall(pkg: string, enforce: boolean): Promise<{ dir: string }> {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "viol-home-")));
    // Plant the "secret" the fs probe will try (and be denied) to read. Without a real file here,
    // the denied read yields ENOENT (unclassified), not EPERM (classified) — Task 3's finding.
    mkdirSync(join(home, ".ssh"), { recursive: true });
    writeFileSync(join(home, ".ssh", "id_rsa"), "TOPSECRET-VIOLATION-KEY");

    const m = await (await fetch(`${base}/-/manifest/${pkg}/1.0.0`)).json() as any;
    const operatorToken = signToken({ role: "operator", sub: "e2e", ttlSeconds: 3600 }, privateKey);
    await fetch(`${base}/-/approvals`, {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${operatorToken}` },
      body: JSON.stringify([{ name: pkg, version: "1.0.0", integrity: m.meta.integrity, decision: "approved", actor: { type: "test", id: "e2e" } }]),
    });
    const proj = realpathSync(mkdtempSync(join(home, "proj-")));
    writeFileSync(join(proj, "package.json"), JSON.stringify({ name: "consumer", version: "1.0.0" }));
    // executable script-shell shim → runs our wrapper under tsx (no build needed)
    const shim = join(proj, "shim.sh");
    writeFileSync(shim, `#!/bin/sh\nexec node "${CLI_DIST_SHELL}" "$@"\n`);
    chmodSync(shim, 0o755);
    const env: NodeJS.ProcessEnv = {
      ...process.env, HOME: home, npm_config_cache: join(home, ".npmcache"), npm_config_audit: "false", npm_config_fund: "false",
    };
    if (enforce) Object.assign(env, { npm_config_script_shell: shim, SENTINEL_ENFORCE: "1", SENTINEL_PROXY: base, SENTINEL_AUTH_TOKEN: agentToken });
    // Use async spawn (not spawnSync): the proxy runs on THIS process's event loop, and a blocking
    // spawnSync would freeze it — npm (a child) could never fetch packument/tarball/manifest from the
    // in-process proxy, deadlocking the install. Awaiting keeps the loop free to serve the request path.
    let out = "";
    await new Promise<void>((resolve) => {
      const child = spawn("npm", ["install", `${pkg}@1.0.0`, "--registry", base, "--no-audit", "--no-fund"], {
        cwd: proj, env,
      });
      // The fixture's postinstall exits non-zero (the propagating EPERM); npm may abort the install
      // or report a failed postinstall. We don't assert on npm's exit code — only that the
      // script-shell reported the violation before the non-zero code propagated (asserted below).
      child.stdout?.on("data", (d: Buffer) => (out += d.toString()));
      child.stderr?.on("data", (d: Buffer) => (out += d.toString()));
      child.on("close", () => resolve());
    });
    return { dir: join(proj, "node_modules", pkg), out };
  }

  test("ENFORCED: the propagating ssh read is contained; on Seatbelt it is also reported and quarantines the build", async () => {
    const { out } = await enforcedInstall("violation-fs-probe", true);

    // Containment (BOTH backends): the planted credential read is blocked — the probe hits a
    // permission/absent error on the .ssh path and never obtains the secret. On Seatbelt the deny
    // yields EPERM; on bwrap the tmpfs mask empties ~/.ssh so the read fails ENOENT.
    assert.match(out, /(EPERM|EACCES|ENOENT)[\s\S]*\.ssh/, `the sandbox must have blocked the credential read; npm+shim output:\n${out.slice(-1500)}`);
    assert.ok(!out.includes("TOPSECRET-VIOLATION-KEY"), "the planted secret must never be obtained under the sandbox");

    // Reporting + quarantine is Seatbelt-only. bwrap masks ~/.ssh via tmpfs → the read fails with
    // ENOENT, which classifyViolation does not classify (the accepted Seatbelt/bwrap telemetry
    // asymmetry — bwrap CONTAINS but does not REPORT credential reads; ADR-0023, Phase 25 Q5).
    // Seatbelt's read-deny yields EPERM, which IS classified, recorded, and quarantined.
    if (process.platform !== "darwin") return;

    const rep = await (await fetch(`${base}/-/audit/violation-fs-probe/1.0.0`)).json() as AuditReport;
    const integrity = rep.meta.integrity!;
    const listed = await (await fetch(`${base}/-/violations`)).json() as {
      violations: { integrity: string; kind: string; quarantined: boolean; evidence: { exitCode: number; stderrExcerpt: string } }[];
    };
    const rec = listed.violations.find((v) => v.integrity === integrity);
    assert.ok(rec && rec.kind === "filesystem" && rec.quarantined, `a confirmed fs violation must be recorded + quarantined; npm+shim output:\n${out.slice(-1500)}`);
    assert.notEqual(rec!.evidence.exitCode, 0, "positive control: the sandboxed probe must have actually exited non-zero");
    assert.match(rec!.evidence.stderrExcerpt, /EPERM|EACCES/, "positive control: the denial must carry a real permission-error signature");

    // Re-serving the same build now 403s.
    assert.equal((await fetch(`${base}/violation-fs-probe/-/violation-fs-probe-1.0.0.tgz`)).status, 403);
  });
});
