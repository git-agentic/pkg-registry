import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { DEFAULT_POLICY, generateKeypair, signPolicy } from "@git-agentic/sentinel-core";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const ENTRY = join(REPO_ROOT, "packages", "proxy", "src", "index.ts");

/** Boot the proxy with env, return { ok, output }. Exits fast: we only need startup. */
function boot(env: Record<string, string>): { ok: boolean; output: string } {
  try {
    const out = execFileSync("node", ["--import", "tsx", ENTRY], {
      cwd: REPO_ROOT,
      env: { ...process.env, ...env, SENTINEL_PORT: "0", SENTINEL_BOOT_EXIT: "1" },
      timeout: 15000,
      encoding: "utf8",
    });
    return { ok: true, output: out };
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string };
    return { ok: false, output: (err.stdout ?? "") + (err.stderr ?? "") };
  }
}

describe("proxy policy startup", () => {
  test("no policy configured → boots with the built-in default", () => {
    const r = boot({ SENTINEL_UPSTREAM: "fixtures" });
    assert.equal(r.ok, true);
    assert.match(r.output, /built-in default policy/i);
  });

  test("valid signed policy → boots and reports the version", () => {
    const { publicKey, privateKey } = generateKeypair();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-boot-"));
    const raw = Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, version: "acme-boot" }));
    writeFileSync(join(dir, "p.json"), raw);
    writeFileSync(join(dir, "p.json.sig"), signPolicy(raw, privateKey));
    writeFileSync(join(dir, "pub.pem"), publicKey);
    const r = boot({ SENTINEL_UPSTREAM: "fixtures",
      SENTINEL_POLICY_FILE: join(dir, "p.json"),
      SENTINEL_POLICY_PUBKEY: join(dir, "pub.pem") });
    assert.equal(r.ok, true);
    assert.match(r.output, /acme-boot/);
  });

  test("tampered policy → fails closed (non-zero exit)", () => {
    const { publicKey, privateKey } = generateKeypair();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-boot-"));
    const raw = Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, version: "acme-boot" }));
    writeFileSync(join(dir, "p.json"), raw);
    writeFileSync(join(dir, "p.json.sig"), signPolicy(raw, privateKey));
    writeFileSync(join(dir, "p.json"), Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, version: "tampered" }))); // mutate after signing
    writeFileSync(join(dir, "pub.pem"), publicKey);
    const r = boot({ SENTINEL_UPSTREAM: "fixtures",
      SENTINEL_POLICY_FILE: join(dir, "p.json"),
      SENTINEL_POLICY_PUBKEY: join(dir, "pub.pem") });
    assert.equal(r.ok, false, "must exit non-zero");
    assert.match(r.output, /signature|FATAL/i);
  });
});
