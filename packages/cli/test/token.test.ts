import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "src", "index.ts");
const run = (args: string[]) => execFileSync("npx", ["tsx", CLI, ...args], { encoding: "utf8" });

describe("sentinel token", () => {
  test("keygen → mint → verify round-trips", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-tok-"));
    const prefix = join(dir, "auth");
    run(["token", "keygen", "--out", prefix]);
    assert.ok(existsSync(`${prefix}.pub.pem`) && existsSync(`${prefix}.key.pem`));
    const token = run(["token", "mint", "--role", "operator", "--sub", "alice", "--ttl", "3600", "--key", `${prefix}.key.pem`]).trim();
    assert.match(token, /^[\w-]+\.[\w-]+$/);
    const out = run(["token", "verify", token, "--pubkey", `${prefix}.pub.pem`]);
    assert.match(out, /operator/);
    assert.match(out, /alice/);
  });

  test("verify of a garbage token reports the rejection (non-zero exit)", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-tok-"));
    const prefix = join(dir, "auth");
    run(["token", "keygen", "--out", prefix]);
    assert.throws(() => run(["token", "verify", "not-a-token", "--pubkey", `${prefix}.pub.pem`]));
  });
});
