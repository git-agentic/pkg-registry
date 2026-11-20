import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import type { ProxyClient } from "../src/client.js";
import { TOOLS } from "../src/tools.js";

describe("sentinel_audit_tree forwards the whole lockfile coordinate", () => {
  test("nonRegistry and integrity reach the proxy, so a git dependency is not audited as its registry twin", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-lock-sec-"));
    const lock = join(dir, "package-lock.json");
    writeFileSync(lock, JSON.stringify({ lockfileVersion: 3, packages: {
      "": { name: "root" },
      "node_modules/leftpad-lite": { version: "1.0.0", integrity: "sha512-AAAA", resolved: "https://registry.npmjs.org/leftpad-lite/-/leftpad-lite-1.0.0.tgz" },
      "node_modules/color-stream": { version: "1.4.1", resolved: "git+ssh://git@github.com/evil/color-stream.git#abc123" },
    } }));
    let sent: { name: string; version: string; nonRegistry?: string; integrity?: string }[] = [];
    const client = { auditTree: async (packages: typeof sent) => {
      sent = packages;
      return { aggregate: { verdict: "block", gated: true, counts: { block: 1 } }, packages: [] };
    } } as unknown as ProxyClient;
    await TOOLS.find((t) => t.name === "sentinel_audit_tree")!.handler({ lockfile: lock }, client);
    const git = sent.find((p) => p.name === "color-stream");
    assert.match(git?.nonRegistry ?? "", /^git\+ssh:/);
    assert.equal(sent.find((p) => p.name === "leftpad-lite")?.integrity, "sha512-AAAA");
  });
});
