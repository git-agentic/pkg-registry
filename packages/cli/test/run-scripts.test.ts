import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import type { Capability } from "@git-agentic/sentinel-core";
import { parseApprovals, unapprovedAtoms, readPackageFiles } from "../src/index.js";

const cap = (kind: string, target: string): Capability => ({ kind: kind as Capability["kind"], target, evidence: [] });

describe("parseApprovals", () => {
  test("parses kind:target flags", () => {
    const a = parseApprovals(["network:api.example.com", "filesystem:.npmrc"]);
    assert.deepEqual(a.map((c) => `${c.kind}:${c.target}`), ["network:api.example.com", "filesystem:.npmrc"]);
  });
  test("ignores malformed flags", () => {
    assert.deepEqual(parseApprovals(["garbage"]), []);
  });
  test("parseApprovals accepts env:<NAME>", () => {
    const caps = parseApprovals(["env:NPM_TOKEN", "network:x", "bogus:y"]);
    assert.ok(caps.some((c) => c.kind === "env" && c.target === "NPM_TOKEN"));
    assert.ok(!caps.some((c) => c.kind === ("bogus" as never)));
  });
});

describe("unapprovedAtoms", () => {
  test("returns detected minus approved by atom", () => {
    const detected = [cap("network", "evil.example.com"), cap("filesystem", ".aws/credentials")];
    const approved = [cap("filesystem", ".aws/credentials")];
    assert.deepEqual(unapprovedAtoms(detected, approved), ["network:evil.example.com"]);
  });
});

describe("readPackageFiles", () => {
  test("does not traverse symlinks pointing to /", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-test-"));
    try {
      // Create a normal file
      writeFileSync(join(dir, "index.js"), "console.log('hello');");
      // Create a symlink pointing to the filesystem root (the traversal escape)
      symlinkSync("/", join(dir, "evil"));
      const files = readPackageFiles(dir);
      // Should be tiny: at most the normal file + the symlink entry itself (empty content)
      // NOT thousands of entries from traversing / through the symlink
      assert.ok(
        files.length <= 2,
        `expected at most 2 entries but got ${files.length} — symlink traversal likely occurred`,
      );
      // Must not contain any path that digs into the symlink target
      const evilPaths = files.filter((f) => f.path.includes("evil/"));
      assert.equal(evilPaths.length, 0, "no paths through the symlink target should appear");
      // Normal file must be present
      assert.ok(files.some((f) => f.path.includes("index.js")), "normal file should be included");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
