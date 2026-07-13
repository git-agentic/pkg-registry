import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { auditTarball } from "../src/audit.js";
import { ensureFixtures, tarball } from "./helpers.js";

async function verdict(name: string, version: string): Promise<string> {
  const report = await auditTarball({ meta: { name, version, author: null, maintainers: [], license: null, hasInstallScripts: false, integrity: null }, tarball: tarball(name, version) });
  return report.verdict;
}

describe("payload-loader fixtures", () => {
  before(() => ensureFixtures());

  test("Gen-1 preinstall loader → block", async () => assert.equal(await verdict("payload-loader-preinstall", "1.0.0"), "block"));
  test("Gen-2 main-entry loader (no install script) → block", async () => assert.equal(await verdict("payload-loader-entry", "1.0.0"), "block"));
  test("Gen-2 bin-entry loader → block", async () => assert.equal(await verdict("payload-loader-bin", "1.0.0"), "block"));
  test("benign loader-lookalike build tool → allow (no false critical)", async () => assert.equal(await verdict("loader-lookalike", "1.0.0"), "allow"));
});
