import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { describe, test } from "node:test";
import { LocalFixtureUpstream } from "@agentic-sentinel/proxy";
import { runCi } from "../src/run.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO, "scripts", "make-fixtures.ts")], { cwd: REPO, stdio: "ignore" });
}

// A v3 package-lock.json referencing a benign + the malicious fixture.
function writeLockfile(dir: string): void {
  const lock = {
    name: "demo", lockfileVersion: 3,
    packages: {
      "": { name: "demo" },
      "node_modules/leftpad-lite": { version: "1.0.0" },
      "node_modules/color-stream": { version: "1.4.1" },
    },
  };
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify(lock, null, 2));
}

function fakeEnv(dir: string): NodeJS.ProcessEnv {
  return { GITHUB_OUTPUT: join(dir, "out.txt"), GITHUB_STEP_SUMMARY: join(dir, "summary.md") };
}

describe("runCi (e2e, hermetic)", () => {
  test("fail-on=block gates a tree containing the malicious fixture (exit 2), writes SBOM + outputs + summary", async () => {
    ensureFixtures();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-ci-"));
    writeLockfile(dir);
    const env = fakeEnv(dir);
    const r = await runCi({
      upstream: new LocalFixtureUpstream(FIXTURES), cwd: dir, sbomPath: join(dir, "sbom.json"),
      failOn: "block", omitDev: false, now: "2026-07-08T00:00:00Z", env,
    });
    assert.equal(r.exitCode, 2);
    assert.equal(r.result.aggregate.counts.block >= 1, true);
    // SBOM written + valid CycloneDX
    const sbom = JSON.parse(readFileSync(join(dir, "sbom.json"), "utf8"));
    assert.equal(sbom.bomFormat, "CycloneDX");
    // GITHUB_OUTPUT carries verdict + sbom-path
    const out = readFileSync(env.GITHUB_OUTPUT!, "utf8");
    assert.match(out, /verdict=block/);
    assert.match(out, /gated=true/);
    assert.match(out, /sbom-path=/);
    // step summary written with the report
    assert.match(readFileSync(env.GITHUB_STEP_SUMMARY!, "utf8"), /Sentinel dependency audit/);
  });

  test("fail-on=none is observe-only (exit 0) but still audits + writes the SBOM", async () => {
    ensureFixtures();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-ci-"));
    writeLockfile(dir);
    const r = await runCi({
      upstream: new LocalFixtureUpstream(FIXTURES), cwd: dir, sbomPath: join(dir, "sbom.json"),
      failOn: "none", omitDev: false, now: "2026-07-08T00:00:00Z", env: {},
    });
    assert.equal(r.exitCode, 0);
    assert.equal(existsSync(join(dir, "sbom.json")), true);
  });

  test("auto-detects the lockfile when none is given", async () => {
    ensureFixtures();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-ci-"));
    writeLockfile(dir);
    const r = await runCi({
      upstream: new LocalFixtureUpstream(FIXTURES), cwd: dir, sbomPath: join(dir, "sbom.json"),
      failOn: "none", omitDev: false, now: "2026-07-08T00:00:00Z", env: {},
    });
    assert.equal(r.result.packages.length >= 2, true);
  });
});
