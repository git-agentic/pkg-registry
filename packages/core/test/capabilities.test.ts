import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { extractCapabilities, diffCapabilities } from "../src/capabilities.js";
import { capabilityAtom } from "../src/detect/patterns.js";
import type { AuditInput, Capability, PackageFile } from "../src/types.js";

function file(path: string, content: string): PackageFile {
  return { path, content, size: content.length, changed: false };
}
function input(...files: PackageFile[]): AuditInput {
  return { meta: {} as never, files, mode: "full" };
}
const atoms = (caps: Capability[]) => caps.map(capabilityAtom);

describe("extractCapabilities", () => {
  test("captures a concrete network host from a URL", () => {
    const caps = extractCapabilities(input(file("package/a.js", 'fetch("https://api.example.com/data")')));
    assert.ok(atoms(caps).includes("network:api.example.com"));
  });

  test("captures a hardcoded IP and the curl command and credential reads", () => {
    const src = [
      'const https = require("https");',
      'https.request({ hostname: "198.51.100.23" });',
      'fs.readFileSync(os.homedir() + "/.npmrc");',
      'execSync("curl -s https://198.51.100.23/beacon");',
    ].join("\n");
    const a = atoms(extractCapabilities(input(file("package/lib/build.js", src))));
    assert.ok(a.includes("network:198.51.100.23"));
    assert.ok(a.includes("filesystem:.npmrc"));
    assert.ok(a.includes("process:curl"));
  });

  test("emits a dynamic '*' target when none is computable", () => {
    const caps = extractCapabilities(input(file("package/a.js", "const cp = require('child_process')")));
    assert.ok(atoms(caps).includes("process:*"));
  });

  test("ignores non-code files", () => {
    const caps = extractCapabilities(input(file("package/readme.md", "https://example.com")));
    assert.equal(caps.length, 0);
  });

  test("is deterministic across runs and deduped/sorted", () => {
    const src = 'fetch("https://api.example.com");fetch("https://api.example.com")';
    const a = extractCapabilities(input(file("package/a.js", src)));
    const b = extractCapabilities(input(file("package/a.js", src)));
    assert.deepEqual(atoms(a), atoms(b));
    assert.equal(atoms(a).filter((x) => x === "network:api.example.com").length, 1, "deduped");
  });

  test("detects credential-shaped env reads as env capabilities, ignores benign env", () => {
    const files = [{
      path: "package/exfil.js",
      content: [
        "const t = process.env.NPM_TOKEN;",
        'const a = process.env["AWS_SECRET_ACCESS_KEY"];',
        "const mode = process.env.NODE_ENV;",   // benign — must NOT be captured
        "const p = process.env.PATH;",          // benign — must NOT be captured
      ].join("\n"),
    }];
    const caps = extractCapabilities({ meta: {} as never, files, mode: "full" });
    const envTargets = caps.filter((c) => c.kind === "env").map((c) => c.target).sort();
    assert.deepEqual(envTargets, ["AWS_SECRET_ACCESS_KEY", "NPM_TOKEN"]);
  });
});

describe("diffCapabilities", () => {
  const net = (t: string): Capability => ({ kind: "network", target: t, evidence: [] });
  test("added = atoms present now but not in baseline", () => {
    const d = diffCapabilities([net("a.example.com"), net("b.example.com")], [net("a.example.com")]);
    assert.deepEqual(d.added.map(capabilityAtom), ["network:b.example.com"]);
    assert.deepEqual(d.removed.map(capabilityAtom), []);
  });
  test("removed = atoms in baseline but gone now", () => {
    const d = diffCapabilities([net("a.example.com")], [net("a.example.com"), net("c.example.com")]);
    assert.deepEqual(d.removed.map(capabilityAtom), ["network:c.example.com"]);
  });
});

import { auditTarball } from "../src/index.js";
import { ensureFixtures, tarball } from "./helpers.js";

const baseMeta = {
  author: null, maintainers: [] as string[], license: null,
  hasInstallScripts: false, signature: "unsigned" as const, provenance: "absent" as const,
};

describe("capabilities in the audit report (color-stream fixture)", () => {
  test("malicious release surfaces network/filesystem/process capabilities as a delta", async () => {
    ensureFixtures();
    const r = await auditTarball({
      meta: { name: "color-stream", version: "1.4.1", ...baseMeta },
      tarball: tarball("color-stream", "1.4.1"),
      baselineTarball: tarball("color-stream", "1.4.0"),
    });
    assert.equal(r.schema, 3);
    const kinds = new Set(r.capabilities.map((c) => c.kind));
    assert.ok(kinds.has("network") && kinds.has("filesystem") && kinds.has("process"));
    assert.ok(r.capabilityDelta);
    assert.ok(r.capabilityDelta.added.length > 0, "new caps appear as a delta vs 1.4.0");
  });

  test("capabilities are deterministic across runs", async () => {
    ensureFixtures();
    const a = await auditTarball({ meta: { name: "color-stream", version: "1.4.1", ...baseMeta }, tarball: tarball("color-stream", "1.4.1") });
    const b = await auditTarball({ meta: { name: "color-stream", version: "1.4.1", ...baseMeta }, tarball: tarball("color-stream", "1.4.1") });
    assert.deepEqual(a.capabilities.map(capabilityAtom), b.capabilities.map(capabilityAtom));
  });
});
