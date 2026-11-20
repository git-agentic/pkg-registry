import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, test } from "node:test";
import {
  formatReport, formatManifest, formatTree, formatViolations, formatStats, formatHistory, formatExplain, formatLint, formatPreview,
  sanitizeTerminal,
} from "../src/format.js";

const pexec = promisify(execFile);
const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

// OSC title set, CSI clear screen, C1 CSI, carriage return (overwrites the line), backspace, bell.
const EVIL = "pwn\x1b]0;owned\x07\x1b[2J\x9b31m\rspoof\x08\x07\x1b(B!";
// Our own SGR colour codes are legitimate; anything else non-printable must be gone.
const unsafe = (out: string) => out.replace(/\x1b\[[0-9;]*m/g, "").match(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/);

describe("sanitizeTerminal", () => {
  test("strips ESC sequences, C0 (except \\n and \\t) and C1 controls", () => {
    assert.equal(sanitizeTerminal(EVIL), "pwnspoof!");
    assert.equal(sanitizeTerminal("a\tb\nc"), "a\tb\nc");
    assert.equal(sanitizeTerminal("\x1b[31mred\x1b[0m"), "red");
    assert.equal(sanitizeTerminal("\x1b]8;;http://evil\x1b\\link\x1b]8;;\x1b\\"), "link");
    assert.equal(sanitizeTerminal("\x1bPdcs payload\x1b\\ok"), "ok");
    assert.equal(sanitizeTerminal("plain text ✓ ünïcode"), "plain text ✓ ünïcode");
  });
});

describe("every formatter neutralizes package- and proxy-controlled strings", () => {
  test("formatReport", () => {
    const out = formatReport({
      meta: { name: EVIL, version: EVIL, author: EVIL, unpackedSize: 1, fileCount: 1, signature: "verified", provenance: "verified",
        provenanceIdentity: { builder: EVIL, sourceRepository: EVIL, ref: EVIL, commit: EVIL }, hasInstallScripts: false },
      engine: { mode: "full", rules: [], version: EVIL }, score: 50, verdict: "warn", llmSummary: EVIL,
      findings: [{ ruleId: EVIL, severity: "high", message: EVIL, evidence: [{ file: EVIL, line: 1, snippet: EVIL }] }],
    } as never);
    assert.equal(unsafe(out), null, JSON.stringify(out));
    assert.match(out, /pwnspoof!/);
  });
  test("formatManifest", () => {
    const cap = { kind: "network", target: EVIL, evidence: [] };
    const out = formatManifest({ meta: { name: EVIL, version: EVIL, integrity: "x" }, verdict: EVIL, approvalState: EVIL,
      capabilities: [cap], approvalRequired: [cap], inheritedFrom: EVIL } as never);
    assert.equal(unsafe(out), null, JSON.stringify(out));
  });
  test("formatTree", () => {
    const out = formatTree({ aggregate: { verdict: "block", gated: true, counts: { allow: 0, warn: 0, block: 1, error: 0 },
      provenance: { verified: 0, invalid: 0, absent: 1, unknown: 0 }, integrityMismatch: 0 },
      packages: [{ name: EVIL, version: EVIL, status: "block", score: 1, topFinding: EVIL, topFindingRuleId: null, error: EVIL,
        provenance: "absent", integrityMismatch: false }] } as never);
    assert.equal(unsafe(out), null, JSON.stringify(out));
  });
  test("formatViolations", () => {
    const out = formatViolations([{ name: EVIL, version: EVIL, kind: EVIL, target: EVIL, confidence: EVIL, quarantined: false,
      evidence: { exitCode: 1, stderrExcerpt: EVIL } }]);
    assert.equal(unsafe(out), null, JSON.stringify(out));
  });
  test("formatStats and formatHistory", () => {
    assert.equal(unsafe(formatStats({ summary: { total: 1, verdict: { allow: 1, warn: 0, block: 0 }, violations: 0, quarantined: 0 },
      trends: [{ date: EVIL, allow: 1, warn: 0, block: 0 }], topFlagged: [{ name: EVIL, warn: 1, block: 0 }] })), null);
    assert.equal(unsafe(formatHistory([{ name: EVIL, version: EVIL, verdict: EVIL, score: 1, topFinding: EVIL, auditedAt: EVIL }])), null);
  });
  test("formatExplain, formatLint and formatPreview", () => {
    assert.equal(unsafe(formatExplain({
      report: { meta: { name: EVIL, version: EVIL }, verdict: "block", score: 1 },
      remediation: { guidance: EVIL, items: [{ ruleId: EVIL, severity: EVIL, summary: EVIL, action: EVIL }], waiver: { approveCommand: EVIL } },
      lastKnownGood: { version: EVIL, score: 1 },
    } as never)), null);
    assert.equal(unsafe(formatLint({ errors: [{ code: EVIL, message: EVIL }], warnings: [{ code: EVIL, message: EVIL }] } as never)), null);
    assert.equal(unsafe(formatPreview({ enabled: true, total: 1, transitions: { [EVIL]: 1 },
      changed: [{ name: EVIL, version: EVIL, from: EVIL, to: EVIL, fromScore: 1, toScore: 2 }] })), null);
  });
});

describe("sentinel run-scripts", { skip: process.platform !== "darwin" }, () => {
  // Under $HOME (not the writable tmp floor) a relative package dir used to produce a profile that
  // granted the wrong path, so the script could not write its own directory.
  test("accepts a relative package directory (resolved against the cwd)", async () => {
    const root = mkdtempSync(join(homedir(), ".sentinel-relpath-"));
    try {
      mkdirSync(join(root, "pkg"));
      writeFileSync(join(root, "pkg", "package.json"), JSON.stringify({ name: "p", version: "1.0.0",
        scripts: { postinstall: "node -e \"require('fs').writeFileSync('proof.txt','ok')\"" } }));
      const { stdout } = await pexec(process.execPath, [CLI, "run-scripts", "pkg"], { cwd: root });
      assert.match(stdout, /-> exit 0/);
      assert.equal(readFileSync(join(root, "pkg", "proof.txt"), "utf8"), "ok");
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
