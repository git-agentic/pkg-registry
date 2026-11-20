import assert from "node:assert/strict";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { SENSITIVE_EXECUTABLES } from "../src/sensitive-executables.js";
import { generateProfile } from "../src/profile.js";
import { SeatbeltSandbox } from "../src/seatbelt.js";
import type { Capability } from "@git-agentic/sentinel-core";

const OPTS = { homeDir: "/Users/x", cwd: "/work/pkg", tmpDir: "/var/folders/z/T", nodePrefix: "/usr/local", projectRoot: "/Users/x/app" };
const ESCAPE_TOOLS = ["launchctl", "open", "shortcuts", "automator"];

describe("F10 launchd / LaunchServices escape tools are exec-denied", () => {
  test("SENSITIVE_EXECUTABLES lists launchctl, open, shortcuts and automator", () => {
    for (const c of ESCAPE_TOOLS) assert.ok(SENSITIVE_EXECUTABLES.includes(c), c);
  });
  test("the generated profile denies exec of each (argument test)", () => {
    const p = generateProfile([], OPTS);
    for (const c of ESCAPE_TOOLS) assert.match(p, new RegExp(`\\(deny process-exec\\*[^\\n]*\\(literal "/[^"]*/${c}"\\)`), c);
  });
  test("a process:<cmd> Grant lifts the carve-out for that command only", () => {
    const g: Capability[] = [{ kind: "process", target: "open", evidence: [] }];
    const p = generateProfile(g, OPTS);
    assert.ok(!p.includes('/usr/bin/open"'));
    assert.ok(p.includes('/bin/launchctl"'));
  });
  test("a real sandboxed `open` and `launchctl` cannot exec (effect test)", { skip: process.platform === "darwin" ? false : "requires macOS sandbox-exec" }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-f10-")));
    for (const cmd of ["/usr/bin/open -h", "/bin/launchctl version"]) {
      const r = new SeatbeltSandbox().run(`${cmd} >/dev/null 2>&1; echo rc=$?`, { cwd: home, approved: [], homeDir: home });
      assert.ok(r.stdout.includes("rc=126"), `${cmd} must be exec-denied (sh rc 126): ${r.stdout}${r.stderr}`);
    }
  });
});
