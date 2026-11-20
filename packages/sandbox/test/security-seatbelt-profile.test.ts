import assert from "node:assert/strict";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import * as seatbelt from "../src/seatbelt.js";

const { SeatbeltSandbox } = seatbelt;

const darwin = process.platform === "darwin";

// F7: the SBPL profile used to be written to <tmpdir>/sentinel-sb-*/profile.sb — inside the
// write floor — so a lingering sandboxed process could rewrite the NEXT run's profile.
describe("F7 Seatbelt profile is passed inline, never via a writable file", () => {
  test("sandboxExecArgv uses -p <profile> and not -f (argument test, platform-neutral)", () => {
    const argv = seatbelt.sandboxExecArgv("(version 1)\n(allow default)\n", ["/bin/sh", "-c", "true"]);
    assert.deepEqual(argv, ["-p", "(version 1)\n(allow default)\n", "/bin/sh", "-c", "true"]);
    assert.ok(!argv.includes("-f"));
  });

  test("run: no sentinel-sb-* profile file exists in tmpdir while the script runs (effect test)", { skip: darwin ? false : "requires macOS sandbox-exec" }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-f7-")));
    const r = new SeatbeltSandbox().run(`ls "${tmpdir()}"; find "${tmpdir()}" -maxdepth 2 -name profile.sb 2>/dev/null; true`, { cwd: home, approved: [], homeDir: home });
    assert.equal(r.exitCode, 0, r.stderr);
    assert.ok(!r.stdout.includes("sentinel-sb-"), `a profile dir is visible to the script:\n${r.stdout}`);
    assert.ok(!r.stdout.includes("profile.sb"), "a profile.sb is visible to the script");
  });

  test("runArgv: same, no profile file visible (effect test)", { skip: darwin ? false : "requires macOS sandbox-exec" }, () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-f7b-")));
    const r = new SeatbeltSandbox().runArgv("/bin/ls", [tmpdir()], { cwd: home, approved: [], homeDir: home });
    assert.equal(r.exitCode, 0, r.stderr);
    assert.ok(!r.stdout.includes("sentinel-sb-"), r.stdout);
  });
});
