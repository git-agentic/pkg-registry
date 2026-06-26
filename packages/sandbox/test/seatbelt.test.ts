import assert from "node:assert/strict";
import net from "node:net";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { SeatbeltSandbox } from "../src/seatbelt.js";
import { runLifecycleScripts } from "../src/runner.js";
import { generateProfile } from "../src/profile.js";

const darwin = process.platform === "darwin";

describe("SeatbeltSandbox (fail-closed)", () => {
  test("non-darwin throws (we never run unsandboxed)", { skip: darwin ? "darwin: covered by enforcement tests" : false }, () => {
    assert.throws(() => new SeatbeltSandbox().run("echo hi", { cwd: tmpdir(), profile: "(version 1)(allow default)" }), /unavailable/i);
  });
});

describe("SeatbeltSandbox enforcement", { skip: darwin ? false : "requires macOS sandbox-exec" }, () => {
  test("a denied file-read leaves the secret unobtained (assert on EFFECT, not exit)", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "sb-enf-")));
    const secret = join(dir, "secret.txt");
    writeFileSync(secret, "TOPSECRET-XYZ");
    const out = join(dir, "out.txt");
    // deny-default profile that denies this exact file
    const profile = `(version 1)\n(allow default)\n(deny file-read* (literal "${secret}"))\n`;
    // script swallows the error (like real exfil) and writes what it managed to read
    const sb = new SeatbeltSandbox();
    sb.run(`cat ${secret} > ${out} 2>/dev/null || true`, { cwd: dir, profile });
    const got = existsSync(out) ? readFileSync(out, "utf8") : "";
    assert.ok(!got.includes("TOPSECRET-XYZ"), "the secret bytes must NOT have been obtained");
  });

  test("a denied network connection never lands (loopback listener)", async () => {
    const got: boolean[] = [];
    const server = net.createServer((s) => { got.push(true); s.destroy(); });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as net.AddressInfo).port;
    const dir = mkdtempSync(join(tmpdir(), "sb-net-"));
    const profile = `(version 1)\n(allow default)\n(deny network*)\n`;
    new SeatbeltSandbox().run(`nc -z -G 2 127.0.0.1 ${port} || true`, { cwd: dir, profile });
    await new Promise((r) => setTimeout(r, 200));
    server.close();
    assert.equal(got.length, 0, "the sandboxed connection must not have reached the listener");
  });
});

describe("runLifecycleScripts", { skip: darwin ? false : "requires macOS sandbox-exec" }, () => {
  test("runs present hooks under the profile and a benign script succeeds", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "sb-run-")));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: "echo built > built.txt" } }));
    const profile = generateProfile([], { homeDir: process.env.HOME ?? "/tmp" });
    const r = runLifecycleScripts({ packageDir: dir, profile, sandbox: new SeatbeltSandbox() });
    assert.equal(r.failed, false);
    assert.equal(r.results.length, 1);
    assert.equal(r.results[0]?.hook, "postinstall");
    assert.equal(readFileSync(join(dir, "built.txt"), "utf8").trim(), "built");
  });
});
