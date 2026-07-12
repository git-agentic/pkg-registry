import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { createSandbox } from "../src/index.js";

const darwin = process.platform === "darwin";
describe("Sandbox.runArgv", { skip: !darwin }, () => {
  test("runs a binary with preserved argument boundaries, no shell interpolation", () => {
    const sb = createSandbox();
    // /bin/echo receives a single arg containing a space + $(...) that a shell would expand.
    const r = sb.runArgv("/bin/echo", ["a b $(whoami)"], { cwd: process.cwd(), approved: [], homeDir: process.env.HOME! });
    assert.equal(r.exitCode, 0);
    assert.equal(r.stdout.trim(), "a b $(whoami)", "no shell expansion; boundaries preserved");
  });
});
