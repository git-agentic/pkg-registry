import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { describe, test } from "node:test";
import { createSandbox } from "../src/factory.js";
import { BubblewrapSandbox } from "../src/bubblewrap.js";
import { SeatbeltSandbox } from "../src/seatbelt.js";

describe("createSandbox", () => {
  test("selects the backend for the host platform (fails closed elsewhere)", () => {
    if (process.platform === "darwin") assert.ok(createSandbox() instanceof SeatbeltSandbox);
    else if (process.platform === "linux") assert.ok(createSandbox() instanceof BubblewrapSandbox);
    else assert.throws(() => createSandbox(), /unavailable/i);
  });
});

describe("BubblewrapSandbox (fail-closed)", () => {
  test("non-linux throws (we never run unsandboxed)", { skip: process.platform === "linux" ? "linux: covered by enforcement tests" : false }, () => {
    assert.throws(() => new BubblewrapSandbox().run("echo hi", { cwd: tmpdir(), approved: [], homeDir: "/tmp" }), /unavailable/i);
  });
});
