import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { DEFAULT_POLICY } from "@agentic-sentinel/core";
import { summarizePolicy } from "../src/index.js";

describe("summarizePolicy", () => {
  test("renders version, thresholds, and allow/deny counts", () => {
    const out = summarizePolicy({ ...DEFAULT_POLICY, version: "acme-9",
      rules: { disabled: ["obfuscation"] },
      allow: [{ package: "esbuild", rules: ["network-egress"] }],
      deny: [{ package: "evil-*" }] });
    assert.match(out, /acme-9/);
    assert.match(out, /allow 80/);
    assert.match(out, /disabled: obfuscation/);
    assert.match(out, /allow rules: 1/);
    assert.match(out, /deny rules: 1/);
  });
});
