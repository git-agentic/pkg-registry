import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Capability } from "@sentinel/core";
import { parseApprovals, unapprovedAtoms } from "../src/index.js";

const cap = (kind: string, target: string): Capability => ({ kind: kind as Capability["kind"], target, evidence: [] });

describe("parseApprovals", () => {
  test("parses kind:target flags", () => {
    const a = parseApprovals(["network:api.example.com", "filesystem:.npmrc"]);
    assert.deepEqual(a.map((c) => `${c.kind}:${c.target}`), ["network:api.example.com", "filesystem:.npmrc"]);
  });
  test("ignores malformed flags", () => {
    assert.deepEqual(parseApprovals(["garbage"]), []);
  });
});

describe("unapprovedAtoms", () => {
  test("returns detected minus approved by atom", () => {
    const detected = [cap("network", "evil.example.com"), cap("filesystem", ".aws/credentials")];
    const approved = [cap("filesystem", ".aws/credentials")];
    assert.deepEqual(unapprovedAtoms(detected, approved), ["network:evil.example.com"]);
  });
});
