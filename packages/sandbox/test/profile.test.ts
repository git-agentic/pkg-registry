import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateProfile } from "../src/profile.js";
import type { Capability } from "@sentinel/core";

const fs = (target: string): Capability => ({ kind: "filesystem", target, evidence: [] });
const net = (target: string): Capability => ({ kind: "network", target, evidence: [] });
const HOME = "/Users/test";

describe("generateProfile", () => {
  test("with no approvals: denies sensitive reads and all network", () => {
    const p = generateProfile([], { homeDir: HOME });
    assert.match(p, /^\(version 1\)/);
    assert.match(p, /\(allow default\)/);
    assert.match(p, /deny file-read\* \(subpath "\/Users\/test\/\.ssh"\)/);
    assert.match(p, /deny file-read\* \(literal "\/Users\/test\/\.npmrc"\)/);
    assert.match(p, /deny file-read\* \(literal "\/etc\/passwd"\) \(literal "\/etc\/shadow"\)/);
    assert.match(p, /\(deny network\*\)/);
  });

  test("an approved network capability omits the network deny", () => {
    const p = generateProfile([net("api.example.com")], { homeDir: HOME });
    assert.doesNotMatch(p, /\(deny network\*\)/);
  });

  test("an approved filesystem capability omits its sensitive-path deny", () => {
    const p = generateProfile([fs(".npmrc")], { homeDir: HOME });
    assert.doesNotMatch(p, /\.npmrc"/);          // the ~/.npmrc deny is gone
    assert.match(p, /\.ssh"/);                   // unrelated denies remain
  });

  test("deterministic for the same inputs", () => {
    assert.equal(generateProfile([net("x")], { homeDir: HOME }), generateProfile([net("x")], { homeDir: HOME }));
  });
});
