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
    assert.match(p, /deny file-read\* \(literal "\/private\/etc\/passwd"\) \(literal "\/private\/etc\/shadow"\)/);
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

  test("denies the canonical /private form of firmlinked system paths", () => {
    const p = generateProfile([], { homeDir: HOME });
    assert.match(p, /\(literal "\/private\/etc\/passwd"\)/);
    assert.match(p, /\(literal "\/private\/etc\/shadow"\)/);
    assert.doesNotMatch(p, /\(literal "\/etc\/passwd"\)/);  // the un-canonical alias is NOT used
  });

  test("deterministic for the same inputs", () => {
    assert.equal(generateProfile([net("x")], { homeDir: HOME }), generateProfile([net("x")], { homeDir: HOME }));
  });

  test("approving one path in a multi-path group still denies the others", () => {
    const p = generateProfile([fs("/etc/passwd")], { homeDir: HOME });
    assert.doesNotMatch(p, /literal "\/private\/etc\/passwd"/);   // approved path no longer denied
    assert.match(p, /deny file-read\* \(literal "\/private\/etc\/shadow"\)/); // sibling still denied
  });

  test("filesystem coverage is path-segment-anchored, not substring", () => {
    // a loose substring like "ssh" must NOT cancel the ~/.ssh deny
    assert.match(generateProfile([fs("ssh")], { homeDir: HOME }), /\/\.ssh"/);
    // the dynamic "*" target covers nothing
    const star = generateProfile([fs("*")], { homeDir: HOME });
    assert.match(star, /\/\.ssh"/);
    assert.match(star, /\/\.npmrc"/);
    // an exact path segment DOES cancel its own deny
    assert.doesNotMatch(generateProfile([fs(".ssh")], { homeDir: HOME }), /\/\.ssh"/);
  });

  test("emits file-write* denies for write-mode entries (persistence + credentials)", () => {
    const p = generateProfile([], { homeDir: HOME });
    assert.match(p, /deny file-write\* \(subpath "\/Users\/test\/Library\/LaunchAgents"\)/);
    assert.match(p, /deny file-write\* \(literal "\/Users\/test\/\.zshrc"\)/);
    assert.match(p, /deny file-write\* \(literal "\/Users\/test\/\.npmrc"\)/); // credential: read AND write
  });

  test("write denies are firmlink-canonicalized", () => {
    const p = generateProfile([], { homeDir: HOME });
    assert.match(p, /deny file-write\* \(subpath "\/private\/var\/at\/tabs"\)/);
    assert.doesNotMatch(p, /file-write\* \(subpath "\/var\/at\/tabs"\)/); // un-canonical alias not used
  });

  test("a filesystem approval omits BOTH the read and write deny for that path", () => {
    const p = generateProfile([fs(".npmrc")], { homeDir: HOME });
    assert.doesNotMatch(p, /file-read\* \(literal "\/Users\/test\/\.npmrc"\)/);
    assert.doesNotMatch(p, /file-write\* \(literal "\/Users\/test\/\.npmrc"\)/);
  });

  test("read-only behavior unchanged: write-only entries emit NO read deny", () => {
    const p = generateProfile([], { homeDir: HOME });
    assert.doesNotMatch(p, /file-read\* \(literal "\/Users\/test\/\.zshrc"\)/); // .zshrc is write-only
  });

  test("emits darwin persistence paths but NOT linux-only ones (pinned to darwin set)", () => {
    const p = generateProfile([], { homeDir: HOME });
    assert.match(p, /LaunchAgents/);                         // darwin entry present
    assert.doesNotMatch(p, /systemd\/user/);                 // linux-only entry absent
    assert.doesNotMatch(p, /spool\/cron/);                   // linux-only entry absent
  });
});
