import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateProfile } from "../src/profile.js";
import type { Capability } from "@sentinel/core";

const fs = (target: string): Capability => ({ kind: "filesystem", target, evidence: [] });
const net = (target: string): Capability => ({ kind: "network", target, evidence: [] });
const HOME = "/Users/test";
const withOpts = (extra: { homeDir: string }) => ({
  cwd: "/work/pkg",
  tmpDir: "/private/tmp/tmpdir-x",
  ...extra,
});

describe("generateProfile", () => {
  test("with no approvals: denies sensitive reads and all network", () => {
    const p = generateProfile([], withOpts({ homeDir: HOME }));
    assert.match(p, /^\(version 1\)/);
    assert.match(p, /\(allow default\)/);
    assert.match(p, /deny file-read\* \(subpath "\/Users\/test\/\.ssh"\)/);
    assert.match(p, /deny file-read\* \(literal "\/Users\/test\/\.npmrc"\)/);
    assert.match(p, /deny file-read\* \(literal "\/private\/etc\/passwd"\) \(literal "\/private\/etc\/shadow"\)/);
    assert.match(p, /\(deny network\*\)/);
  });

  test("an approved network capability omits the network deny", () => {
    const p = generateProfile([net("api.example.com")], withOpts({ homeDir: HOME }));
    assert.doesNotMatch(p, /\(deny network\*\)/);
  });

  test("an approved filesystem capability omits its sensitive-path deny", () => {
    const p = generateProfile([fs(".npmrc")], withOpts({ homeDir: HOME }));
    assert.doesNotMatch(p, /deny file-read\*[^\n]*\.npmrc"/);   // the ~/.npmrc read-deny is gone
    assert.doesNotMatch(p, /deny file-write\*[^\n]*\.npmrc"/);  // the ~/.npmrc write-deny is gone
    assert.match(p, /\.ssh"/);                                  // unrelated denies remain
  });

  test("denies the canonical /private form of firmlinked system paths", () => {
    const p = generateProfile([], withOpts({ homeDir: HOME }));
    assert.match(p, /\(literal "\/private\/etc\/passwd"\)/);
    assert.match(p, /\(literal "\/private\/etc\/shadow"\)/);
    assert.doesNotMatch(p, /\(literal "\/etc\/passwd"\)/);  // the un-canonical alias is NOT used
  });

  test("deterministic for the same inputs", () => {
    assert.equal(generateProfile([net("x")], withOpts({ homeDir: HOME })), generateProfile([net("x")], withOpts({ homeDir: HOME })));
  });

  test("approving one path in a multi-path group still denies the others", () => {
    const p = generateProfile([fs("/etc/passwd")], withOpts({ homeDir: HOME }));
    assert.doesNotMatch(p, /literal "\/private\/etc\/passwd"/);   // approved path no longer denied
    assert.match(p, /deny file-read\* \(literal "\/private\/etc\/shadow"\)/); // sibling still denied
  });

  test("filesystem coverage is path-segment-anchored, not substring", () => {
    // a loose substring like "ssh" must NOT cancel the ~/.ssh deny
    assert.match(generateProfile([fs("ssh")], withOpts({ homeDir: HOME })), /\/\.ssh"/);
    // the dynamic "*" target covers nothing
    const star = generateProfile([fs("*")], withOpts({ homeDir: HOME }));
    assert.match(star, /\/\.ssh"/);
    assert.match(star, /\/\.npmrc"/);
    // an exact path segment DOES cancel its own deny
    assert.doesNotMatch(
      generateProfile([fs(".ssh")], withOpts({ homeDir: HOME })),
      /deny file-(read|write)\*[^\n]*\/\.ssh"/,
    );
  });

  test("emits file-write* denies for write-mode entries (persistence + credentials)", () => {
    const p = generateProfile([], withOpts({ homeDir: HOME }));
    assert.match(p, /deny file-write\* \(subpath "\/Users\/test\/Library\/LaunchAgents"\)/);
    assert.match(p, /deny file-write\* \(literal "\/Users\/test\/\.zshrc"\)/);
    assert.match(p, /deny file-write\* \(literal "\/Users\/test\/\.npmrc"\)/); // credential: read AND write
  });

  test("write denies are firmlink-canonicalized", () => {
    const p = generateProfile([], withOpts({ homeDir: HOME }));
    assert.match(p, /deny file-write\* \(subpath "\/private\/var\/at\/tabs"\)/);
    assert.doesNotMatch(p, /file-write\* \(subpath "\/var\/at\/tabs"\)/); // un-canonical alias not used
  });

  test("a filesystem approval omits BOTH the read and write deny for that path", () => {
    const p = generateProfile([fs(".npmrc")], withOpts({ homeDir: HOME }));
    assert.doesNotMatch(p, /file-read\* \(literal "\/Users\/test\/\.npmrc"\)/);
    assert.doesNotMatch(p, /file-write\* \(literal "\/Users\/test\/\.npmrc"\)/);
  });

  test("read-only behavior unchanged: write-only entries emit NO read deny", () => {
    const p = generateProfile([], withOpts({ homeDir: HOME }));
    assert.doesNotMatch(p, /file-read\* \(literal "\/Users\/test\/\.zshrc"\)/); // .zshrc is write-only
  });

  test("emits darwin persistence paths but NOT linux-only ones (pinned to darwin set)", () => {
    const p = generateProfile([], withOpts({ homeDir: HOME }));
    assert.match(p, /LaunchAgents/);                         // darwin entry present
    assert.doesNotMatch(p, /systemd\/user/);                 // linux-only entry absent
    assert.doesNotMatch(p, /spool\/cron/);                   // linux-only entry absent
    assert.doesNotMatch(p, /\.config\/autostart/);           // XDG autostart is linux-only (moved off darwin in Phase 5)
  });
});

const OPTS = { homeDir: "/Users/x", cwd: "/work/pkg", tmpDir: "/var/folders/z/T" };

describe("generateProfile — write-deny (Phase 25)", () => {
  test("emits a blanket write-deny before the floor allows", () => {
    const p = generateProfile([], OPTS);
    const denyIdx = p.indexOf("(deny file-write*)");
    const allowIdx = p.indexOf("(allow file-write*");
    assert.ok(denyIdx !== -1, "blanket write-deny present");
    assert.ok(allowIdx > denyIdx, "floor allow comes AFTER the blanket deny (SBPL last-match-wins)");
  });
  test("the floor re-allows cwd, temp, /private/tmp, /dev and the node caches", () => {
    const p = generateProfile([], OPTS);
    for (const frag of [
      `(subpath "/work/pkg")`,
      `(subpath "/private/var/folders/z/T")`, // tmpDir canonicalized
      `(subpath "/private/tmp")`,             // /tmp canonicalized
      `(subpath "/dev")`,
      `(subpath "/Users/x/.node-gyp")`,
      `(subpath "/Users/x/.npm/_logs")`,
    ]) assert.ok(p.includes(frag), `floor must allow ${frag}`);
  });
  test("an approved filesystem capability becomes a positive write Grant", () => {
    const approved: Capability[] = [{ kind: "filesystem", target: ".config/app", evidence: [] }];
    const p = generateProfile(approved, OPTS);
    assert.ok(p.includes(`(allow file-write*`) && p.includes(`(subpath "/Users/x/.config/app")`),
      "approved fs target is write-allowed");
  });
  test("SENSITIVE write targets are carved back out AFTER the floor (persistence stays denied even under an allowed ancestor)", () => {
    const p = generateProfile([], OPTS);
    const floorAllow = p.indexOf("(allow file-write*");
    const carve = p.lastIndexOf("(deny file-write*");
    assert.ok(carve > floorAllow, "sensitive write carve-out must come after the floor allow (last-match-wins)");
    assert.ok(p.includes(`/Users/x/.zshrc`), "a persistence path is re-denied");
  });
  test("an approved Grant lifts the carve-out for its own path (approve ~/.zshrc → writable)", () => {
    const approved: Capability[] = [{ kind: "filesystem", target: ".zshrc", evidence: [] }];
    const p = generateProfile(approved, OPTS);
    // .zshrc is now covered by a Grant, so it is NOT in the trailing write carve-out.
    const carveTail = p.slice(p.indexOf("(allow file-write*"));
    assert.ok(!carveTail.includes(`(deny file-write* (literal "/Users/x/.zshrc")`), "granted path is not carved back out");
  });
  test("read-denies for credential paths are UNCHANGED (Slice 1 leaves reads alone)", () => {
    const p = generateProfile([], OPTS);
    assert.ok(p.includes("(deny file-read*"), "credential read-denies still emitted");
  });
  test("pure — same inputs, identical profile", () => {
    assert.equal(generateProfile([], OPTS), generateProfile([], OPTS));
  });
});
