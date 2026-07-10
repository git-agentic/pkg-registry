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
  nodePrefix: "/usr/local",
  projectRoot: "/work/pkg",
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

  test("a bare '~' grant does not open $HOME for write, read, or exec (#28 guard)", () => {
    const p = generateProfile(
      [fs("~"), { kind: "process", target: "~", evidence: [] }],
      withOpts({ homeDir: HOME }),
    );
    // The exact closing quote makes this precise: read-allow entries like
    // "/Users/test/.node-gyp" do not match '(subpath "/Users/test")'.
    // Check data-read and write/exec ALLOW lines (not metadata-allow which is required for Slice 2).
    const dataAllowLines = p.split("\n")
      .filter((l) => (l.startsWith("(allow file-read*") || l.startsWith("(allow file-write*") || l.startsWith("(allow process-exec*")))
      .join(" ");
    assert.ok(!dataAllowLines.includes('(subpath "/Users/test")'), "no allow form may target $HOME itself");
    assert.match(p, /\(deny file-read\* \(subpath "\/Users\/test"\)\)/); // Slice 2 deny still present
  });
});

const OPTS = { homeDir: "/Users/x", cwd: "/work/pkg", tmpDir: "/var/folders/z/T", nodePrefix: "/usr/local", projectRoot: "/work/pkg" };

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
  test("a '..' filesystem target does NOT become a write Grant (fail-closed escape guard)", () => {
    const approved: Capability[] = [{ kind: "filesystem", target: "..", evidence: [] }];
    const p = generateProfile(approved, OPTS);
    const allowLine = p.split("\n").find((l) => l.startsWith("(allow file-write*"))!;
    assert.ok(!allowLine.includes(`"/Users/x/.."`), "the parent-of-home escape must not be granted");
  });
  test("a bare '/' filesystem target does NOT become a write Grant (fail-closed escape guard)", () => {
    const approved: Capability[] = [{ kind: "filesystem", target: "/", evidence: [] }];
    const p = generateProfile(approved, OPTS);
    const allowLine = p.split("\n").find((l) => l.startsWith("(allow file-write*"))!;
    assert.ok(!allowLine.includes(`(subpath "/")`), "bare root must not be granted");
  });
});

const OPTS2 = { homeDir: "/Users/x", cwd: "/Users/x/app/node_modules/pkg", tmpDir: "/var/folders/z/T", nodePrefix: "/usr/local", projectRoot: "/Users/x/app" };

describe("generateProfile — $HOME-read-deny (Phase 25 Slice 2)", () => {
  test("denies $HOME reads, allows metadata traversal, then re-allows the read-allow list, in that order", () => {
    const p = generateProfile([], OPTS2);
    const denyHome = p.indexOf(`(deny file-read* (subpath "/Users/x")`);
    const metaAllow = p.indexOf(`(allow file-read-metadata (subpath "/Users/x")`);
    const allowList = p.indexOf(`(allow file-read* `);
    assert.ok(denyHome !== -1, "$HOME read-deny present");
    assert.ok(metaAllow > denyHome, "metadata (lstat) traversal allow comes AFTER the $HOME read-deny (so require() can resolve)");
    assert.ok(allowList > metaAllow, "read-allow list comes AFTER the metadata allow (SBPL last-match-wins)");
    for (const frag of [`(subpath "/usr/local")`, `(subpath "/Users/x/app")`, `(subpath "/Users/x/.node-gyp")`, `(subpath "/Users/x/.cache")`]) {
      assert.ok(p.includes(frag), `read-allow must include ${frag}`);
    }
  });
  test("the SENSITIVE read carve-out (incl. /etc/passwd) still comes after the re-allows", () => {
    const p = generateProfile([], OPTS2);
    const allowList = p.indexOf(`(allow file-read*`);
    const carve = p.indexOf(`(deny file-read* (literal "/private/etc/passwd")`);
    assert.ok(carve > allowList, "/etc/passwd read-deny is a carve-out after the re-allows");
  });
  test("write-deny (slice 1) is unchanged", () => {
    const p = generateProfile([], OPTS2);
    assert.ok(p.includes("(deny file-write*)"), "slice-1 blanket write-deny still present");
  });
  test("an approved filesystem Grant under $HOME is READ-allowed too (Grants confer read+write)", () => {
    const approved: Capability[] = [{ kind: "filesystem", target: ".config/app", evidence: [] }];
    const p = generateProfile(approved, OPTS2);
    const readAllowLine = p.split("\n").find((l) => l.startsWith("(allow file-read*") && !l.includes("metadata"))!;
    assert.ok(readAllowLine.includes(`(subpath "/Users/x/.config/app")`), "granted path is read-allowed");
  });
  test("projectRoot === homeDir does not re-open all of $HOME for reads (guard drops the entry)", () => {
    const opts = { ...OPTS2, projectRoot: OPTS2.homeDir };
    const p = generateProfile([], opts);
    const readAllowLine = p.split("\n").find((l) => l.startsWith("(allow file-read*") && !l.includes("metadata"))!;
    assert.ok(!readAllowLine.includes(`(subpath "/Users/x")`), "the guard must drop $HOME itself from the read-allow list");
  });
});

const proc = (target: string): Capability => ({ kind: "process", target, evidence: [] });

describe("generateProfile — exec deny-by-default (Phase 28)", () => {
  test("blanket exec deny, then floor re-allow (last-match-wins order)", () => {
    const p = generateProfile([], withOpts({ homeDir: HOME }));
    assert.match(p, /\(deny process-exec\*\)/);
    const denyIdx = p.indexOf("(deny process-exec*)");
    const allowIdx = p.indexOf("(allow process-exec*");
    assert.ok(denyIdx >= 0 && allowIdx > denyIdx, "floor allow must FOLLOW the blanket deny");
    assert.match(p, /\(allow process-exec\* [^\n]*\(subpath "\/bin"\)/);
    assert.match(p, /\(subpath "\/work\/pkg"\)/);           // projectRoot
    assert.match(p, /\(subpath "\/Library\/Developer"\)/);
  });

  test("carve-out literals are re-denied AFTER the floor allow", () => {
    const p = generateProfile([], withOpts({ homeDir: HOME }));
    assert.match(p, /\(deny process-exec\* [^\n]*\(literal "\/usr\/bin\/curl"\)/);
    const allowIdx = p.indexOf("(allow process-exec*");
    const carveIdx = p.indexOf('(literal "/usr/bin/curl")');
    assert.ok(carveIdx > allowIdx, "carve-out must FOLLOW the floor allow");
  });

  test("a command Grant lifts exactly that command's carve-out", () => {
    const p = generateProfile([proc("curl")], withOpts({ homeDir: HOME }));
    assert.doesNotMatch(p, /literal "\/usr\/bin\/curl"/);
    assert.match(p, /literal "\/usr\/bin\/wget"/);          // siblings stay denied
  });

  test("a path Grant is appended to the exec allow (with ~ expansion)", () => {
    const p = generateProfile([proc("~/tools/bin")], withOpts({ homeDir: HOME }));
    assert.match(p, /\(allow process-exec\* [^\n]*\(subpath "\/Users\/test\/tools\/bin"\)/);
  });

  test("a path Grant covering a carve-out literal lifts it", () => {
    const p = generateProfile([proc("/usr/bin/curl")], withOpts({ homeDir: HOME }));
    assert.doesNotMatch(p, /literal "\/usr\/bin\/curl"/);
    assert.match(p, /literal "\/opt\/homebrew\/bin\/curl"/); // other candidates stay denied
  });

  test("the * Grant lifts the whole carve-out but opens no paths", () => {
    const p = generateProfile([proc("*")], withOpts({ homeDir: HOME }));
    assert.doesNotMatch(p, /\(deny process-exec\* \(literal/);
    assert.match(p, /\(deny process-exec\*\)/);              // blanket deny still present
    // no allow entries beyond the floor:
    const allowLine = p.split("\n").find((l) => l.startsWith("(allow process-exec*"))!;
    assert.doesNotMatch(allowLine, /Users\/test/);
  });

  test("an unsafe path Grant is dropped fail-closed", () => {
    const p = generateProfile([proc("/"), proc("a/../b")], withOpts({ homeDir: HOME }));
    const allowLine = p.split("\n").find((l) => l.startsWith("(allow process-exec*"))!;
    assert.doesNotMatch(allowLine, /subpath "\/"\)/);
    assert.doesNotMatch(allowLine, /a\/\.\.\/b/);
  });

  test("process Grants do not disturb the write or read sections", () => {
    const a = generateProfile([], withOpts({ homeDir: HOME }));
    const b = generateProfile([proc("curl")], withOpts({ homeDir: HOME }));
    const writeAndRead = (s: string) => s.split("\n").filter((l) => l.includes("file-write") || l.includes("file-read")).join("\n");
    assert.equal(writeAndRead(a), writeAndRead(b));
  });
});
