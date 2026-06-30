import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { SENSITIVE_PATHS } from "../src/index.js";

describe("SENSITIVE_PATHS", () => {
  test("covers the key credential locations with valid shapes", () => {
    const denyPaths = SENSITIVE_PATHS.flatMap((p) => p.denyPaths);
    for (const expected of ["~/.ssh", "~/.aws", "~/.npmrc", "/etc/passwd"]) {
      assert.ok(denyPaths.includes(expected), `expected a denyPath ${expected}`);
    }
    for (const p of SENSITIVE_PATHS) {
      assert.ok(p.label && p.denyPaths.length > 0, "each entry has a label + denyPaths");
      assert.ok(p.denyKind === "literal" || p.denyKind === "subpath", "denyKind is literal|subpath");
    }
  });

  test("the four detectRe entries match the historical secret-exfil patterns", () => {
    const withRe = SENSITIVE_PATHS.filter((p) => p.detectRe);
    const hits = (s: string) => withRe.some((p) => p.detectRe!.test(s));
    assert.ok(hits("os.homedir()+'/.npmrc'"));
    assert.ok(hits(".aws/credentials"));
    assert.ok(hits(".ssh/id_rsa"));
    assert.ok(hits("/etc/passwd"));
    assert.ok(!hits("just some normal code"));
  });

  test("every entry declares non-empty access modes", () => {
    for (const p of SENSITIVE_PATHS) {
      assert.ok(Array.isArray(p.modes) && p.modes.length > 0, `${p.label} missing modes`);
      for (const m of p.modes) assert.ok(m === "read" || m === "write", `${p.label} bad mode ${m}`);
    }
  });

  test("credential entries are read+write; persistence targets are write-only", () => {
    const npmrc = SENSITIVE_PATHS.find((p) => p.denyPaths.includes("~/.npmrc"));
    assert.deepEqual(npmrc?.modes.slice().sort(), ["read", "write"]);
    const launch = SENSITIVE_PATHS.find((p) => p.denyPaths.includes("~/Library/LaunchAgents"));
    assert.ok(launch, "LaunchAgents persistence entry must exist");
    assert.deepEqual(launch?.modes, ["write"]);
    assert.equal(launch?.denyKind, "subpath"); // a dir we block creation WITHIN
    const zsh = SENSITIVE_PATHS.find((p) => p.denyPaths.includes("~/.zshrc"));
    assert.deepEqual(zsh?.modes, ["write"]);
    assert.equal(zsh?.denyKind, "literal");
  });
});
