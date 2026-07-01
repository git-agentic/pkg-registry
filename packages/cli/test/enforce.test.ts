import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { approvedCapsForManifest, isRootScript, commandFromArgv, EnforceError } from "../src/enforce.js";
import type { Manifest } from "../src/format.js";

const mk = (state: string, caps: any[] = []): Manifest => ({
  meta: { name: "p", version: "1.0.0", integrity: "sha512-x" },
  verdict: "allow", approvalState: state, capabilities: caps, approvalRequired: [], inheritedFrom: null,
});

describe("approvedCapsForManifest", () => {
  test("approved/inherited return the manifest capabilities", () => {
    const caps = [{ kind: "network", target: "198.51.100.5", evidence: [] }];
    assert.deepEqual(approvedCapsForManifest(mk("approved", caps)), caps);
    assert.deepEqual(approvedCapsForManifest(mk("inherited", caps)), caps);
  });
  test("n-a returns empty (no capabilities, strict sandbox)", () => {
    assert.deepEqual(approvedCapsForManifest(mk("n-a")), []);
  });
  test("required and denied FAIL CLOSED (throw)", () => {
    assert.throws(() => approvedCapsForManifest(mk("required")), EnforceError);
    assert.throws(() => approvedCapsForManifest(mk("denied")), EnforceError);
  });
});

describe("isRootScript", () => {
  test("cwd equal to INIT_CWD is the root project", () => {
    assert.equal(isRootScript("/proj", "/proj"), true);
  });
  test("cwd under node_modules is a dependency", () => {
    assert.equal(isRootScript("/proj/node_modules/dep", "/proj"), false);
  });
  test("missing INIT_CWD falls back to the node_modules check", () => {
    assert.equal(isRootScript("/proj/node_modules/dep", undefined), false);
    assert.equal(isRootScript("/proj", undefined), true);
  });
});

describe("commandFromArgv", () => {
  test("extracts the command after -c", () => {
    assert.equal(commandFromArgv(["-c", "node -e \"x\""]), "node -e \"x\"");
  });
  test("throws when the shape is not -c <cmd>", () => {
    assert.throws(() => commandFromArgv(["node", "x"]), EnforceError);
    assert.throws(() => commandFromArgv(["-c"]), EnforceError);
  });
});
