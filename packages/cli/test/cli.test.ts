import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { formatManifest, type Manifest } from "../src/format.js";
import { planApprovals } from "../src/index.js";

const base: Manifest = {
  meta: { name: "net-fetch-lite", version: "1.0.0", integrity: "sha512-x" },
  verdict: "allow", approvalState: "required", inheritedFrom: null,
  capabilities: [{ kind: "network", target: "api.example.com", evidence: [] }],
  approvalRequired: [{ kind: "network", target: "api.example.com", evidence: [] }],
};

describe("CLI manifest formatting", () => {
  test("formatManifest renders the package, state, and required atoms", () => {
    const out = formatManifest(base);
    assert.match(out, /net-fetch-lite@1\.0\.0/);
    assert.match(out, /network/);
    assert.match(out, /api\.example\.com/);
    assert.match(out, /required/i);
  });
});

describe("planApprovals", () => {
  test("selects only manifests whose state is 'required'", () => {
    const inherited: Manifest = { ...base, meta: { ...base.meta, version: "1.0.1", integrity: "sha512-y" }, approvalState: "inherited", approvalRequired: [] };
    const plan = planApprovals([base, inherited]);
    assert.deepEqual(plan, [{ name: "net-fetch-lite", version: "1.0.0", integrity: "sha512-x" }]);
  });
});
