import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { DEFAULT_POLICY, type EnterprisePolicy } from "@sentinel/core";
import {
  EMPTY_CLAIM_CORPUS,
  normalizePackageName,
  normalizeRegistryReadName,
  source,
  validateClaimCorpus,
  type ClaimCorpus,
} from "../src/resolution.js";

function policy(privateNamespaces: string[]): EnterprisePolicy {
  return { ...DEFAULT_POLICY, privateNamespaces };
}

function corpus(namespaces: string[]): ClaimCorpus {
  return {
    schema: 1, version: "test", issuedAt: "2026-07-02T00:00:00.000Z",
    claims: namespaces.map((namespace, i) => ({ namespace, domain: `org${i}.example`, status: "active",
      challenge: { method: "dns-txt", id: `c-${i}`, verifiedAt: "2026-07-01T00:00:00.000Z" },
      renewalDueAt: "2027-07-01T00:00:00.000Z" })),
  };
}

describe("deterministic registry source selection", () => {
  test("precedence is policy-private → verified-claim → public-mirror", () => {
    const claims = corpus(["@both/*", "claimed-name"]);
    assert.equal(source("@both/pkg", policy(["@both/*"]), claims), "policy-private");
    assert.equal(source("claimed-name", policy([]), claims), "verified-claim");
    assert.equal(source("unclaimed", policy([]), claims), "public-mirror");
  });

  test("empty claim corpus degenerates to policy-private or public-mirror", () => {
    assert.equal(source("@acme/pkg", policy(["@acme/*"]), EMPTY_CLAIM_CORPUS), "policy-private");
    assert.equal(source("left-pad", policy([]), EMPTY_CLAIM_CORPUS), "public-mirror");
  });

  test("source selection is repeatable and does not mutate its inputs", () => {
    const p = policy(["@local/*"]);
    const claims = corpus(["@global/*"]);
    const before = JSON.stringify({ p, claims });
    const results = Array.from({ length: 100 }, () => source("@global/pkg", p, claims));
    assert.deepEqual(new Set(results), new Set(["verified-claim"]));
    assert.equal(JSON.stringify({ p, claims }), before);
  });

  test("freeze or dispute never changes source selection or falls through", () => {
    for (const status of ["frozen", "disputed"] as const) {
      const claims = corpus(["claimed-name"]);
      const lifecycleCorpus: ClaimCorpus = { ...claims, claims: claims.claims.map((claim) => ({ ...claim, status })) };
      assert.equal(source("claimed-name", policy([]), lifecycleCorpus), "verified-claim");
    }
  });

  test("generated policy/claim/name combinations obey first-match precedence", () => {
    // Deterministic generated corpus: enough combinations to exercise overlaps,
    // exact names, scope globs, and misses without adding a random test dependency.
    let seed = 0x5e17_1e1;
    const next = () => (seed = (seed * 1664525 + 1013904223) >>> 0);
    for (let i = 0; i < 2_000; i++) {
      const n = next() % 16;
      const name = n % 2 === 0 ? `@scope${n % 4}/pkg${n}` : `pkg${n}`;
      const policyMatch = (next() & 1) === 1;
      const claimMatch = (next() & 1) === 1;
      const privateNamespaces = policyMatch ? [name.includes("/") ? `${name.split("/")[0]}/*` : name] : ["@other/*"];
      const claims = corpus(claimMatch ? [name.includes("/") ? `${name.split("/")[0]}/*` : name] : ["other-name"]);
      const expected = policyMatch ? "policy-private" : claimMatch ? "verified-claim" : "public-mirror";
      assert.equal(source(name, policy(privateNamespaces), claims), expected, `case ${i}: ${name}`);
    }
  });

  test("package names and claim grammar reject traversal and unscoped wildcards", () => {
    assert.equal(normalizePackageName("@acme/pkg"), "@acme/pkg");
    assert.throws(() => normalizePackageName("@acme/../pkg"), /invalid package name/);
    assert.throws(() => normalizePackageName(" pkg"), /invalid package name/);
    assert.throws(() => validateClaimCorpus(corpus(["pkg*"])), /claim corpus/);
    assert.doesNotThrow(() => validateClaimCorpus(corpus(["@acme/*", "pkg"])));
  });

  test("legacy uppercase spelling is read-only compatibility, not valid for publication", () => {
    assert.equal(normalizeRegistryReadName("JSONStream"), "JSONStream");
    assert.throws(() => normalizePackageName("JSONStream"), /invalid package name/);
    assert.throws(() => normalizeRegistryReadName("../JSONStream"), /invalid package name/);
  });
});
