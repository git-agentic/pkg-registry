import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateKeypair, type ProvenanceIdentity, type VerifiedClaim } from "@git-agentic/sentinel-core";
import { trustedPublisherAuthorized } from "../src/resolution.js";

const identity: ProvenanceIdentity = {
  workflow: "https://github.com/acme/lib/.github/workflows/release.yml@refs/heads/main",
  issuer: "https://token.actions.githubusercontent.com",
  sourceRepository: "https://github.com/acme/lib",
  ref: "refs/heads/main",
  builder: "https://github.com/actions/runner/github-hosted",
  commit: null,
};
const claim = (trustedPublishers: VerifiedClaim["trustedPublishers"]): VerifiedClaim => ({
  namespace: "@acme/*", domain: "acme.example", claimantPublicKey: generateKeypair().publicKey, status: "active",
  challenge: { method: "dns-txt", id: "c", verifiedAt: "2026-07-01T00:00:00.000Z" },
  renewalDueAt: "2027-07-01T00:00:00.000Z", trustedPublishers,
});

describe("F14: trustedPublisherAuthorized never authorizes on the signer-written builder alone", () => {
  test("an issuer + builder entry (no repository/workflowRef) does not authorize", () => {
    assert.equal(trustedPublisherAuthorized(claim([{ issuer: identity.issuer!, builder: identity.builder! }]), identity), false);
  });
  test("an issuer-only entry does not authorize", () => {
    assert.equal(trustedPublisherAuthorized(claim([{ issuer: identity.issuer! }]), identity), false);
  });
  test("a repository-constrained entry still authorizes, and a mismatched repository does not", () => {
    assert.equal(trustedPublisherAuthorized(claim([{ issuer: identity.issuer!, repository: "https://github.com/acme/*" }]), identity), true);
    assert.equal(trustedPublisherAuthorized(claim([{ issuer: identity.issuer!, repository: "https://github.com/acme/*" }]), { ...identity, sourceRepository: "https://github.com/evil/x" }), false);
  });
});
