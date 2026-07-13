import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { generateKeypair, parseClaimCorpus, verifyClaimCorpusBytes } from "@sentinel/core";
import { ClaimSteward, corroboratesClaimDomain, signTransferRequest, type UpstreamClaimLookup } from "../src/steward.js";
import { createStewardServer } from "../src/server.js";

const FIXTURE = JSON.parse(readFileSync(join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "grandfathering.json"), "utf8")) as {
  cases: { name: string; domain: string; expected: boolean; packument: unknown }[];
};
const linkedPackument = FIXTURE.cases[0]!.packument;
const absent: UpstreamClaimLookup = async () => ({ kind: "absent" });
const claimant = generateKeypair();

describe("claim steward pipeline", () => {
  test("a corpus entry cannot exist before an exact-apex DNS challenge passes", async () => {
    let now = Date.parse("2026-07-01T00:00:00.000Z");
    const steward = new ClaimSteward({ now: () => now, id: (() => { let i = 0; return () => `id-${++i}`; })(),
      lookupUpstream: async () => ({ kind: "active", packument: linkedPackument }) });
    const application = await steward.issueChallenge({ namespace: "@acme/*", domain: "acme.example", claimantPublicKey: claimant.publicKey });
    assert.equal(steward.release("r0").corpus.claims.length, 0);

    let queried = "";
    assert.equal(await steward.verifyChallenge(application.id, async (domain) => { queried = domain; return [["wrong-value"]]; }), false);
    assert.equal(queried, "acme.example");
    assert.throws(() => steward.approve(application.id), /passed challenge/i);
    assert.equal(await steward.verifyChallenge(application.id, async () => [[application.txtValue]]), true);
    steward.approve(application.id);
    assert.deepEqual(steward.release("r1").corpus.claims.map((claim) => claim.namespace), ["@acme/*"]);

    now += 366 * 24 * 60 * 60 * 1000;
    assert.equal(steward.release("r2").corpus.claims[0]?.status, "frozen");
  });

  test("Tier-1 linkage is pure; Tier-2 stays announced and unroutable for 30 days", async () => {
    for (const fixture of FIXTURE.cases) {
      assert.equal(corroboratesClaimDomain(fixture.packument, fixture.domain), fixture.expected, fixture.name);
      assert.equal(corroboratesClaimDomain(fixture.packument, fixture.domain), fixture.expected, `${fixture.name} is repeatable`);
    }

    let now = Date.parse("2026-07-01T00:00:00.000Z");
    const steward = new ClaimSteward({ now: () => now, id: () => "tier2",
      lookupUpstream: async () => ({ kind: "active", packument: { name: "tanstack", repository: "https://github.com/squatter/tanstack" } }) });
    const app = await steward.issueChallenge({ namespace: "tanstack", domain: "tanstack.com", claimantPublicKey: claimant.publicKey });
    await steward.verifyChallenge(app.id, async () => [[app.txtValue]]);
    steward.approve(app.id, { evidenceRef: "case/PEP541-grade-42" });
    const announced = steward.release("announce").corpus;
    assert.equal(announced.claims.length, 0);
    assert.equal(announced.pendingClaims?.[0]?.namespace, "tanstack");

    now += 30 * 24 * 60 * 60 * 1000 - 1;
    assert.equal(steward.release("day-29").corpus.claims.length, 0);
    now += 1;
    assert.equal(steward.release("day-30").corpus.claims[0]?.namespace, "tanstack");
  });

  test("transfers remain attributed to the old domain until a full 30-day release window", async () => {
    let now = Date.parse("2026-07-01T00:00:00.000Z");
    let next = 0;
    const oldClaimant = generateKeypair();
    const newClaimant = generateKeypair();
    const steward = new ClaimSteward({ now: () => now, id: () => `id-${++next}`, lookupUpstream: absent });
    const original = await steward.issueChallenge({ namespace: "pkg", domain: "old.example", claimantPublicKey: oldClaimant.publicKey });
    await steward.verifyChallenge(original.id, async () => [[original.txtValue]]);
    steward.approve(original.id);
    const target = await steward.issueChallenge({ namespace: "pkg", domain: "new.example", claimantPublicKey: newClaimant.publicKey });
    await steward.verifyChallenge(target.id, async () => [[target.txtValue]]);
    assert.throws(() => steward.requestTransfer("pkg", target.id, "invalid"), /valid old claimant signature/);
    const signature = signTransferRequest({ namespace: "pkg", targetDomain: "new.example", targetChallengeId: target.id,
      targetClaimantPublicKey: newClaimant.publicKey }, oldClaimant.privateKey);
    steward.requestTransfer("pkg", target.id, signature);

    assert.equal(steward.release("pending").corpus.claims[0]?.domain, "old.example");
    now += 30 * 24 * 60 * 60 * 1000;
    assert.equal(steward.release("effective").corpus.claims[0]?.domain, "new.example");
    assert.equal(steward.release("effective").corpus.claims[0]?.claimantPublicKey, newClaimant.publicKey);
  });

  test("a dispute freezes publish state immediately and its ruling waits 30 days", async () => {
    let now = Date.parse("2026-07-01T00:00:00.000Z");
    let next = 0;
    const steward = new ClaimSteward({ now: () => now, id: () => `dispute-${++next}`, lookupUpstream: absent });
    const original = await steward.issueChallenge({ namespace: "contested", domain: "old.example", claimantPublicKey: claimant.publicKey });
    await steward.verifyChallenge(original.id, async () => [[original.txtValue]]);
    steward.approve(original.id);
    const challenger = await steward.issueChallenge({ namespace: "contested", domain: "new.example", claimantPublicKey: claimant.publicKey });
    await steward.verifyChallenge(challenger.id, async () => [[challenger.txtValue]]);
    const unrelated = await steward.issueChallenge({ namespace: "other-name", domain: "new.example", claimantPublicKey: claimant.publicKey });
    await steward.verifyChallenge(unrelated.id, async () => [[unrelated.txtValue]]);
    steward.contest("contested");
    assert.throws(() => steward.ruleDispute("contested", unrelated.id, "case/wrong-target"), /namespace mismatch/);
    steward.ruleDispute("contested", challenger.id, "case/ruling-9");
    assert.equal(steward.release("announced").corpus.claims[0]?.status, "disputed");
    assert.equal(steward.release("announced").corpus.claims[0]?.domain, "old.example");
    now += 30 * 24 * 60 * 60 * 1000 - 1;
    assert.equal(steward.release("day-29").corpus.claims[0]?.domain, "old.example");
    now += 1;
    assert.equal(steward.release("day-30").corpus.claims[0]?.domain, "new.example");
    assert.equal(steward.release("day-30").corpus.claims[0]?.status, "active");
  });

  test("releases are parseable and can be signed for offline fail-closed consumers", async () => {
    const { publicKey, privateKey } = generateKeypair();
    const steward = new ClaimSteward({ now: () => Date.parse("2026-07-01T00:00:00.000Z"), id: () => "free", lookupUpstream: absent });
    const app = await steward.issueChallenge({ namespace: "free-name", domain: "free.example", claimantPublicKey: claimant.publicKey });
    await steward.verifyChallenge(app.id, async () => [[app.txtValue]]);
    steward.approve(app.id);
    const release = steward.release("signed-1", privateKey);
    assert.ok(release.signature);
    assert.equal(verifyClaimCorpusBytes(release.raw, release.signature!, publicKey), true);
    assert.equal(parseClaimCorpus(release.raw).claims[0]?.challenge.id, app.id);
  });

  test("challenge, renewal, and claim state survives a steward restart", async () => {
    const stateFile = join(mkdtempSync(join(tmpdir(), "sentinel-steward-state-")), "state.json");
    const first = new ClaimSteward({ now: () => Date.parse("2026-07-01T00:00:00.000Z"), id: () => "durable", stateFile, lookupUpstream: absent });
    const app = await first.issueChallenge({ namespace: "durable-name", domain: "durable.example", claimantPublicKey: claimant.publicKey });
    await first.verifyChallenge(app.id, async () => [[app.txtValue]]);
    first.approve(app.id);

    const restarted = new ClaimSteward({ now: () => Date.parse("2026-07-02T00:00:00.000Z"), stateFile, lookupUpstream: absent });
    assert.equal(restarted.release("after-restart").corpus.claims[0]?.namespace, "durable-name");
    assert.equal(restarted.release("after-restart").corpus.claims[0]?.renewalDueAt, "2027-07-01T00:00:00.000Z");
  });

  test("only steward-owned upstream evidence selects Tier 3, including adjudicated long-dead placeholders", async () => {
    const longDead = new ClaimSteward({ lookupUpstream: async () => ({ kind: "long-dead-placeholder", packument: { name: "retired", deprecated: "retired" } }) });
    const app = await longDead.issueChallenge({ namespace: "retired", domain: "retired.example", claimantPublicKey: claimant.publicKey });
    await longDead.verifyChallenge(app.id, async () => [[app.txtValue]]);
    longDead.approve(app.id);
    assert.equal(longDead.release("long-dead").corpus.claims[0]?.namespace, "retired");
  });

  test("a visible domain change freezes the claim immediately", async () => {
    const steward = new ClaimSteward({ lookupUpstream: absent });
    const app = await steward.issueChallenge({ namespace: "renamed", domain: "old.example", claimantPublicKey: claimant.publicKey });
    await steward.verifyChallenge(app.id, async () => [[app.txtValue]]);
    steward.approve(app.id);
    steward.freezeForDomainChange("renamed", "monitor/domain-change-7");
    assert.equal(steward.release("frozen").corpus.claims[0]?.status, "frozen");
  });

  test("the authenticated control plane atomically publishes a version directory", async () => {
    const releaseDir = mkdtempSync(join(tmpdir(), "sentinel-steward-release-"));
    const signing = generateKeypair();
    const app = createStewardServer({ steward: new ClaimSteward({ lookupUpstream: absent }), token: "operator-token",
      resolveTxt: async () => [], privateKeyPem: signing.privateKey, releaseDir });
    const server = await new Promise<Server>((resolve) => { const value = app.listen(0, () => resolve(value)); });
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      assert.equal((await fetch(`${base}/-/claims/releases`, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ version: "release-1" }) })).status, 401);
      const response = await fetch(`${base}/-/claims/releases`, { method: "POST",
        headers: { "content-type": "application/json", authorization: "Bearer operator-token" },
        body: JSON.stringify({ version: "release-1" }) });
      assert.equal(response.status, 200);
      assert.deepEqual(readdirSync(join(releaseDir, "release-1")).sort(), ["claims.json", "claims.json.sig"]);
      assert.equal(existsSync(join(releaseDir, "claims.json")), false);
      assert.equal(verifyClaimCorpusBytes(readFileSync(join(releaseDir, "release-1", "claims.json")),
        readFileSync(join(releaseDir, "release-1", "claims.json.sig"), "utf8"), signing.publicKey), true);
    } finally { server.close(); }
  });
});
