import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { generateKeypair, parseClaimCorpus, verifyClaimCorpusBytes } from "@sentinel/core";
import { ClaimSteward, corroboratesClaimDomain } from "../src/steward.js";

const FIXTURE = JSON.parse(readFileSync(join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "grandfathering.json"), "utf8")) as {
  cases: { name: string; domain: string; expected: boolean; packument: unknown }[];
};
const linkedPackument = FIXTURE.cases[0]!.packument;

describe("claim steward pipeline", () => {
  test("a corpus entry cannot exist before an exact-apex DNS challenge passes", async () => {
    let now = Date.parse("2026-07-01T00:00:00.000Z");
    const steward = new ClaimSteward({ now: () => now, id: (() => { let i = 0; return () => `id-${++i}`; })() });
    const application = steward.issueChallenge({ namespace: "@acme/*", domain: "acme.example", tier: 1, upstreamPackument: linkedPackument });
    assert.equal(steward.release("r0").corpus.claims.length, 0);

    let queried = "";
    assert.equal(await steward.verifyChallenge(application.id, async (domain) => { queried = domain; return [["wrong-value"]]; }), false);
    assert.equal(queried, "acme.example");
    assert.throws(() => steward.approve(application.id), /passed challenge/i);
    assert.equal(await steward.verifyChallenge(application.id, async () => [[application.txtValue]]), true);
    steward.approve(application.id);
    assert.deepEqual(steward.release("r1").corpus.claims.map((claim) => claim.namespace), ["@acme/*"]);

    now += 366 * 24 * 60 * 60 * 1000;
    steward.freezeExpiredClaims();
    assert.equal(steward.release("r2").corpus.claims[0]?.status, "frozen");
  });

  test("Tier-1 linkage is pure; Tier-2 stays announced and unroutable for 30 days", async () => {
    for (const fixture of FIXTURE.cases) {
      assert.equal(corroboratesClaimDomain(fixture.packument, fixture.domain), fixture.expected, fixture.name);
      assert.equal(corroboratesClaimDomain(fixture.packument, fixture.domain), fixture.expected, `${fixture.name} is repeatable`);
    }

    let now = Date.parse("2026-07-01T00:00:00.000Z");
    const steward = new ClaimSteward({ now: () => now, id: () => "tier2" });
    const app = steward.issueChallenge({ namespace: "tanstack", domain: "tanstack.com", tier: 2,
      upstreamPackument: { name: "tanstack", repository: "https://github.com/squatter/tanstack" } });
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
    const steward = new ClaimSteward({ now: () => now, id: () => `id-${++next}` });
    const original = steward.issueChallenge({ namespace: "pkg", domain: "old.example", tier: 3, upstreamPackument: null });
    await steward.verifyChallenge(original.id, async () => [[original.txtValue]]);
    steward.approve(original.id);
    const target = steward.issueChallenge({ namespace: "pkg", domain: "new.example", tier: 3, upstreamPackument: null });
    await steward.verifyChallenge(target.id, async () => [[target.txtValue]]);
    steward.requestTransfer("pkg", target.id, "old-claimant-signature");

    assert.equal(steward.release("pending").corpus.claims[0]?.domain, "old.example");
    now += 30 * 24 * 60 * 60 * 1000;
    assert.equal(steward.release("effective").corpus.claims[0]?.domain, "new.example");
  });

  test("a dispute freezes publish state immediately and its ruling waits 30 days", async () => {
    let now = Date.parse("2026-07-01T00:00:00.000Z");
    let next = 0;
    const steward = new ClaimSteward({ now: () => now, id: () => `dispute-${++next}` });
    const original = steward.issueChallenge({ namespace: "contested", domain: "old.example", tier: 3, upstreamPackument: null });
    await steward.verifyChallenge(original.id, async () => [[original.txtValue]]);
    steward.approve(original.id);
    const challenger = steward.issueChallenge({ namespace: "contested", domain: "new.example", tier: 3, upstreamPackument: null });
    await steward.verifyChallenge(challenger.id, async () => [[challenger.txtValue]]);
    steward.contest("contested");
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
    const steward = new ClaimSteward({ now: () => Date.parse("2026-07-01T00:00:00.000Z"), id: () => "free" });
    const app = steward.issueChallenge({ namespace: "free-name", domain: "free.example", tier: 3, upstreamPackument: null });
    await steward.verifyChallenge(app.id, async () => [[app.txtValue]]);
    steward.approve(app.id);
    const release = steward.release("signed-1", privateKey);
    assert.ok(release.signature);
    assert.equal(verifyClaimCorpusBytes(release.raw, release.signature!, publicKey), true);
    assert.equal(parseClaimCorpus(release.raw).claims[0]?.challenge.id, app.id);
  });

  test("challenge, renewal, and claim state survives a steward restart", async () => {
    const stateFile = join(mkdtempSync(join(tmpdir(), "sentinel-steward-state-")), "state.json");
    const first = new ClaimSteward({ now: () => Date.parse("2026-07-01T00:00:00.000Z"), id: () => "durable", stateFile });
    const app = first.issueChallenge({ namespace: "durable-name", domain: "durable.example", tier: 3, upstreamPackument: null });
    await first.verifyChallenge(app.id, async () => [[app.txtValue]]);
    first.approve(app.id);

    const restarted = new ClaimSteward({ now: () => Date.parse("2026-07-02T00:00:00.000Z"), stateFile });
    assert.equal(restarted.release("after-restart").corpus.claims[0]?.namespace, "durable-name");
    assert.equal(restarted.release("after-restart").corpus.claims[0]?.renewalDueAt, "2027-07-01T00:00:00.000Z");
  });
});
