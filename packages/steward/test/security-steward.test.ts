import assert from "node:assert/strict";
import { createPrivateKey, sign as edSign } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { connect, type AddressInfo } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";
import { generateKeypair } from "@git-agentic/sentinel-core";
import { ClaimSteward, corroboratesClaimDomain, signTransferRequest, type UpstreamClaimLookup } from "../src/steward.js";
import { createStewardServer } from "../src/server.js";

const DAY = 24 * 60 * 60 * 1000;
const absent: UpstreamClaimLookup = async () => ({ kind: "absent" });
const claimant = generateKeypair();

function clock(start = "2026-07-01T00:00:00.000Z") {
  const state = { now: Date.parse(start) };
  let n = 0;
  return { state, options: { now: () => state.now, id: () => `id-${++n}` } };
}

async function verified(steward: ClaimSteward, input: Parameters<ClaimSteward["issueChallenge"]>[0]) {
  const challenge = await steward.issueChallenge(input);
  assert.equal(await steward.verifyChallenge(challenge.id, async () => [[challenge.txtValue]]), true);
  return challenge;
}

describe("F12: Tier-1 corroboration needs a host under the claimed domain", () => {
  test("a same-named GitHub/GitLab organisation does not corroborate", () => {
    assert.equal(corroboratesClaimDomain({ repository: "https://github.com/TanStack/query" }, "tanstack.com"), false);
    assert.equal(corroboratesClaimDomain({ repository: "git+https://gitlab.com/acme/widget.git" }, "acme.example"), false);
    assert.equal(corroboratesClaimDomain({ homepage: "https://docs.acme.example/widget" }, "acme.example"), true);
  });

  test("a claim linked only through a same-named GitHub org lands in Tier 2 and needs evidence + timelock", async () => {
    const { state, options } = clock();
    const steward = new ClaimSteward({ ...options,
      lookupUpstream: async () => ({ kind: "active", packument: { name: "query", repository: "https://github.com/TanStack/query" } }) });
    const app = await verified(steward, { namespace: "query", domain: "tanstack.com", claimantPublicKey: claimant.publicKey });
    await assert.rejects(async () => steward.approve(app.id), /evidence/i);
    await steward.approve(app.id, { evidenceRef: "case/42" });
    assert.equal(steward.release("r1").corpus.claims.length, 0);
    state.now += 30 * DAY;
    assert.equal(steward.release("r2").corpus.claims[0]?.namespace, "query");
  });
});

describe("F15a: transfers only on an active, non-pending claim", () => {
  async function setup() {
    const c = clock();
    const oldKey = generateKeypair();
    const newKey = generateKeypair();
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: absent });
    const original = await verified(steward, { namespace: "pkg", domain: "old.example", claimantPublicKey: oldKey.publicKey });
    await steward.approve(original.id);
    const target = await verified(steward, { namespace: "pkg", domain: "new.example", claimantPublicKey: newKey.publicKey });
    const sign = () => signTransferRequest({ namespace: "pkg", targetDomain: "new.example", targetChallengeId: target.id,
      targetClaimantPublicKey: newKey.publicKey, currentChallengeId: original.id }, oldKey.privateKey);
    return { ...c, steward, original, target, sign, oldKey, newKey };
  }

  test("a disputed claim refuses a new transfer", async () => {
    const { steward, target, sign } = await setup();
    steward.contest("pkg");
    assert.throws(() => steward.requestTransfer("pkg", target.id, sign()), /active/);
  });

  test("a second transfer cannot replace a pending one", async () => {
    const { steward, target, sign } = await setup();
    steward.requestTransfer("pkg", target.id, sign());
    assert.throws(() => steward.requestTransfer("pkg", target.id, sign()), /pending/);
  });

  test("a transfer announced before a dispute is not materialized while the claim is disputed", async () => {
    const { steward, target, sign, state } = await setup();
    steward.requestTransfer("pkg", target.id, sign());
    steward.contest("pkg");
    state.now += 31 * DAY;
    const claim = steward.release("after-dispute").corpus.claims[0]!;
    assert.equal(claim.domain, "old.example");
    assert.equal(claim.status, "disputed");
  });
});

describe("F15b: renewal needs a fresh passed challenge and refuses disputes", () => {
  async function setup() {
    const c = clock();
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: absent });
    const original = await verified(steward, { namespace: "pkg", domain: "acme.example", claimantPublicKey: claimant.publicKey });
    await steward.approve(original.id);
    return { ...c, steward, original };
  }

  test("the challenge that created the claim cannot renew it", async () => {
    const { steward, original, state } = await setup();
    state.now += DAY;
    assert.throws(() => steward.renew("pkg", original.id), /fresh|newer/i);
  });

  test("a disputed claim cannot be renewed back to active", async () => {
    const { steward, state } = await setup();
    steward.contest("pkg");
    state.now += DAY;
    const fresh = await verified(steward, { namespace: "pkg", domain: "acme.example", claimantPublicKey: claimant.publicKey });
    assert.throws(() => steward.renew("pkg", fresh.id), /disputed/);
    assert.equal(steward.release("still-disputed").corpus.claims[0]?.status, "disputed");
  });

  test("a fresh challenge from the same domain still renews and unfreezes", async () => {
    const { steward, state } = await setup();
    state.now += 366 * DAY;
    assert.equal(steward.release("frozen").corpus.claims[0]?.status, "frozen");
    const fresh = await verified(steward, { namespace: "pkg", domain: "acme.example", claimantPublicKey: claimant.publicKey });
    steward.renew("pkg", fresh.id);
    assert.equal(steward.release("renewed").corpus.claims[0]?.status, "active");
  });
});

describe("F15c: challenges expire and Tier is recomputed at approval", () => {
  test("verify, approve, transfer and renew reject a challenge older than 30 days", async () => {
    const c = clock();
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: absent });
    const original = await verified(steward, { namespace: "pkg", domain: "acme.example", claimantPublicKey: claimant.publicKey });
    await steward.approve(original.id);
    const stale = await verified(steward, { namespace: "pkg", domain: "acme.example", claimantPublicKey: claimant.publicKey });
    const unverified = await steward.issueChallenge({ namespace: "other", domain: "other.example", claimantPublicKey: claimant.publicKey });
    const unapproved = await verified(steward, { namespace: "third", domain: "third.example", claimantPublicKey: claimant.publicKey });
    c.state.now += 31 * DAY;
    await assert.rejects(steward.verifyChallenge(unverified.id, async () => [[unverified.txtValue]]), /expired/i);
    await assert.rejects(async () => steward.approve(unapproved.id), /expired/i);
    assert.throws(() => steward.renew("pkg", stale.id), /expired/i);
    const sig = signTransferRequest({ namespace: "pkg", targetDomain: "acme.example", targetChallengeId: stale.id,
      targetClaimantPublicKey: claimant.publicKey, currentChallengeId: original.id }, claimant.privateKey);
    assert.throws(() => steward.requestTransfer("pkg", stale.id, sig), /expired/i);
  });

  test("approve re-runs the upstream lookup: a name taken since issuance is no longer free", async () => {
    const c = clock();
    let evidence: Awaited<ReturnType<UpstreamClaimLookup>> = { kind: "absent" };
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: async () => evidence });
    const app = await verified(steward, { namespace: "newly-squatted", domain: "acme.example", claimantPublicKey: claimant.publicKey });
    evidence = { kind: "active", packument: { name: "newly-squatted", repository: "https://github.com/squatter/x" } };
    await assert.rejects(async () => steward.approve(app.id), /evidence/i);
    assert.equal(steward.release("none").corpus.claims.length, 0);
  });
});

describe("F15d: evidenceRef and request bodies are type-checked", () => {
  test("a non-string evidenceRef is refused and cannot poison persisted state", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-steward-sec-"));
    const stateFile = join(dir, "state.json");
    const c = clock();
    const steward = new ClaimSteward({ ...c.options, stateFile,
      lookupUpstream: async () => ({ kind: "active", packument: { repository: "https://github.com/squatter/x" } }) });
    const app = await verified(steward, { namespace: "contested", domain: "acme.example", claimantPublicKey: claimant.publicKey });
    await assert.rejects(async () => steward.approve(app.id, { evidenceRef: { x: 1 } as never }), /evidence/i);
    assert.doesNotThrow(() => new ClaimSteward({ stateFile, lookupUpstream: absent }), "state must still load after a rejected request");
  });

  test("ruleDispute rejects a non-string evidenceRef", async () => {
    const c = clock();
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: absent });
    const original = await verified(steward, { namespace: "pkg", domain: "old.example", claimantPublicKey: claimant.publicKey });
    await steward.approve(original.id);
    const challenger = await verified(steward, { namespace: "pkg", domain: "new.example", claimantPublicKey: claimant.publicKey });
    steward.contest("pkg");
    assert.throws(() => steward.ruleDispute("pkg", challenger.id, { x: 1 } as never), /evidence/i);
  });

  test("issueChallenge ignores unknown body fields, so verifiedAt cannot pre-verify a challenge", async () => {
    const c = clock();
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: absent });
    const forged = await steward.issueChallenge({ namespace: "pkg", domain: "acme.example", claimantPublicKey: claimant.publicKey,
      verifiedAt: "2026-07-01T00:00:00.000Z" } as never);
    await assert.rejects(async () => steward.approve(forged.id), /passed challenge/i);
  });

  test("the control plane rejects wrongly typed bodies with 400 and leaves state untouched", async () => {
    const c = clock();
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: absent });
    let txt = "";
    const app = createStewardServer({ steward, token: "t", resolveTxt: async () => [[txt]], privateKeyPem: generateKeypair().privateKey });
    const server = await new Promise<Server>((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const post = (path: string, body: unknown) => fetch(`${base}${path}`, { method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer t" }, body: JSON.stringify(body) });
    try {
      assert.equal((await post("/-/claims/challenges", { namespace: 1, domain: "a.example", claimantPublicKey: claimant.publicKey })).status, 400);
      const issued = await post("/-/claims/challenges", { namespace: "pkg", domain: "a.example", claimantPublicKey: claimant.publicKey });
      assert.equal(issued.status, 201);
      const challenge = await issued.json() as { id: string; txtValue: string };
      txt = challenge.txtValue;
      assert.equal((await post(`/-/claims/challenges/${challenge.id}/verify`, {})).status, 200);
      assert.equal((await post(`/-/claims/challenges/${challenge.id}/approve`, { evidenceRef: 123 })).status, 400);
      assert.equal(steward.release("untouched").corpus.claims.length, 0, "a rejected approval must not create a claim");
      assert.equal((await post("/-/claims/transfers", { namespace: "pkg", targetChallengeId: 5, oldClaimantSignature: {} })).status, 400);
      assert.equal((await post("/-/claims/dispute-rulings", { namespace: "pkg", targetChallengeId: challenge.id, evidenceRef: [] })).status, 400);
      assert.equal((await post("/-/claims/renewals", { namespace: ["pkg"], challengeId: challenge.id })).status, 400);
      assert.equal((await post("/-/claims/domain-change-freezes", { namespace: "pkg", evidenceRef: 7 })).status, 400);
      assert.equal((await post(`/-/claims/challenges/${challenge.id}/approve`, {})).status, 200);
    } finally { server.close(); }
  });
});

describe("transfer signatures bind the claim's current challenge", () => {
  test("a signature over the legacy (unbound) bytes is no longer accepted", async () => {
    const c = clock();
    const oldKey = generateKeypair();
    const newKey = generateKeypair();
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: absent });
    const original = await verified(steward, { namespace: "pkg", domain: "old.example", claimantPublicKey: oldKey.publicKey });
    await steward.approve(original.id);
    const target = await verified(steward, { namespace: "pkg", domain: "new.example", claimantPublicKey: newKey.publicKey });
    const legacy = edSign(null, Buffer.from(JSON.stringify({ schema: 1, namespace: "pkg", targetDomain: "new.example",
      targetChallengeId: target.id, targetClaimantPublicKey: newKey.publicKey })), createPrivateKey(oldKey.privateKey)).toString("base64");
    assert.throws(() => steward.requestTransfer("pkg", target.id, legacy), /valid old claimant signature/);
  });

  test("a signature made before a renewal cannot be replayed after it", async () => {
    const c = clock();
    const oldKey = generateKeypair();
    const newKey = generateKeypair();
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: absent });
    const original = await verified(steward, { namespace: "pkg", domain: "old.example", claimantPublicKey: oldKey.publicKey });
    await steward.approve(original.id);
    const target = await verified(steward, { namespace: "pkg", domain: "new.example", claimantPublicKey: newKey.publicKey });
    const sig = signTransferRequest({ namespace: "pkg", targetDomain: "new.example", targetChallengeId: target.id,
      targetClaimantPublicKey: newKey.publicKey, currentChallengeId: original.id }, oldKey.privateKey);
    c.state.now += DAY;
    const renewal = await verified(steward, { namespace: "pkg", domain: "old.example", claimantPublicKey: oldKey.publicKey });
    steward.renew("pkg", renewal.id);
    assert.throws(() => steward.requestTransfer("pkg", target.id, sig), /valid old claimant signature/);
    const fresh = signTransferRequest({ namespace: "pkg", targetDomain: "new.example", targetChallengeId: target.id,
      targetClaimantPublicKey: newKey.publicKey, currentChallengeId: renewal.id }, oldKey.privateKey);
    steward.requestTransfer("pkg", target.id, fresh);
  });
});

describe("freezes and pending changes (review follow-ups)", () => {
  async function claimed() {
    const c = clock();
    const oldKey = generateKeypair();
    const newKey = generateKeypair();
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: absent });
    const original = await verified(steward, { namespace: "pkg", domain: "old.example", claimantPublicKey: oldKey.publicKey });
    await steward.approve(original.id);
    return { ...c, steward, original, oldKey, newKey };
  }

  test("a pending transfer is not materialized while the claim is frozen", async () => {
    const { steward, original, oldKey, newKey, state } = await claimed();
    const target = await verified(steward, { namespace: "pkg", domain: "new.example", claimantPublicKey: newKey.publicKey });
    steward.requestTransfer("pkg", target.id, signTransferRequest({ namespace: "pkg", targetDomain: "new.example",
      targetChallengeId: target.id, targetClaimantPublicKey: newKey.publicKey, currentChallengeId: original.id }, oldKey.privateKey));
    steward.freezeForDomainChange("pkg", "monitor/domain-change-1");
    state.now += 31 * DAY;
    const claim = steward.release("frozen-with-transfer").corpus.claims[0]!;
    assert.equal(claim.domain, "old.example");
    assert.equal(claim.status, "frozen");
  });

  test("a dispute survives expiry: only a ruling clears it, renewal cannot", async () => {
    const { steward, state } = await claimed();
    steward.contest("pkg");
    state.now += 366 * DAY;
    assert.equal(steward.release("expired-while-disputed").corpus.claims[0]?.status, "disputed");
    const fresh = await verified(steward, { namespace: "pkg", domain: "old.example", claimantPublicKey: claimant.publicKey });
    assert.throws(() => steward.renew("pkg", fresh.id), /disputed/);
    assert.equal(steward.release("still-disputed").corpus.claims[0]?.status, "disputed");
  });

  test("a domain-change freeze does not overwrite a dispute", async () => {
    const { steward } = await claimed();
    steward.contest("pkg");
    steward.freezeForDomainChange("pkg", "monitor/domain-change-2");
    assert.equal(steward.release("disputed-then-frozen").corpus.claims[0]?.status, "disputed");
  });
});

describe("review round 1: proofs are single-use and freshness holds across awaits", () => {
  test("re-verifying a used challenge does not revive it as a renewal, so an old transfer signature stays dead", async () => {
    const c = clock();
    const oldKey = generateKeypair();
    const newKey = generateKeypair();
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: absent });
    const c1 = await verified(steward, { namespace: "pkg", domain: "old.example", claimantPublicKey: oldKey.publicKey });
    await steward.approve(c1.id);
    const target = await verified(steward, { namespace: "pkg", domain: "new.example", claimantPublicKey: newKey.publicKey });
    const sigOnC1 = signTransferRequest({ namespace: "pkg", targetDomain: "new.example", targetChallengeId: target.id,
      targetClaimantPublicKey: newKey.publicKey, currentChallengeId: c1.id }, oldKey.privateKey);
    c.state.now += DAY;
    const c2 = await verified(steward, { namespace: "pkg", domain: "old.example", claimantPublicKey: oldKey.publicKey });
    steward.renew("pkg", c2.id);
    c.state.now += DAY;
    // Re-verify C1 (its TXT record is still published), then try to restore it as the claim's proof.
    assert.equal(await steward.verifyChallenge(c1.id, async () => [[c1.txtValue]]), true);
    assert.throws(() => steward.renew("pkg", c1.id), /fresh|already|used/i);
    assert.throws(() => steward.requestTransfer("pkg", target.id, sigOnC1), /valid old claimant signature/);
    assert.equal(steward.release("after-replay").corpus.claims[0]?.challenge.id, c2.id);
  });

  test("verifyChallenge re-checks expiry after the DNS lookup", async () => {
    const c = clock();
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: absent });
    const app = await steward.issueChallenge({ namespace: "pkg", domain: "acme.example", claimantPublicKey: claimant.publicKey });
    c.state.now += 29 * DAY + 23 * 3600_000;
    await assert.rejects(steward.verifyChallenge(app.id, async () => { c.state.now += 2 * 3600_000; return [[app.txtValue]]; }), /expired/i);
    c.state.now -= 2 * 3600_000;
    await assert.rejects(async () => steward.approve(app.id), /passed challenge/i);
  });

  test("approve re-checks expiry after the upstream lookup", async () => {
    const c = clock();
    let slow = false;
    const steward = new ClaimSteward({ ...c.options, lookupUpstream: async () => { if (slow) c.state.now += 2 * 3600_000; return { kind: "absent" }; } });
    const app = await verified(steward, { namespace: "pkg", domain: "acme.example", claimantPublicKey: claimant.publicKey });
    c.state.now += 29 * DAY + 23 * 3600_000;
    slow = true;
    await assert.rejects(async () => steward.approve(app.id), /expired/i);
    assert.equal(steward.release("none").corpus.claims.length, 0);
  });
});

describe("steward bind address", () => {
  const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

  async function boot(extra: Record<string, string>): Promise<{ log: string; port?: number; kill: () => void; code: Promise<number | null> }> {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-steward-bind-"));
    const keys = generateKeypair();
    writeFileSync(join(dir, "key.pem"), keys.privateKey);
    mkdirSync(join(dir, "release"));
    const child = spawn(process.execPath, [CLI], { env: { PATH: process.env.PATH ?? "", SENTINEL_STEWARD_TOKEN: "t",
      SENTINEL_STEWARD_STATE: join(dir, "state.json"), SENTINEL_CLAIM_CORPUS_PRIVATE_KEY: join(dir, "key.pem"),
      SENTINEL_CLAIM_CORPUS_RELEASE_DIR: join(dir, "release"), SENTINEL_STEWARD_PORT: "0", ...extra } });
    let log = "";
    const code = new Promise<number | null>((resolve) => child.once("exit", resolve));
    await new Promise<void>((resolve) => {
      const onData = (b: Buffer) => { log += b.toString(); if (/listening|FATAL/.test(log)) resolve(); };
      child.stdout.on("data", onData); child.stderr.on("data", onData); void code.then(() => resolve());
    });
    const port = /:(\d+)\s*$/m.exec(log)?.[1];
    return { log, ...(port ? { port: Number(port) } : {}), kill: () => child.kill("SIGKILL"), code };
  }

  const reachable = (host: string, port: number) => new Promise<boolean>((resolve) => {
    const socket = connect({ host, port, timeout: 1000 });
    socket.once("connect", () => { socket.destroy(); resolve(true); });
    socket.once("error", () => resolve(false));
    socket.once("timeout", () => { socket.destroy(); resolve(false); });
  });

  test("defaults to loopback only", async () => {
    const s = await boot({});
    try {
      assert.match(s.log, /http:\/\/127\.0\.0\.1:\d+/);
      assert.ok(s.port, "log carries the bound port");
      assert.equal(await reachable("127.0.0.1", s.port!), true);
      const external = Object.values(networkInterfaces()).flat().find((i) => i && i.family === "IPv4" && !i.internal);
      if (external) assert.equal(await reachable(external.address, s.port!), false, "must not accept connections on a non-loopback address");
    } finally { s.kill(); }
  });

  test("SENTINEL_STEWARD_HOST overrides and an empty value is FATAL", async () => {
    const wide = await boot({ SENTINEL_STEWARD_HOST: "0.0.0.0" });
    try { assert.match(wide.log, /http:\/\/0\.0\.0\.0:\d+/); } finally { wide.kill(); }
    const bad = await boot({ SENTINEL_STEWARD_HOST: "" });
    assert.match(bad.log, /FATAL.*SENTINEL_STEWARD_HOST/);
    assert.equal(await bad.code, 1);
  });
});
