import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import {
  DEFAULT_POLICY, generateKeypair, signPolicy, verifyPolicyBytes,
  policyHashOfBytes, parsePolicy, loadPolicy, treeGateOf,
  publishGateOf, retractionWindowOf, verdictAtOrAbove,
} from "../src/index.js";

const rawDefault = Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, version: "acme-1" }));

describe("policy signing", () => {
  test("sign → verify round-trips; tamper fails", () => {
    const { publicKey, privateKey } = generateKeypair();
    const sig = signPolicy(rawDefault, privateKey);
    assert.equal(verifyPolicyBytes(rawDefault, sig, publicKey), true);
    const tampered = Buffer.from(rawDefault.toString().replace("acme-1", "acme-2"));
    assert.equal(verifyPolicyBytes(tampered, sig, publicKey), false);
  });

  test("policyHashOfBytes is stable and prefixed", () => {
    assert.equal(policyHashOfBytes(rawDefault), policyHashOfBytes(rawDefault));
    assert.match(policyHashOfBytes(rawDefault), /^sha256-[0-9a-f]{64}$/);
  });

  test("parsePolicy rejects a non-schema-1 document", () => {
    assert.throws(() => parsePolicy(Buffer.from(JSON.stringify({ schema: 9 }))));
  });

  test("loadPolicy verifies signature and returns policy + raw-bytes hash", () => {
    const { publicKey, privateKey } = generateKeypair();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-policy-"));
    const file = join(dir, "policy.json");
    writeFileSync(file, rawDefault);
    writeFileSync(file + ".sig", signPolicy(rawDefault, privateKey));
    const { policy, hash } = loadPolicy({ file, sig: file + ".sig", publicKeyPem: publicKey });
    assert.equal(policy.version, "acme-1");
    assert.equal(hash, policyHashOfBytes(rawDefault));
  });

  test("loadPolicy throws on a bad signature (caller fails closed)", () => {
    const { publicKey } = generateKeypair();
    const other = generateKeypair();
    const dir = mkdtempSync(join(tmpdir(), "sentinel-policy-"));
    const file = join(dir, "policy.json");
    writeFileSync(file, rawDefault);
    writeFileSync(file + ".sig", signPolicy(rawDefault, other.privateKey)); // wrong key
    assert.throws(() => loadPolicy({ file, sig: file + ".sig", publicKeyPem: publicKey }), /signature/i);
  });
});

describe("parsePolicy malformed-policy rejection (fail closed at boot)", () => {
  function makeValid() {
    return {
      schema: 1,
      version: "test",
      scoring: {
        severityWeight: { info: 0, low: 4, medium: 12, high: 25, critical: 55 },
        diffMultiplier: 1.6,
        thresholds: { allow: 80, warn: 50 },
        hardBlockSeverity: "critical",
      },
      rules: { disabled: [] },
      allow: [],
      deny: [],
    };
  }

  test("accepts a fully-valid policy", () => {
    const policy = makeValid();
    const parsed = parsePolicy(Buffer.from(JSON.stringify(policy)));
    assert.equal(parsed.version, "test");
    assert.equal(parsed.scoring.hardBlockSeverity, "critical");
  });

  test("accepts a policy that omits allow/deny/rules (defaults to empty)", () => {
    const { allow: _a, deny: _d, rules: _r, ...minimal } = makeValid();
    const parsed = parsePolicy(Buffer.from(JSON.stringify(minimal)));
    assert.deepEqual(parsed.allow, []);
    assert.deepEqual(parsed.deny, []);
    assert.deepEqual(parsed.rules.disabled, []);
  });

  test("(a) throws when severityWeight is missing a key (no critical)", () => {
    const p = makeValid();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (p.scoring.severityWeight as any).critical;
    assert.throws(
      () => parsePolicy(Buffer.from(JSON.stringify(p))),
      /severityWeight.*critical|critical.*severityWeight/i,
    );
  });

  test("(b) throws when an allow entry is missing package", () => {
    const p = makeValid();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (p as any).allow = [{ rules: ["no-shell"] }];
    assert.throws(
      () => parsePolicy(Buffer.from(JSON.stringify(p))),
      /allow.*package|package.*allow/i,
    );
  });

  test("(c) throws when an allow entry's rules is not an array", () => {
    const p = makeValid();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (p as any).allow = [{ package: "lodash", rules: "no-shell" }];
    assert.throws(
      () => parsePolicy(Buffer.from(JSON.stringify(p))),
      /allow.*rules|rules.*array/i,
    );
  });

  test("(d) throws when hardBlockSeverity is not a valid severity", () => {
    const p = makeValid();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (p as any).scoring.hardBlockSeverity = "catastrophic";
    assert.throws(
      () => parsePolicy(Buffer.from(JSON.stringify(p))),
      /hardBlockSeverity/i,
    );
  });
});

describe("privateNamespaces validation", () => {
  const valid = (over: object) => Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, version: "v", ...over }));
  test("accepts an array of strings", () => {
    const p = parsePolicy(valid({ privateNamespaces: ["@acme/*", "acme-config"] }));
    assert.deepEqual(p.privateNamespaces, ["@acme/*", "acme-config"]);
  });
  test("defaults to [] when absent", () => {
    const body = { ...DEFAULT_POLICY, version: "v" } as Record<string, unknown>;
    delete body.privateNamespaces;
    assert.deepEqual(parsePolicy(Buffer.from(JSON.stringify(body))).privateNamespaces, []);
  });
  test("throws when present but not an array of strings", () => {
    assert.throws(() => parsePolicy(valid({ privateNamespaces: "@acme/*" })));
    assert.throws(() => parsePolicy(valid({ privateNamespaces: [1, 2] })));
  });
});

describe("provenanceIdentities parsing", () => {
  test("valid entries parse through", () => {
    const p = parsePolicy(Buffer.from(JSON.stringify({
      ...JSON.parse(JSON.stringify(DEFAULT_POLICY)),
      provenanceIdentities: [{ pattern: "@acme/*", repository: "https://github.com/acme/*", issuer: "https://token.actions.githubusercontent.com" }],
    })));
    assert.equal(p.provenanceIdentities?.[0]?.pattern, "@acme/*");
  });
  test("rejects entries without a pattern", () => {
    assert.throws(() => parsePolicy(Buffer.from(JSON.stringify({
      ...JSON.parse(JSON.stringify(DEFAULT_POLICY)),
      provenanceIdentities: [{ repository: "x" }],
    }))), /provenanceIdentities/);
  });
  test("rejects non-string constraint fields", () => {
    assert.throws(() => parsePolicy(Buffer.from(JSON.stringify({
      ...JSON.parse(JSON.stringify(DEFAULT_POLICY)),
      provenanceIdentities: [{ pattern: "a", repository: 42 }],
    }))), /provenanceIdentities/);
  });
});

describe("treeGate policy field", () => {
  test("treeGateOf defaults to block and honors an explicit value", () => {
    assert.equal(treeGateOf(DEFAULT_POLICY), "block");
    assert.equal(treeGateOf({ ...DEFAULT_POLICY, treeGate: "warn" }), "warn");
    assert.equal(treeGateOf({ ...DEFAULT_POLICY, treeGate: undefined }), "block");
  });

  test("parsePolicy accepts a valid treeGate and rejects a bad one", () => {
    const good = Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, treeGate: "warn" }));
    assert.equal(parsePolicy(good).treeGate, "warn");
    const bad = Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, treeGate: "nope" }));
    assert.throws(() => parsePolicy(bad), /treeGate/);
  });
});

describe("publishGate policy field", () => {
  test("defaults to block and accepts every verdict level", () => {
    assert.equal(publishGateOf(DEFAULT_POLICY), "block");
    for (const gate of ["allow", "warn", "block"] as const) {
      const parsed = parsePolicy(Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, publishGate: gate })));
      assert.equal(publishGateOf(parsed), gate);
    }
  });

  test("rejects an invalid publishGate", () => {
    assert.throws(
      () => parsePolicy(Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, publishGate: "nope" }))),
      /publishGate/,
    );
  });

  test("gate comparison follows allow < warn < block", () => {
    assert.equal(verdictAtOrAbove("allow", "allow"), true);
    assert.equal(verdictAtOrAbove("allow", "warn"), false);
    assert.equal(verdictAtOrAbove("warn", "warn"), true);
    assert.equal(verdictAtOrAbove("block", "warn"), true);
    assert.equal(verdictAtOrAbove("block", "block"), true);
  });
});

describe("retraction policy window", () => {
  test("defaults to 72 hours and 1,000 cumulative downloads", () => {
    assert.deepEqual(retractionWindowOf(DEFAULT_POLICY), { maxAgeHours: 72, maxDownloads: 1_000 });
    assert.deepEqual(retractionWindowOf({ ...DEFAULT_POLICY, retraction: undefined }), { maxAgeHours: 72, maxDownloads: 1_000 });
  });

  test("accepts finite non-negative policy-data bounds", () => {
    const parsed = parsePolicy(Buffer.from(JSON.stringify({
      ...DEFAULT_POLICY,
      retraction: { maxAgeHours: 24, maxDownloads: 50 },
    })));
    assert.deepEqual(retractionWindowOf(parsed), { maxAgeHours: 24, maxDownloads: 50 });
    assert.deepEqual(
      retractionWindowOf(parsePolicy(Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, retraction: { maxAgeHours: 0, maxDownloads: 0 } })))),
      { maxAgeHours: 0, maxDownloads: 0 },
    );
  });

  test("rejects malformed or unbounded retraction limits", () => {
    for (const retraction of [
      null,
      { maxAgeHours: -1, maxDownloads: 1_000 },
      { maxAgeHours: 72, maxDownloads: -1 },
      { maxAgeHours: 72.5, maxDownloads: 1_000 },
      { maxAgeHours: 72, maxDownloads: 1.5 },
      { maxAgeHours: 72 },
    ]) {
      assert.throws(
        () => parsePolicy(Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, retraction }))),
        /retraction/,
      );
    }
  });
});

describe("releaseCooldown policy field", () => {
  const base = { schema: 1, version: "t", scoring: { severityWeight: { info:0, low:4, medium:12, high:25, critical:55 }, diffMultiplier: 1.6, thresholds: { allow: 80, warn: 50 }, hardBlockSeverity: "critical" } };
  const parse = (extra: object) => parsePolicy(Buffer.from(JSON.stringify({ ...base, ...extra })));
  test("valid cooldown parses", () => {
    const p = parse({ releaseCooldown: { hours: 72, exempt: ["@acme/*"] } });
    assert.deepEqual(p.releaseCooldown, { hours: 72, exempt: ["@acme/*"] });
  });
  test("hours must be positive", () => assert.throws(() => parse({ releaseCooldown: { hours: 0 } }), /releaseCooldown/));
  test("hours must be finite and bounded", () => assert.throws(() => parse({ releaseCooldown: { hours: 100000 } }), /releaseCooldown/));
  test("exempt must be string[]", () => assert.throws(() => parse({ releaseCooldown: { hours: 24, exempt: [1] } }), /releaseCooldown/));
  test("absent cooldown ⇒ undefined (no behavior change)", () => assert.equal(parse({}).releaseCooldown, undefined));
});
