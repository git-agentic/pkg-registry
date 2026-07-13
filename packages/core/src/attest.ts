import { createHash, createPublicKey } from "node:crypto";
import { signPolicy, verifyPolicyBytes } from "./policy.js";
import { ENGINE_VERSION } from "./audit.js";
import type { TreeAuditResult } from "./tree.js";
import type { Verdict } from "./types.js";

export const SENTINEL_PREDICATE_TYPE = "https://sentinel.dev/attestation/audit-summary/v1";
const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
const PAYLOAD_TYPE = "application/vnd.in-toto+json";

export interface AuditPredicate {
  verifier: { name: string; version: string };
  policyHash: string | null;
  claimCorpus: { version: string; hash: string } | null;
  verdict: Verdict;
  gated: boolean;
  counts: { allow: number; warn: number; block: number; error: number };
  packageCount: number;
  timestamp: string;
}
export interface InTotoStatementV1 {
  _type: string;
  subject: { name: string; digest: { sha256: string } }[];
  predicateType: string;
  predicate: AuditPredicate;
}
export interface DsseEnvelope { payloadType: string; payload: string; signatures: { keyid: string; sig: string }[]; }

export type VerifyReason =
  | "malformed" | "invalid-signature" | "wrong-predicate"
  | "subject-mismatch" | "policy-mismatch" | "verdict-block" | "verdict-warn";
export type VerifyResult =
  | { valid: true; statement: InTotoStatementV1; predicate: AuditPredicate }
  | { valid: false; reason: VerifyReason };

/** DSSE Pre-Authentication Encoding over the raw payload bytes. */
export function pae(payloadType: string, payload: Buffer): Buffer {
  const preamble = Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `, "utf8");
  return Buffer.concat([preamble, payload]);
}

/** Stable keyid for a public key: `SHA256:<base64(sha256(SPKI DER))>` (matches Phase 8 keyids). */
export function attestationKeyid(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return `SHA256:${createHash("sha256").update(der).digest("base64")}`;
}

/** Build the in-toto audit-summary Statement over a tree audit. Pure; `now` injected. */
export function buildAuditStatement(tree: TreeAuditResult, opts: { sbomDigest: string; sbomName: string; now: string }): InTotoStatementV1 {
  const a = tree.aggregate;
  // The fixed key insertion order below is load-bearing: signAttestation serializes this via
  // JSON.stringify, so the envelope is byte-identical only while the order is stable. Do NOT
  // rebuild via spread/dynamic keys — that would silently break determinism (and the round-trip).
  return {
    _type: STATEMENT_TYPE,
    subject: [{ name: opts.sbomName, digest: { sha256: opts.sbomDigest } }],
    predicateType: SENTINEL_PREDICATE_TYPE,
    predicate: {
      verifier: { name: "sentinel", version: ENGINE_VERSION },
      policyHash: tree.policyHash ?? null,
      claimCorpus: tree.claimCorpus ?? null,
      verdict: a.verdict,
      gated: a.gated,
      counts: { allow: a.counts.allow, warn: a.counts.warn, block: a.counts.block, error: a.counts.error },
      packageCount: tree.packages.length,
      timestamp: opts.now,
    },
  };
}

/** Sign a Statement into a DSSE envelope (Ed25519 over the PAE). */
export function signAttestation(statement: InTotoStatementV1, privateKeyPem: string, keyid: string): DsseEnvelope {
  const payloadBytes = Buffer.from(JSON.stringify(statement), "utf8");
  const sig = signPolicy(pae(PAYLOAD_TYPE, payloadBytes), privateKeyPem);
  return { payloadType: PAYLOAD_TYPE, payload: payloadBytes.toString("base64"), signatures: [{ keyid, sig }] };
}

/** Verify a DSSE audit attestation offline against a pinned key. Pure, total, fail-closed. */
export function verifyAttestation(
  envelope: unknown,
  publicKeyPem: string,
  opts: { expectedSbomDigest?: string; expectedPolicyHash?: string; requireVerdict?: "allow" | "allow-or-warn" } = {},
): VerifyResult {
  try {
    const env = envelope as DsseEnvelope;
    if (!env || typeof env.payloadType !== "string" || typeof env.payload !== "string" || !Array.isArray(env.signatures)) {
      return { valid: false, reason: "malformed" };
    }
    const payloadBytes = Buffer.from(env.payload, "base64");
    const signed = pae(env.payloadType, payloadBytes);
    const ok = env.signatures.some((s) => s && typeof s.sig === "string" && verifyPolicyBytes(signed, s.sig, publicKeyPem));
    if (!ok) return { valid: false, reason: "invalid-signature" };

    const statement = JSON.parse(payloadBytes.toString("utf8")) as InTotoStatementV1;
    if (statement.predicateType !== SENTINEL_PREDICATE_TYPE) return { valid: false, reason: "wrong-predicate" };
    const predicate = statement.predicate;

    if (opts.expectedSbomDigest && statement.subject?.[0]?.digest?.sha256 !== opts.expectedSbomDigest) {
      return { valid: false, reason: "subject-mismatch" };
    }
    if (opts.expectedPolicyHash && predicate.policyHash !== opts.expectedPolicyHash) {
      return { valid: false, reason: "policy-mismatch" };
    }
    if (opts.requireVerdict) {
      const allowed = opts.requireVerdict === "allow" ? ["allow"] : ["allow", "warn"];
      if (!allowed.includes(predicate.verdict)) {
        return { valid: false, reason: predicate.verdict === "block" ? "verdict-block" : "verdict-warn" };
      }
    }
    return { valid: true, statement, predicate };
  } catch {
    return { valid: false, reason: "malformed" };
  }
}
