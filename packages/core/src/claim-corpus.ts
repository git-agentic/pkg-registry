import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";

export type ClaimStatus = "active" | "frozen" | "disputed";
export type ClaimChangeKind = "transfer" | "dispute-ruling" | "tier2-grant";

export interface DnsChallengeProof {
  method: "dns-txt";
  id: string;
  verifiedAt: string;
}

export interface TrustedPublisher {
  issuer: string;
  repository?: string;
  workflowRef?: string;
  builder?: string;
}

export interface PendingClaimChange {
  kind: ClaimChangeKind;
  announcedAt: string;
  effectiveAt: string;
  targetDomain?: string;
  challenge?: DnsChallengeProof;
  authorizedBy: string;
}

export interface VerifiedClaim {
  /** `@scope/*` or an exact unscoped package name. */
  namespace: string;
  domain: string;
  status: ClaimStatus;
  challenge: DnsChallengeProof;
  renewalDueAt: string;
  trustedPublishers?: readonly TrustedPublisher[];
  /** Announcement only. Consumers never apply it; a later steward release materializes it. */
  pending?: PendingClaimChange;
}

/** Announced Tier-2 issuance. It is deliberately excluded from source(name). */
export interface PendingClaimGrant {
  namespace: string;
  domain: string;
  tier: 2;
  challenge: DnsChallengeProof;
  announcedAt: string;
  effectiveAt: string;
  authorizedBy: string;
  trustedPublishers?: readonly TrustedPublisher[];
}

export interface ClaimCorpus {
  schema: 1;
  version: string;
  issuedAt: string;
  claims: readonly VerifiedClaim[];
  pendingClaims?: readonly PendingClaimGrant[];
}

export interface LoadedClaimCorpus {
  corpus: ClaimCorpus;
  hash: string;
}

export const EMPTY_CLAIM_CORPUS: ClaimCorpus = Object.freeze({
  schema: 1,
  version: "empty",
  issuedAt: "1970-01-01T00:00:00.000Z",
  claims: Object.freeze([]),
});

const UNSCOPED_NAME = /^[a-z0-9][a-z0-9._~-]*$/;
const SCOPED_CLAIM = /^@[a-z0-9][a-z0-9._~-]*\/\*$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const STATUSES = new Set<ClaimStatus>(["active", "frozen", "disputed"]);
const CHANGE_KINDS = new Set<ClaimChangeKind>(["transfer", "dispute-ruling", "tier2-grant"]);
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

function objectAt(value: unknown, path: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`invalid claim corpus: ${path} must be an object`);
  return value as Record<string, unknown>;
}

function nonempty(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`invalid claim corpus: ${path} must be a non-empty string`);
  return value;
}

function instant(value: unknown, path: string): string {
  const text = nonempty(value, path);
  if (!Number.isFinite(Date.parse(text)) || new Date(text).toISOString() !== text) {
    throw new Error(`invalid claim corpus: ${path} must be a canonical ISO timestamp`);
  }
  return text;
}

function domain(value: unknown, path: string): string {
  const text = nonempty(value, path);
  if (!DOMAIN.test(text)) throw new Error(`invalid claim corpus: ${path} must be a lowercase apex domain`);
  return text;
}

function challenge(value: unknown, path: string): DnsChallengeProof {
  const input = objectAt(value, path);
  if (input.method !== "dns-txt") throw new Error(`invalid claim corpus: ${path}.method must be dns-txt`);
  return { method: "dns-txt", id: nonempty(input.id, `${path}.id`), verifiedAt: instant(input.verifiedAt, `${path}.verifiedAt`) };
}

function trustedPublishers(value: unknown, path: string): TrustedPublisher[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length === 0) throw new Error(`invalid claim corpus: ${path} must be a non-empty array`);
  return value.map((entry, index) => {
    const input = objectAt(entry, `${path}[${index}]`);
    const publisher: TrustedPublisher = { issuer: nonempty(input.issuer, `${path}[${index}].issuer`) };
    for (const field of ["repository", "workflowRef", "builder"] as const) {
      if (input[field] !== undefined) publisher[field] = nonempty(input[field], `${path}[${index}].${field}`);
    }
    if (!publisher.repository && !publisher.workflowRef) {
      throw new Error(`invalid claim corpus: ${path}[${index}] requires repository or workflowRef`);
    }
    return publisher;
  });
}

function pendingChange(value: unknown, path: string): PendingClaimChange | undefined {
  if (value === undefined) return undefined;
  const input = objectAt(value, path);
  if (!CHANGE_KINDS.has(input.kind as ClaimChangeKind)) throw new Error(`invalid claim corpus: ${path}.kind is invalid`);
  const announcedAt = instant(input.announcedAt, `${path}.announcedAt`);
  const effectiveAt = instant(input.effectiveAt, `${path}.effectiveAt`);
  if (Date.parse(effectiveAt) - Date.parse(announcedAt) < THIRTY_DAYS_MS) {
    throw new Error(`invalid claim corpus: ${path} must provide at least 30 days notice`);
  }
  const kind = input.kind as ClaimChangeKind;
  const result: PendingClaimChange = {
    kind,
    announcedAt,
    effectiveAt,
    authorizedBy: nonempty(input.authorizedBy, `${path}.authorizedBy`),
  };
  if (input.targetDomain !== undefined) result.targetDomain = domain(input.targetDomain, `${path}.targetDomain`);
  if (input.challenge !== undefined) result.challenge = challenge(input.challenge, `${path}.challenge`);
  if ((kind === "transfer" || kind === "dispute-ruling") && (!result.targetDomain || !result.challenge)) {
    throw new Error(`invalid claim corpus: ${path} requires targetDomain and a passed challenge`);
  }
  return result;
}

/** Strictly parse trust-bearing claim data. Invalid input always throws. */
export function parseClaimCorpus(raw: Buffer): ClaimCorpus {
  let decoded: unknown;
  try { decoded = JSON.parse(raw.toString("utf8")); }
  catch { throw new Error("invalid claim corpus: expected JSON"); }
  const input = objectAt(decoded, "root");
  if (input.schema !== 1) throw new Error("invalid claim corpus: schema must be 1");
  const version = nonempty(input.version, "version");
  const issuedAt = instant(input.issuedAt, "issuedAt");
  if (!Array.isArray(input.claims)) throw new Error("invalid claim corpus: claims must be an array");
  const seen = new Set<string>();
  const claims = input.claims.map((entry, index): VerifiedClaim => {
    const path = `claims[${index}]`;
    const value = objectAt(entry, path);
    const namespace = nonempty(value.namespace, `${path}.namespace`);
    if (!SCOPED_CLAIM.test(namespace) && !UNSCOPED_NAME.test(namespace)) {
      throw new Error(`invalid claim corpus: ${path}.namespace must be @scope/* or an exact unscoped name`);
    }
    if (seen.has(namespace)) throw new Error(`invalid claim corpus: overlapping namespace ${namespace}`);
    seen.add(namespace);
    if (!STATUSES.has(value.status as ClaimStatus)) throw new Error(`invalid claim corpus: ${path}.status is invalid`);
    const proof = challenge(value.challenge, `${path}.challenge`);
    if (Date.parse(proof.verifiedAt) > Date.parse(issuedAt)) {
      throw new Error(`invalid claim corpus: ${path}.challenge cannot postdate the corpus release`);
    }
    const renewalDueAt = instant(value.renewalDueAt, `${path}.renewalDueAt`);
    if (Date.parse(renewalDueAt) <= Date.parse(proof.verifiedAt)) {
      throw new Error(`invalid claim corpus: ${path}.renewalDueAt must follow challenge verification`);
    }
    const publishers = trustedPublishers(value.trustedPublishers, `${path}.trustedPublishers`);
    const pending = pendingChange(value.pending, `${path}.pending`);
    if (pending && Date.parse(pending.announcedAt) > Date.parse(issuedAt)) {
      throw new Error(`invalid claim corpus: ${path}.pending cannot postdate the corpus release`);
    }
    if (pending?.challenge && Date.parse(pending.challenge.verifiedAt) > Date.parse(pending.announcedAt)) {
      throw new Error(`invalid claim corpus: ${path}.pending challenge must pass before announcement`);
    }
    return {
      namespace,
      domain: domain(value.domain, `${path}.domain`),
      status: value.status as ClaimStatus,
      challenge: proof,
      renewalDueAt,
      ...(publishers ? { trustedPublishers: publishers } : {}),
      ...(pending ? { pending } : {}),
    };
  });
  let pendingClaims: PendingClaimGrant[] | undefined;
  if (input.pendingClaims !== undefined) {
    if (!Array.isArray(input.pendingClaims)) throw new Error("invalid claim corpus: pendingClaims must be an array");
    pendingClaims = input.pendingClaims.map((entry, index) => {
      const path = `pendingClaims[${index}]`;
      const value = objectAt(entry, path);
      const namespace = nonempty(value.namespace, `${path}.namespace`);
      if (!SCOPED_CLAIM.test(namespace) && !UNSCOPED_NAME.test(namespace)) {
        throw new Error(`invalid claim corpus: ${path}.namespace must be @scope/* or an exact unscoped name`);
      }
      if (seen.has(namespace)) throw new Error(`invalid claim corpus: overlapping namespace ${namespace}`);
      seen.add(namespace);
      if (value.tier !== 2) throw new Error(`invalid claim corpus: ${path}.tier must be 2`);
      const announcedAt = instant(value.announcedAt, `${path}.announcedAt`);
      const effectiveAt = instant(value.effectiveAt, `${path}.effectiveAt`);
      if (Date.parse(effectiveAt) - Date.parse(announcedAt) < THIRTY_DAYS_MS) {
        throw new Error(`invalid claim corpus: ${path} must provide at least 30 days notice`);
      }
      if (Date.parse(announcedAt) > Date.parse(issuedAt)) throw new Error(`invalid claim corpus: ${path} cannot postdate the corpus release`);
      const proof = challenge(value.challenge, `${path}.challenge`);
      if (Date.parse(proof.verifiedAt) > Date.parse(announcedAt)) throw new Error(`invalid claim corpus: ${path}.challenge must pass before announcement`);
      const publishers = trustedPublishers(value.trustedPublishers, `${path}.trustedPublishers`);
      return {
        namespace,
        domain: domain(value.domain, `${path}.domain`),
        tier: 2,
        challenge: proof,
        announcedAt,
        effectiveAt,
        authorizedBy: nonempty(value.authorizedBy, `${path}.authorizedBy`),
        ...(publishers ? { trustedPublishers: publishers } : {}),
      };
    });
  }
  return { schema: 1, version, issuedAt, claims, ...(pendingClaims ? { pendingClaims } : {}) };
}

export function claimCorpusHashOfBytes(raw: Buffer): string {
  return `sha256-${createHash("sha256").update(raw).digest("hex")}`;
}

export function signClaimCorpus(raw: Buffer, privateKeyPem: string): string {
  return sign(null, raw, createPrivateKey(privateKeyPem)).toString("base64");
}

export function verifyClaimCorpusBytes(raw: Buffer, signature: string, publicKeyPem: string): boolean {
  try { return verify(null, raw, createPublicKey(publicKeyPem), Buffer.from(signature, "base64")); }
  catch { return false; }
}

/** Load and verify raw bytes before parsing. Suitable for fail-closed startup. */
export function loadClaimCorpus(opts: { file: string; sig: string; publicKeyPem: string }): LoadedClaimCorpus {
  const raw = readFileSync(opts.file);
  const signature = readFileSync(opts.sig, "utf8").trim();
  if (!verifyClaimCorpusBytes(raw, signature, opts.publicKeyPem)) throw new Error("claim corpus signature verification failed");
  return { corpus: parseClaimCorpus(raw), hash: claimCorpusHashOfBytes(raw) };
}
