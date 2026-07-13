import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, randomBytes, randomUUID, sign as edSign, verify as edVerify } from "node:crypto";
import { dirname } from "node:path";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import {
  parseClaimCorpus,
  signClaimCorpus,
  isValidClaimDomain,
  isValidClaimNamespace,
  type ClaimCorpus,
  type DnsChallengeProof,
  type PendingClaimGrant,
  type TrustedPublisher,
  type VerifiedClaim,
} from "@sentinel/core";

export type GrandfatherTier = 1 | 2 | 3;
export type TxtResolver = (domain: string) => Promise<readonly (readonly string[])[]>;

export interface ClaimApplicationInput {
  namespace: string;
  domain: string;
  trustedPublishers?: TrustedPublisher[];
  claimantPublicKey: string;
}

export type UpstreamClaimEvidence =
  | { kind: "absent" }
  | { kind: "long-dead-placeholder"; packument: unknown }
  | { kind: "active"; packument: unknown };

export type UpstreamClaimLookup = (namespace: string) => Promise<UpstreamClaimEvidence>;

export interface ClaimChallenge {
  id: string;
  domain: string;
  txtValue: string;
}

interface Application extends ClaimApplicationInput, ClaimChallenge {
  tier: GrandfatherTier;
  upstreamPackument: unknown | null;
  issuedAt: string;
  verifiedAt?: string;
}

interface PendingGrant {
  claim: VerifiedClaim;
  announcedAt: string;
  effectiveAt: string;
  evidenceRef: string;
}

export interface StewardOptions {
  now?: () => number;
  id?: () => string;
  /** Durable state file. Invalid state fails closed during construction. */
  stateFile?: string;
  /** Authoritative upstream lookup owned by the steward, never applicant input. */
  lookupUpstream: UpstreamClaimLookup;
}

const DAY = 24 * 60 * 60 * 1000;
const STATE_VALIDATION_ISSUED_AT = "9999-12-31T23:59:59.999Z";

function iso(ms: number): string { return new Date(ms).toISOString(); }

function isCanonicalInstant(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

function renewalDue(verifiedAt: string): string {
  const date = new Date(verifiedAt);
  date.setUTCFullYear(date.getUTCFullYear() + 1);
  return date.toISOString();
}

export function transferRequestBytes(input: { namespace: string; targetDomain: string; targetChallengeId: string; targetClaimantPublicKey: string }): Buffer {
  return Buffer.from(JSON.stringify({ schema: 1, ...input }));
}

export function signTransferRequest(
  input: { namespace: string; targetDomain: string; targetChallengeId: string; targetClaimantPublicKey: string },
  privateKeyPem: string,
): string {
  return edSign(null, transferRequestBytes(input), createPrivateKey(privateKeyPem)).toString("base64");
}

function directUrls(packument: unknown): string[] {
  if (!packument || typeof packument !== "object") return [];
  const input = packument as Record<string, unknown>;
  const result: string[] = [];
  const add = (value: unknown) => {
    if (typeof value === "string") result.push(value);
    else if (value && typeof value === "object" && typeof (value as { url?: unknown }).url === "string") result.push((value as { url: string }).url);
  };
  add(input.homepage);
  add(input.repository);
  add(input.provenanceRepository);
  if (input.versions && typeof input.versions === "object") {
    for (const version of Object.values(input.versions as Record<string, unknown>)) {
      if (!version || typeof version !== "object") continue;
      add((version as Record<string, unknown>).homepage);
      add((version as Record<string, unknown>).repository);
      add((version as Record<string, unknown>).provenanceRepository);
    }
  }
  return result;
}

/** Pure Tier-1 linkage check over upstream-owned metadata and the challenged domain. */
export function corroboratesClaimDomain(upstreamPackument: unknown, claimDomain: string): boolean {
  const org = claimDomain.split(".")[0]?.replaceAll("-", "").toLowerCase();
  return directUrls(upstreamPackument).some((raw) => {
    try {
      const normalized = raw.replace(/^git\+/, "").replace(/^git:\/\//, "https://");
      const url = new URL(normalized);
      const host = url.hostname.toLowerCase();
      if (host === claimDomain || host.endsWith(`.${claimDomain}`)) return true;
      if (host === "github.com" || host === "gitlab.com") {
        return Boolean(org) && (url.pathname.split("/").filter(Boolean)[0]?.replaceAll("-", "").toLowerCase() === org);
      }
      return false;
    } catch { return false; }
  });
}

/**
 * Steward-side state machine. Network access is confined to verifyChallenge's
 * injected DNS lookup; release output is static signed data for offline fleets.
 */
export class ClaimSteward {
  private readonly now: () => number;
  private readonly id: () => string;
  private readonly stateFile: string | undefined;
  private readonly lookupUpstream: UpstreamClaimLookup;
  private readonly applications = new Map<string, Application>();
  private readonly claims = new Map<string, VerifiedClaim>();
  private readonly pendingGrants = new Map<string, PendingGrant>();

  constructor(options: StewardOptions) {
    this.now = options.now ?? Date.now;
    this.id = options.id ?? randomUUID;
    this.stateFile = options.stateFile;
    this.lookupUpstream = options.lookupUpstream;
    this.loadState();
  }

  async issueChallenge(input: ClaimApplicationInput): Promise<ClaimChallenge> {
    if (!isValidClaimNamespace(input.namespace)) throw new Error("invalid namespace: expected @scope/* or exact unscoped name");
    if (!isValidClaimDomain(input.domain)) throw new Error("invalid domain: expected a lowercase exact apex domain");
    try {
      if (createPublicKey(input.claimantPublicKey).asymmetricKeyType !== "ed25519") throw new Error("wrong key type");
    } catch { throw new Error("claimantPublicKey must be an Ed25519 public key PEM"); }
    const id = this.id();
    if (this.applications.has(id)) throw new Error(`duplicate challenge id ${id}`);
    const txtValue = `sentinel-claim=${id}.${randomBytes(18).toString("base64url")}`;
    const evidence = await this.lookupUpstream(input.namespace);
    const upstreamPackument = evidence.kind === "absent" ? null : evidence.packument;
    const tier: GrandfatherTier = evidence.kind === "absent" || evidence.kind === "long-dead-placeholder"
      ? 3
      : corroboratesClaimDomain(evidence.packument, input.domain) ? 1 : 2;
    this.applications.set(id, { ...input, tier, upstreamPackument, id, domain: input.domain, txtValue, issuedAt: iso(this.now()) });
    this.persist();
    return { id, domain: input.domain, txtValue };
  }

  async verifyChallenge(id: string, resolveTxt: TxtResolver): Promise<boolean> {
    const application = this.application(id);
    const records = await resolveTxt(application.domain);
    const passed = records.some((parts) => parts.join("") === application.txtValue);
    if (passed) { application.verifiedAt = iso(this.now()); this.persist(); }
    return passed;
  }

  approve(id: string, options: { evidenceRef?: string } = {}): void {
    const application = this.application(id);
    if (!application.verifiedAt) throw new Error("claim cannot be approved without a passed challenge");
    if (this.claims.has(application.namespace) || this.pendingGrants.has(application.namespace)) {
      throw new Error(`namespace overlap: ${application.namespace} already claimed or pending`);
    }
    if (application.tier === 1 && !corroboratesClaimDomain(application.upstreamPackument, application.domain)) {
      throw new Error("Tier-1 claim lacks corroborating upstream metadata");
    }
    const claim = parseClaimCorpus(Buffer.from(JSON.stringify({
      schema: 1, version: "steward-approval", issuedAt: iso(this.now()), claims: [this.claimFrom(application)],
    }))).claims[0]!;
    if (application.tier === 2) {
      if (!options.evidenceRef) throw new Error("Tier-2 claim requires adjudicated evidence");
      const announcedAt = iso(this.now());
      this.pendingGrants.set(application.namespace, {
        claim, announcedAt, effectiveAt: iso(this.now() + 30 * DAY), evidenceRef: options.evidenceRef,
      });
      this.persist();
      return;
    }
    this.claims.set(application.namespace, claim);
    this.persist();
  }

  requestTransfer(namespace: string, targetChallengeId: string, oldClaimantSignature: string): void {
    const claim = this.claim(namespace);
    const target = this.application(targetChallengeId);
    if (!target.verifiedAt) throw new Error("transfer target requires a passed challenge");
    if (target.namespace !== namespace) throw new Error("transfer challenge namespace mismatch");
    const request = { namespace, targetDomain: target.domain, targetChallengeId, targetClaimantPublicKey: target.claimantPublicKey };
    let authorized = false;
    try {
      authorized = edVerify(null, transferRequestBytes(request), createPublicKey(claim.claimantPublicKey), Buffer.from(oldClaimantSignature, "base64"));
    } catch { authorized = false; }
    if (!authorized) throw new Error("transfer requires a valid old claimant signature");
    const announcedAt = iso(this.now());
    claim.pending = {
      kind: "transfer", announcedAt, effectiveAt: iso(this.now() + 30 * DAY), targetDomain: target.domain,
      targetClaimantPublicKey: target.claimantPublicKey, challenge: this.proof(target), authorizedBy: oldClaimantSignature,
    };
    this.persist();
  }

  contest(namespace: string): void {
    this.claim(namespace).status = "disputed";
    this.persist();
  }

  ruleDispute(namespace: string, targetChallengeId: string, evidenceRef: string): void {
    const claim = this.claim(namespace);
    const target = this.application(targetChallengeId);
    if (claim.status !== "disputed") throw new Error("claim is not disputed");
    if (!target.verifiedAt) throw new Error("ruling target requires a passed challenge");
    if (target.namespace !== namespace) throw new Error("ruling challenge namespace mismatch");
    if (!evidenceRef) throw new Error("dispute ruling requires evidence");
    const announcedAt = iso(this.now());
    claim.pending = { kind: "dispute-ruling", announcedAt, effectiveAt: iso(this.now() + 30 * DAY),
      targetDomain: target.domain, targetClaimantPublicKey: target.claimantPublicKey,
      challenge: this.proof(target), authorizedBy: evidenceRef };
    this.persist();
  }

  renew(namespace: string, challengeId: string): void {
    const claim = this.claim(namespace);
    const application = this.application(challengeId);
    if (!application.verifiedAt || application.domain !== claim.domain) throw new Error("renewal requires a passed challenge by the same domain");
    claim.challenge = this.proof(application);
    claim.renewalDueAt = renewalDue(application.verifiedAt);
    claim.status = "active";
    this.persist();
  }

  freezeExpiredClaims(): void {
    this.applyExpiryFreeze();
    this.persist();
  }

  freezeForDomainChange(namespace: string, evidenceRef: string): void {
    if (!evidenceRef) throw new Error("domain-change freeze requires evidence");
    this.claim(namespace).status = "frozen";
    this.persist();
  }

  release(version: string, privateKeyPem?: string): { corpus: ClaimCorpus; raw: Buffer; signature?: string } {
    this.applyExpiryFreeze();
    this.materializeEffectiveChanges();
    this.persist();
    const pendingClaims: PendingClaimGrant[] = [...this.pendingGrants.values()].map(({ claim, announcedAt, effectiveAt, evidenceRef }) => ({
      namespace: claim.namespace, domain: claim.domain, claimantPublicKey: claim.claimantPublicKey, tier: 2, challenge: claim.challenge,
      announcedAt, effectiveAt, authorizedBy: evidenceRef,
      ...(claim.trustedPublishers ? { trustedPublishers: claim.trustedPublishers } : {}),
    }));
    const candidate: ClaimCorpus = {
      schema: 1, version, issuedAt: iso(this.now()), claims: [...this.claims.values()].map((claim) => structuredClone(claim)),
      ...(pendingClaims.length ? { pendingClaims } : {}),
    };
    const raw = Buffer.from(JSON.stringify(candidate));
    const corpus = parseClaimCorpus(raw);
    return { corpus, raw, ...(privateKeyPem ? { signature: signClaimCorpus(raw, privateKeyPem) } : {}) };
  }

  private materializeEffectiveChanges(): void {
    for (const [namespace, pending] of this.pendingGrants) {
      if (Date.parse(pending.effectiveAt) <= this.now()) {
        this.claims.set(namespace, pending.claim);
        this.pendingGrants.delete(namespace);
      }
    }
    for (const claim of this.claims.values()) {
      const pending = claim.pending;
      if (!pending || Date.parse(pending.effectiveAt) > this.now()) continue;
      claim.domain = pending.targetDomain!;
      claim.claimantPublicKey = pending.targetClaimantPublicKey!;
      claim.challenge = pending.challenge!;
      claim.renewalDueAt = renewalDue(pending.challenge!.verifiedAt);
      claim.status = "active";
      delete claim.pending;
    }
  }

  private applyExpiryFreeze(): void {
    for (const claim of this.claims.values()) if (Date.parse(claim.renewalDueAt) <= this.now()) claim.status = "frozen";
  }

  private claimFrom(application: Application): VerifiedClaim {
    return {
      namespace: application.namespace, domain: application.domain, claimantPublicKey: application.claimantPublicKey, status: "active",
      challenge: this.proof(application), renewalDueAt: renewalDue(application.verifiedAt!),
      ...(application.trustedPublishers?.length ? { trustedPublishers: structuredClone(application.trustedPublishers) } : {}),
    };
  }

  private proof(application: Application): DnsChallengeProof {
    return { method: "dns-txt", id: application.id, verifiedAt: application.verifiedAt! };
  }

  private application(id: string): Application {
    const application = this.applications.get(id);
    if (!application) throw new Error(`unknown challenge ${id}`);
    return application;
  }

  private claim(namespace: string): VerifiedClaim {
    const claim = this.claims.get(namespace);
    if (!claim) throw new Error(`unknown claim ${namespace}`);
    return claim;
  }

  private loadState(): void {
    if (!this.stateFile || !existsSync(this.stateFile)) return;
    let decoded: unknown;
    try { decoded = JSON.parse(readFileSync(this.stateFile, "utf8")); }
    catch { throw new Error("invalid steward state: expected JSON"); }
    const state = decoded as { schema?: unknown; applications?: unknown; claims?: unknown; pendingGrants?: unknown };
    if (state?.schema !== 1 || !Array.isArray(state.applications) || !Array.isArray(state.claims) || !Array.isArray(state.pendingGrants)) {
      throw new Error("invalid steward state: expected schema 1 arrays");
    }
    const parsedClaims = parseClaimCorpus(Buffer.from(JSON.stringify({
      schema: 1, version: "steward-state", issuedAt: STATE_VALIDATION_ISSUED_AT, claims: state.claims,
    }))).claims;
    for (const candidate of state.applications as Application[]) {
      const application = candidate as Application;
      if (!application || typeof application.id !== "string" || !application.id || !isValidClaimNamespace(application.namespace) ||
          !isValidClaimDomain(application.domain) || ![1, 2, 3].includes(application.tier) ||
          typeof application.txtValue !== "string" || !application.txtValue || !isCanonicalInstant(application.issuedAt) ||
          (application.verifiedAt !== undefined && !isCanonicalInstant(application.verifiedAt))) {
        throw new Error("invalid steward state: malformed application");
      }
      try {
        if (createPublicKey(application.claimantPublicKey).asymmetricKeyType !== "ed25519") throw new Error("wrong key type");
      } catch { throw new Error("invalid steward state: malformed application claimant key"); }
      if (this.applications.has(application.id)) throw new Error("invalid steward state: duplicate application id");
      this.applications.set(application.id, application);
    }
    for (const claim of parsedClaims) this.claims.set(claim.namespace, claim);
    for (const candidate of state.pendingGrants as PendingGrant[]) {
      const pending = candidate as PendingGrant;
      if (!pending?.claim || !isCanonicalInstant(pending.announcedAt) || !isCanonicalInstant(pending.effectiveAt) ||
          Date.parse(pending.effectiveAt) - Date.parse(pending.announcedAt) < 30 * DAY ||
          typeof pending.evidenceRef !== "string" || !pending.evidenceRef) {
        throw new Error("invalid steward state: malformed pending grant");
      }
      const parsed = parseClaimCorpus(Buffer.from(JSON.stringify({
        schema: 1, version: "steward-pending-state", issuedAt: STATE_VALIDATION_ISSUED_AT, claims: [pending.claim],
      }))).claims[0]!;
      if (this.claims.has(parsed.namespace) || this.pendingGrants.has(parsed.namespace)) {
        throw new Error("invalid steward state: overlapping pending grant");
      }
      this.pendingGrants.set(parsed.namespace, { ...pending, claim: parsed });
    }
  }

  private persist(): void {
    if (!this.stateFile) return;
    mkdirSync(dirname(this.stateFile), { recursive: true });
    const raw = JSON.stringify({
      schema: 1,
      applications: [...this.applications.values()],
      claims: [...this.claims.values()],
      pendingGrants: [...this.pendingGrants.values()],
    });
    const temporary = `${this.stateFile}.${process.pid}.tmp`;
    writeFileSync(temporary, raw, { mode: 0o600 });
    renameSync(temporary, this.stateFile);
  }
}
