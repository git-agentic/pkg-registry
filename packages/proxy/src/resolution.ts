import { matchPackage, type EnterprisePolicy } from "@sentinel/core";

export type RegistrySource = "policy-private" | "verified-claim" | "public-mirror";

/**
 * Phase 30 consumes already-verified claim data. Signature verification,
 * issuance, lifecycle, and corpus loading belong to Phase 31 (ADR-0046).
 */
export interface VerifiedClaim {
  /** `@scope/*` or an exact unscoped package name (ADR-0045 claim grammar). */
  namespace: string;
}

export interface ClaimCorpus {
  claims: readonly VerifiedClaim[];
}

export const EMPTY_CLAIM_CORPUS: ClaimCorpus = Object.freeze({ claims: Object.freeze([]) });

const UNSCOPED_PACKAGE_NAME_RE = /^[a-z0-9][a-z0-9._~-]*$/;
const SCOPED_PACKAGE_NAME_RE = /^@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*$/;
const SCOPED_CLAIM_RE = /^@[a-z0-9][a-z0-9._~-]*\/\*$/;

/** Validate and return the one canonical package-name representation used by the registry path. */
export function normalizePackageName(input: string): string {
  const name = input.trim();
  if (name !== input || name.length === 0 || name.length > 214 || (!UNSCOPED_PACKAGE_NAME_RE.test(name) && !SCOPED_PACKAGE_NAME_RE.test(name))) {
    throw new Error(`invalid package name "${input}"`);
  }
  return name;
}

export function validateClaimCorpus(corpus: ClaimCorpus): void {
  if (!corpus || !Array.isArray(corpus.claims)) throw new Error("invalid claim corpus: claims must be an array");
  for (let i = 0; i < corpus.claims.length; i++) {
    const namespace = corpus.claims[i]?.namespace;
    if (typeof namespace !== "string" || (!SCOPED_CLAIM_RE.test(namespace) && !UNSCOPED_PACKAGE_NAME_RE.test(namespace))) {
      throw new Error(`invalid claim corpus: claims[${i}].namespace must be @scope/* or an exact unscoped name`);
    }
  }
}

/** Pure, name-level source partition. Store contents and upstream state are deliberately absent. */
export function source(name: string, signedPolicy: EnterprisePolicy, claimCorpus: ClaimCorpus): RegistrySource {
  if ((signedPolicy.privateNamespaces ?? []).some((pattern) => matchPackage(pattern, name))) return "policy-private";
  if (claimCorpus.claims.some((claim) => matchPackage(claim.namespace, name))) return "verified-claim";
  return "public-mirror";
}

export function isNativeSource(value: RegistrySource): boolean {
  return value !== "public-mirror";
}
