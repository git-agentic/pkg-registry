import {
  EMPTY_CLAIM_CORPUS,
  matchPackage,
  parseClaimCorpus,
  type ClaimCorpus,
  type EnterprisePolicy,
  type ProvenanceIdentity,
  type VerifiedClaim,
} from "@sentinel/core";

export { EMPTY_CLAIM_CORPUS } from "@sentinel/core";
export type { ClaimCorpus, VerifiedClaim } from "@sentinel/core";

export type RegistrySource = "policy-private" | "verified-claim" | "public-mirror";

const UNSCOPED_PACKAGE_NAME_RE = /^[a-z0-9][a-z0-9._~-]*$/;
const SCOPED_PACKAGE_NAME_RE = /^@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*$/;
const LEGACY_UNSCOPED_PACKAGE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._~-]*$/;
const LEGACY_SCOPED_PACKAGE_NAME_RE = /^@[A-Za-z0-9][A-Za-z0-9._~-]*\/[A-Za-z0-9][A-Za-z0-9._~-]*$/;

/** Validate and return the one canonical package-name representation used by the registry path. */
export function normalizePackageName(input: string): string {
  const name = input.trim();
  if (name !== input || name.length === 0 || name.length > 214 || (!UNSCOPED_PACKAGE_NAME_RE.test(name) && !SCOPED_PACKAGE_NAME_RE.test(name))) {
    throw new Error(`invalid package name "${input}"`);
  }
  return name;
}

/**
 * Validate a registry read name without lowercasing it. npm still serves
 * grandfathered uppercase names, so transparent mirror GETs must preserve
 * their exact spelling; new native publications remain on the strict grammar.
 */
export function normalizeRegistryReadName(input: string): string {
  const name = input.trim();
  if (name !== input || name.length === 0 || name.length > 214 ||
      (!LEGACY_UNSCOPED_PACKAGE_NAME_RE.test(name) && !LEGACY_SCOPED_PACKAGE_NAME_RE.test(name))) {
    throw new Error(`invalid package name "${input}"`);
  }
  return name;
}

export function validateClaimCorpus(corpus: ClaimCorpus): void {
  parseClaimCorpus(Buffer.from(JSON.stringify(corpus)));
}

/** Pure, name-level source partition. Store contents and upstream state are deliberately absent. */
export function source(name: string, signedPolicy: EnterprisePolicy, claimCorpus: ClaimCorpus): RegistrySource {
  if ((signedPolicy.privateNamespaces ?? []).some((pattern) => matchPackage(pattern, name))) return "policy-private";
  if (claimCorpus.claims.some((claim) => matchPackage(claim.namespace, name))) return "verified-claim";
  return "public-mirror";
}

/** The verified claim governing a name, independent of its lifecycle state. */
export function claimForPackage(name: string, claimCorpus: ClaimCorpus): VerifiedClaim | undefined {
  return claimCorpus.claims.find((claim) => matchPackage(claim.namespace, name));
}

/** Match a verified SLSA identity against any trusted-publisher enrollment on a claim. */
export function trustedPublisherAuthorized(claim: VerifiedClaim, identity: ProvenanceIdentity | null | undefined): boolean {
  if (!identity || !claim.trustedPublishers?.length) return false;
  return claim.trustedPublishers.some((publisher) =>
    publisher.issuer === identity.issuer &&
    (publisher.repository === undefined || (identity.sourceRepository !== null && matchPackage(publisher.repository, identity.sourceRepository))) &&
    (publisher.workflowRef === undefined || (identity.workflow !== null && matchPackage(publisher.workflowRef, identity.workflow))) &&
    (publisher.builder === undefined || (identity.builder !== null && matchPackage(publisher.builder, identity.builder)))
  );
}

export function isNativeSource(value: RegistrySource): boolean {
  return value !== "public-mirror";
}
