import { Buffer } from "node:buffer";
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { bundleFromJSON } from "@sigstore/bundle";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import type { ProvenanceIdentity, ProvenanceStatus } from "./types.js";

export type { ProvenanceIdentity, ProvenanceStatus };

/** One key from npm's TUF-distributed `registry.npmjs.org/keys.json` target. */
export interface NpmAttestationKey {
  keyId: string;
  keyUsage?: string;
  publicKey: {
    rawBytes: string;
    keyDetails?: string;
    validFor?: { start?: string | null; end?: string | null };
  };
}

/**
 * Pinned Sigstore trust material — a STATIC input like NPM_SIGNING_KEYS, never
 * fetched at audit time (invariant #3). `trustedRootJson` is the canonical
 * protobuf-JSON `trusted_root.json` TUF target.
 */
export interface ProvenanceTrustMaterial {
  trustedRootJson: unknown;
  npmKeys: NpmAttestationKey[];
}

export interface ProvenanceVerification {
  status: ProvenanceStatus;
  identity: ProvenanceIdentity | null;
  /** Human-readable cause when status is "invalid" or "unknown". */
  reason: string | null;
  /** True when every CA in the pinned root is past its validity window. */
  rootStale: boolean;
}

const SLSA_V1 = "https://slsa.dev/provenance/v1";

let defaultTrust: ProvenanceTrustMaterial | null | undefined;

/** Load the trust material bundled with the package (packages/core/trust/). */
export function loadDefaultTrustMaterial(): ProvenanceTrustMaterial | null {
  if (defaultTrust !== undefined) return defaultTrust;
  try {
    // ../trust resolves to packages/core/trust from BOTH src/ (tsx) and dist/ (built).
    const trustedRootJson = JSON.parse(readFileSync(new URL("../trust/trusted-root.json", import.meta.url), "utf8")) as unknown;
    const keysDoc = JSON.parse(readFileSync(new URL("../trust/npm-attestation-keys.json", import.meta.url), "utf8")) as { keys?: NpmAttestationKey[] };
    defaultTrust = { trustedRootJson, npmKeys: keysDoc.keys ?? [] };
  } catch {
    defaultTrust = null;
  }
  return defaultTrust;
}

/** Load operator-supplied trust material from explicit paths (env override). */
export function loadTrustMaterial(opts: { trustedRootPath: string; npmKeysPath?: string }): ProvenanceTrustMaterial {
  const trustedRootJson = JSON.parse(readFileSync(opts.trustedRootPath, "utf8")) as unknown;
  const npmKeys = opts.npmKeysPath
    ? ((JSON.parse(readFileSync(opts.npmKeysPath, "utf8")) as { keys?: NpmAttestationKey[] }).keys ?? [])
    : [];
  return { trustedRootJson, npmKeys };
}

interface AttestationEntry {
  predicateType?: string;
  bundle?: unknown;
}

/**
 * Offline-verify a package's attestation bundles against pinned trust material.
 * Pure and total: never throws, same inputs ⇒ same result.
 *
 * Status semantics (ADR-0022):
 * - "absent": the packument claimed no attestations.
 * - "unknown": claimed, but an input is missing (bundles unfetchable, empty
 *   list, or no trust material). Fail-open — outages never break installs.
 * - "invalid": bundles are PRESENT but any of them fails crypto, chain, tlog,
 *   parsing, or subject binding. Fail-closed — a crafted bundle must not
 *   degrade to "unknown" and slip past an identity gate.
 * - "verified": every present attestation verifies AND every subject digest
 *   binds to `integrity` (the SRI of the ACTUAL served bytes).
 */
export function verifyProvenance(input: {
  name: string;
  version: string;
  integrity: string;
  claimed: boolean;
  attestations: unknown | null;
  trust: ProvenanceTrustMaterial | null;
  /** Injectable clock (ISO) for root-staleness; an explicit input for determinism. */
  now?: string;
}): ProvenanceVerification {
  if (!input.claimed) return { status: "absent", identity: null, reason: null, rootStale: false };
  if (!input.trust) return { status: "unknown", identity: null, reason: "no Sigstore trust material configured", rootStale: false };
  const rootStale = trustRootStale(input.trust, input.now);
  if (!input.attestations) {
    return { status: "unknown", identity: null, reason: "attestation bundle could not be fetched", rootStale };
  }
  const list = (input.attestations as { attestations?: AttestationEntry[] }).attestations;
  if (!Array.isArray(list) || list.length === 0) {
    return { status: "unknown", identity: null, reason: "attestation endpoint returned no bundles", rootStale };
  }
  try {
    const verifier = buildVerifier(input.trust);
    let identity: ProvenanceIdentity | null = null;
    for (const a of list) {
      const bundle = bundleFromJSON(a.bundle);
      const result = verifier.verify(toSignedEntity(bundle));
      const stmt = statementOf(bundle);
      const bindErr = checkSubjectBinding(stmt, input.integrity);
      if (bindErr) return { status: "invalid", identity: null, reason: bindErr, rootStale };
      if (a.predicateType === SLSA_V1) identity = extractIdentity(result, stmt);
    }
    return { status: "verified", identity, reason: null, rootStale };
  } catch (e) {
    return { status: "invalid", identity: null, reason: (e as Error)?.message ?? "attestation verification failed", rootStale };
  }
}

function buildVerifier(trust: ProvenanceTrustMaterial): Verifier {
  const root = TrustedRoot.fromJSON(trust.trustedRootJson);
  // keyFinder resolves the npm publish attestation's key hint from the pinned
  // registry.npmjs.org/keys.json target. Probed 2026-07-07: one Verifier with
  // {ctlog 1, tlog 1, tsa 0} verifies BOTH the Fulcio-cert SLSA bundle and the
  // public-key npm publish bundle.
  const keyFinder = (hint: string) => {
    const k = trust.npmKeys.find((x) => x.keyId === hint);
    if (!k) throw new Error(`key not found: ${hint}`);
    const body = (k.publicKey.rawBytes.match(/.{1,64}/g) ?? []).join("\n");
    const start = k.publicKey.validFor?.start ? new Date(k.publicKey.validFor.start) : new Date(0);
    const end = k.publicKey.validFor?.end ? new Date(k.publicKey.validFor.end) : null;
    return {
      publicKey: createPublicKey(`-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`),
      validFor: (d: Date) => d >= start && (end === null || d <= end),
    };
  };
  return new Verifier(toTrustMaterial(root, keyFinder), { ctlogThreshold: 1, tlogThreshold: 1, tsaThreshold: 0 });
}

interface InTotoStatement {
  subject?: { name?: string; digest?: Record<string, string> }[];
  predicate?: {
    buildDefinition?: {
      externalParameters?: { workflow?: { ref?: unknown; repository?: unknown; path?: unknown } };
      resolvedDependencies?: { digest?: Record<string, string> }[];
    };
    runDetails?: { builder?: { id?: unknown } };
  };
}

function statementOf(bundle: ReturnType<typeof bundleFromJSON>): InTotoStatement {
  const env = (bundle as { content?: { dsseEnvelope?: { payload?: Uint8Array } } }).content?.dsseEnvelope;
  if (!env?.payload) throw new Error("attestation bundle has no DSSE envelope");
  return JSON.parse(Buffer.from(env.payload).toString("utf8")) as InTotoStatement;
}

/**
 * The in-toto subject digest (hex sha512) must match the tarball SRI. This is
 * the binding that makes verification mean something: a cryptographically valid
 * attestation for DIFFERENT bytes is invalid here. (Name/purl matching is
 * deliberately not attempted — the digest is the strong bind; purl encodings
 * vary across registries.)
 */
function checkSubjectBinding(stmt: InTotoStatement, integrity: string): string | null {
  const subjects = stmt.subject;
  if (!Array.isArray(subjects) || subjects.length === 0) return "attestation statement has no subject";
  for (const s of subjects) {
    const hex = s?.digest?.["sha512"];
    if (typeof hex !== "string" || hex.length === 0) return "attestation subject has no sha512 digest";
    const sri = "sha512-" + Buffer.from(hex, "hex").toString("base64");
    if (sri !== integrity) return "attestation subject digest does not match tarball integrity";
  }
  return null;
}

function extractIdentity(result: unknown, stmt: InTotoStatement): ProvenanceIdentity {
  const id = (result as { identity?: { subjectAlternativeName?: string; extensions?: { issuer?: string } } }).identity;
  const pred = stmt.predicate ?? {};
  const wf = pred.buildDefinition?.externalParameters?.workflow ?? {};
  const commit = pred.buildDefinition?.resolvedDependencies?.find((d) => typeof d?.digest?.["gitCommit"] === "string")?.digest?.["gitCommit"];
  return {
    workflow: id?.subjectAlternativeName ?? null,
    issuer: id?.extensions?.issuer ?? null,
    sourceRepository: typeof wf.repository === "string" ? wf.repository : null,
    ref: typeof wf.ref === "string" ? wf.ref : null,
    builder: typeof pred.runDetails?.builder?.id === "string" ? pred.runDetails.builder.id : null,
    commit: typeof commit === "string" ? commit : null,
  };
}

/**
 * Stale when EVERY CA in the pinned root has a validity window that has ended.
 * A CA with no validFor.end is open-ended: staleness is not determinable from
 * the snapshot, so it never reports stale.
 */
function trustRootStale(trust: ProvenanceTrustMaterial, nowIso?: string): boolean {
  try {
    const root = trust.trustedRootJson as { certificateAuthorities?: { validFor?: { end?: string } }[] };
    const cas = root.certificateAuthorities ?? [];
    if (cas.length === 0) return false;
    const now = nowIso ? new Date(nowIso) : new Date();
    return cas.every((ca) => typeof ca.validFor?.end === "string" && new Date(ca.validFor.end) < now);
  } catch {
    return false;
  }
}
