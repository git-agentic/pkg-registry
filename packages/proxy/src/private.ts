import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";

/** Constant-time token equality without treating bearer tokens as passwords
 * or storing a password-style digest. Length is not confidential here: the
 * candidate came from the request and configured token lengths are visible to
 * the operator who owns this process. */
function tokenEqual(candidate: string, configured: string): boolean {
  const a = Buffer.from(candidate);
  const b = Buffer.from(configured);
  const length = Math.max(a.length, b.length, 1);
  const paddedA = Buffer.alloc(length);
  const paddedB = Buffer.alloc(length);
  a.copy(paddedA);
  b.copy(paddedB);
  return timingSafeEqual(paddedA, paddedB) && a.length === b.length;
}

export interface ParsedPublish {
  version: string;
  distTag: string;
  manifest: Record<string, unknown>;
  tarball: Buffer;
  declaredIntegrity: string | undefined;
  /** npm's optional publish-time Sigstore bundle, shaped for verifyProvenance(). */
  attestations: { attestations: { bundle: unknown }[] } | null;
}

/**
 * Parse an npm publish payload (PUT /:pkg). Each publish carries exactly one new
 * version, identified by one `<name>-<version>.tgz` attachment, plus at most one
 * optional matching `<name>-<version>.sigstore` provenance attachment.
 */
export function parsePublishBody(name: string, body: unknown): ParsedPublish {
  const b = body as {
    _id?: unknown;
    name?: unknown;
    "dist-tags"?: Record<string, unknown>;
    versions?: Record<string, Record<string, unknown>>;
    _attachments?: Record<string, { data?: string; length?: unknown }>;
  };
  if (!b || typeof b !== "object" || Array.isArray(b) || b._id !== name || b.name !== name) {
    throw new Error("publish payload _id/name must match the target package");
  }
  const attachments = b?._attachments ?? {};
  const prefix = `${name}-`;
  const keys = Object.keys(attachments);
  const tarballKeys = keys.filter((key) => key.startsWith(prefix) && key.endsWith(".tgz"));
  if (tarballKeys.length !== 1) throw new Error("publish payload must have exactly one tarball _attachment");
  const key = tarballKeys[0]!;
  if (!key.startsWith(prefix) || !key.endsWith(".tgz")) {
    throw new Error(`unexpected attachment name ${key} for ${name}`);
  }
  const version = key.slice(prefix.length, key.length - ".tgz".length);
  if (!/^[A-Za-z0-9][\w.+-]*$/.test(version)) {
    throw new Error(`invalid version "${version}" in publish payload`);
  }
  const data = attachments[key]?.data;
  if (typeof data !== "string") throw new Error("publish attachment has no base64 data");
  if (data.length === 0 || data.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(data)) {
    throw new Error("publish attachment is not canonical base64");
  }
  const tarball = Buffer.from(data, "base64");
  if (tarball.toString("base64") !== data) throw new Error("publish attachment is not canonical base64");
  const declaredLength = attachments[key]?.length;
  if (declaredLength !== undefined && declaredLength !== tarball.length) {
    throw new Error("publish attachment length does not match decoded bytes");
  }
  const sigstoreKey = `${name}-${version}.sigstore`;
  const unexpected = keys.filter((candidate) => candidate !== key && candidate !== sigstoreKey);
  if (unexpected.length > 0) throw new Error(`unexpected publish attachment ${unexpected[0]}`);
  let attestations: ParsedPublish["attestations"] = null;
  const sigstore = attachments[sigstoreKey];
  if (sigstore) {
    if (typeof sigstore.data !== "string" || sigstore.data.length === 0) throw new Error("publish sigstore attachment has no JSON data");
    if (sigstore.length !== undefined && sigstore.length !== Buffer.byteLength(sigstore.data)) {
      throw new Error("publish sigstore attachment length does not match JSON bytes");
    }
    let bundle: unknown;
    try { bundle = JSON.parse(sigstore.data); }
    catch { throw new Error("publish sigstore attachment is not valid JSON"); }
    if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) throw new Error("publish sigstore attachment must contain a bundle object");
    attestations = { attestations: [{ bundle }] };
  }
  const versions = b.versions ?? {};
  if (Object.keys(versions).length !== 1) throw new Error("publish payload must have exactly one version");
  const manifest = versions[version];
  if (!manifest) throw new Error(`publish payload missing manifest for version ${version}`);
  const distTags = Object.entries(b["dist-tags"] ?? {}).filter(([, target]) => target === version);
  if (distTags.length !== 1 || Object.keys(b["dist-tags"] ?? {}).length !== 1) {
    throw new Error("publish payload must have exactly one dist-tag targeting the published version");
  }
  if (!/^[^\s/]+$/.test(distTags[0]![0])) throw new Error("publish payload contains an invalid dist-tag");
  if (manifest.name !== name) {
    throw new Error(`publish manifest name "${String(manifest.name)}" does not match ${name}`);
  }
  if (manifest.version !== version) {
    throw new Error(`publish manifest version "${String(manifest.version)}" does not match ${version}`);
  }
  const dist = manifest.dist as { integrity?: string } | undefined;
  return {
    version,
    distTag: distTags[0]![0],
    manifest,
    tarball,
    declaredIntegrity: dist?.integrity,
    attestations,
  };
}

export function publishTokenValid(authHeader: string | undefined, tokens: string[]): boolean {
  if (tokens.length === 0) return false; // no tokens configured ⇒ publishing disabled (fail closed)
  // `\S.*` (not `.+`) so the token's first char is non-whitespace, keeping the
  // capture disjoint from the preceding `\s+` — linear-time on an adversarial
  // Authorization header (no polynomial backtracking over a long space run).
  const m = /^Bearer\s+(\S.*)$/i.exec(authHeader ?? "");
  if (!m) return false;
  const candidate = (m[1] ?? "").trim();
  return tokens.some((token) => tokenEqual(candidate, token));
}
