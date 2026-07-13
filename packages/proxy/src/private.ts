import { Buffer } from "node:buffer";
import { createHash, timingSafeEqual } from "node:crypto";

function sha(s: string): Buffer {
  return createHash("sha256").update(s).digest();
}

export interface ParsedPublish {
  version: string;
  manifest: Record<string, unknown>;
  tarball: Buffer;
  declaredIntegrity: string | undefined;
}

/**
 * Parse an npm publish payload (PUT /:pkg). Each publish carries exactly one new
 * version, identified by the single `_attachments` key `<name>-<version>.tgz`.
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
  const keys = Object.keys(attachments);
  if (keys.length !== 1) throw new Error("publish payload must have exactly one _attachment");
  const key = keys[0]!;
  const prefix = `${name}-`;
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
  const versions = b.versions ?? {};
  if (Object.keys(versions).length !== 1) throw new Error("publish payload must have exactly one version");
  const manifest = versions[version];
  if (!manifest) throw new Error(`publish payload missing manifest for version ${version}`);
  if (b["dist-tags"]?.latest !== version) throw new Error("publish dist-tags.latest must match the published version");
  if (manifest.name !== name) {
    throw new Error(`publish manifest name "${String(manifest.name)}" does not match ${name}`);
  }
  if (manifest.version !== version) {
    throw new Error(`publish manifest version "${String(manifest.version)}" does not match ${version}`);
  }
  const dist = manifest.dist as { integrity?: string } | undefined;
  return {
    version,
    manifest,
    tarball,
    declaredIntegrity: dist?.integrity,
  };
}

export function publishTokenValid(authHeader: string | undefined, tokens: string[]): boolean {
  if (tokens.length === 0) return false; // no tokens configured ⇒ publishing disabled (fail closed)
  // `\S.*` (not `.+`) so the token's first char is non-whitespace, keeping the
  // capture disjoint from the preceding `\s+` — linear-time on an adversarial
  // Authorization header (no polynomial backtracking over a long space run).
  const m = /^Bearer\s+(\S.*)$/i.exec(authHeader ?? "");
  if (!m) return false;
  const candidate = sha((m[1] ?? "").trim());
  return tokens.some((t) => timingSafeEqual(candidate, sha(t)));
}
