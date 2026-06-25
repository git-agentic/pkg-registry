import { Buffer } from "node:buffer";
import { createHash, timingSafeEqual } from "node:crypto";
import { matchPackage, type EnterprisePolicy } from "@sentinel/core";

function sha(s: string): Buffer {
  return createHash("sha256").update(s).digest();
}

export function isClaimed(name: string, policy: EnterprisePolicy): boolean {
  return (policy.privateNamespaces ?? []).some((p) => matchPackage(p, name));
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
    versions?: Record<string, Record<string, unknown>>;
    _attachments?: Record<string, { data?: string }>;
  };
  const attachments = b?._attachments ?? {};
  const keys = Object.keys(attachments);
  if (keys.length === 0) throw new Error("publish payload has no _attachments");
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
  const manifest = (b.versions ?? {})[version];
  if (!manifest) throw new Error(`publish payload missing manifest for version ${version}`);
  if (manifest.name !== undefined && manifest.name !== name) {
    throw new Error(`publish manifest name "${String(manifest.name)}" does not match ${name}`);
  }
  if (manifest.version !== undefined && manifest.version !== version) {
    throw new Error(`publish manifest version "${String(manifest.version)}" does not match ${version}`);
  }
  const dist = manifest.dist as { integrity?: string } | undefined;
  return {
    version,
    manifest,
    tarball: Buffer.from(data, "base64"),
    declaredIntegrity: dist?.integrity,
  };
}

export function publishTokenValid(authHeader: string | undefined, tokens: string[]): boolean {
  if (tokens.length === 0) return false; // no tokens configured ⇒ publishing disabled (fail closed)
  const m = /^Bearer\s+(.+)$/i.exec(authHeader ?? "");
  if (!m) return false;
  const candidate = sha((m[1] ?? "").trim());
  return tokens.some((t) => timingSafeEqual(candidate, sha(t)));
}
