import { Buffer } from "node:buffer";
import { createPublicKey, verify } from "node:crypto";
import type { SignatureVerdict } from "./types.js";

export type { SignatureVerdict };

/** One entry from a packument's `dist.signatures` (npm serves `sig` base64). */
export interface RegistrySignature {
  keyid: string;
  sig: string;
}

/** A trusted registry signing key. `spkiPem` is a SubjectPublicKeyInfo PEM. */
export interface NpmSigningKey {
  keyid: string;
  spkiPem: string;
  expires: string | null;
}

/** Convert npm's base64 SPKI DER key body to a SPKI PEM for `createPublicKey`. */
function derB64ToSpkiPem(b64: string): string {
  const body = b64.replace(/(.{64})/g, "$1\n");
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`;
}

/**
 * npm's published registry signing keys (`/-/npm/v1/keys`), bundled as a static
 * input. Verified live against the endpoint. Maintained by hand; NOT fetched at
 * audit time (invariant #3). The first key expired 2025-01-29; the second is the
 * current active key (`expires: null`).
 */
export const NPM_SIGNING_KEYS: NpmSigningKey[] = [
  {
    keyid: "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
    spkiPem: derB64ToSpkiPem("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg=="),
    expires: "2025-01-29T00:00:00.000Z",
  },
  {
    keyid: "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U",
    spkiPem: derB64ToSpkiPem("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY6Ya7W++7aUPzvMTrezH6Ycx3c+HOKYCcNGybJZSCJq/fd7Qa8uuAKtdIkUQtQiEKERhAmE5lMMJhP8OkDOa2g=="),
    expires: null,
  },
];

/**
 * Offline-verify the npm registry signature over `${name}@${version}:${integrity}`.
 * ECDSA P-256 / SHA-256 / DER (Node default). Pure: same inputs ⇒ same verdict.
 */
export function verifyRegistrySignature(
  payload: { name: string; version: string; integrity: string },
  signatures: RegistrySignature[] | null | undefined,
  keys: NpmSigningKey[],
): SignatureVerdict {
  if (!signatures || signatures.length === 0) return "unsigned";
  const data = Buffer.from(`${payload.name}@${payload.version}:${payload.integrity}`);
  for (const s of signatures) {
    const key = keys.find((k) => k.keyid === s.keyid);
    if (!key) continue;
    try {
      const ok = verify("sha256", data, createPublicKey(key.spkiPem), Buffer.from(s.sig, "base64"));
      return ok ? "verified" : "invalid";
    } catch {
      return "invalid";
    }
  }
  return "unknown";
}
