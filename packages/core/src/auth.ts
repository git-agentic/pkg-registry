import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";

export type Role = "operator" | "agent" | "publisher";
const ROLES: readonly Role[] = ["operator", "agent", "publisher"];

export interface TokenPayload {
  role: Role;
  sub: string;
  iat: number; // unix seconds
  exp: number; // unix seconds
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Mint a signed role token: base64url(payload).base64url(ed25519 sig over the payload segment). */
export function signToken(
  input: { role: Role; sub: string; ttlSeconds: number },
  privateKeyPem: string,
  now: number = nowSeconds(),
): string {
  const payload: TokenPayload = { role: input.role, sub: input.sub, iat: now, exp: now + input.ttlSeconds };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = edSign(null, Buffer.from(payloadB64), createPrivateKey(privateKeyPem)).toString("base64url");
  return `${payloadB64}.${sig}`;
}

/**
 * Verify a role token offline against a public key. Pure/total: never throws.
 * Order: signature (a tampered payload ⇒ bad-signature) → parse → role → expiry.
 */
export function verifyToken(
  token: string,
  publicKeyPem: string,
  now: number = nowSeconds(),
): { ok: true; role: Role; sub: string; exp: number } | { ok: false; reason: "malformed" | "bad-signature" | "expired" | "bad-role" } {
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return { ok: false, reason: "malformed" };
  const [payloadB64, sigB64] = parts;
  let okSig = false;
  try {
    okSig = edVerify(null, Buffer.from(payloadB64), createPublicKey(publicKeyPem), Buffer.from(sigB64, "base64url"));
  } catch {
    return { ok: false, reason: "bad-signature" };
  }
  if (!okSig) return { ok: false, reason: "bad-signature" };
  let payload: TokenPayload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as TokenPayload;
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return { ok: false, reason: "malformed" };
  }
  if (!ROLES.includes(payload.role)) return { ok: false, reason: "bad-role" };
  if (typeof payload.exp !== "number" || now >= payload.exp) return { ok: false, reason: "expired" };
  return { ok: true, role: payload.role, sub: String(payload.sub ?? ""), exp: payload.exp };
}
