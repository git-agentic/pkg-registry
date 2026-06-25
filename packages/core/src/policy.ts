import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import type { Severity } from "./types.js";

export interface EnterprisePolicy {
  schema: 1;
  /** Free-form version string recorded on every verdict. */
  version: string;
  scoring: {
    severityWeight: Record<Severity, number>;
    diffMultiplier: number;
    thresholds: { allow: number; warn: number };
    hardBlockSeverity: Severity;
  };
  rules: { disabled: string[] };
  allow: { package: string; rules: string[]; reason?: string }[];
  deny: { package: string; reason?: string }[];
}

/** Compiled-in default. Equals the historical POLICY so out-of-the-box behavior is unchanged. */
export const DEFAULT_POLICY: EnterprisePolicy = {
  schema: 1,
  version: "default",
  scoring: {
    severityWeight: { info: 0, low: 4, medium: 12, high: 25, critical: 55 },
    diffMultiplier: 1.6,
    thresholds: { allow: 80, warn: 50 },
    hardBlockSeverity: "critical",
  },
  rules: { disabled: [] },
  allow: [],
  deny: [],
};

/** Stable hash of a policy OBJECT (used for the in-code default; external policies hash raw bytes). */
export function policyHashOf(policy: EnterprisePolicy): string {
  return "sha256-" + createHash("sha256").update(canonicalJSON(policy)).digest("hex");
}

function canonicalJSON(v: unknown): string {
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  if (v && typeof v === "object") {
    return "{" + Object.keys(v as object).sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalJSON((v as Record<string, unknown>)[k]))
      .join(",") + "}";
  }
  return JSON.stringify(v);
}

/** Anchored full-name glob: `*` is the only metacharacter; everything else is literal. */
export function matchPackage(pattern: string, name: string): boolean {
  const re = new RegExp("^" + pattern.split("*").map(escapeRe).join(".*") + "$");
  return re.test(name);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function policyHashOfBytes(raw: Buffer): string {
  return "sha256-" + createHash("sha256").update(raw).digest("hex");
}

export function generateKeypair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

export function signPolicy(raw: Buffer, privateKeyPem: string): string {
  // Ed25519: algorithm is null in node:crypto.
  return edSign(null, raw, createPrivateKey(privateKeyPem)).toString("base64");
}

export function verifyPolicyBytes(raw: Buffer, sigB64: string, publicKeyPem: string): boolean {
  try {
    return edVerify(null, raw, createPublicKey(publicKeyPem), Buffer.from(sigB64, "base64"));
  } catch {
    return false;
  }
}

export function parsePolicy(raw: Buffer): EnterprisePolicy {
  const p = JSON.parse(raw.toString("utf8")) as Partial<EnterprisePolicy>;
  if (p?.schema !== 1 || typeof p.version !== "string" || !p.scoring || typeof p.scoring !== "object") {
    throw new Error("invalid policy: expected schema 1 with a version and scoring block");
  }
  const s = p.scoring as EnterprisePolicy["scoring"];
  if (!s.severityWeight || typeof s.diffMultiplier !== "number" || !s.thresholds || !s.hardBlockSeverity) {
    throw new Error("invalid policy: incomplete scoring block");
  }
  return {
    schema: 1,
    version: p.version,
    scoring: s,
    rules: { disabled: p.rules?.disabled ?? [] },
    allow: p.allow ?? [],
    deny: p.deny ?? [],
  };
}

export function loadPolicy(opts: { file: string; sig: string; publicKeyPem: string }): {
  policy: EnterprisePolicy;
  hash: string;
} {
  const raw = readFileSync(opts.file);
  const sigB64 = readFileSync(opts.sig, "utf8").trim();
  if (!verifyPolicyBytes(raw, sigB64, opts.publicKeyPem)) {
    throw new Error(`policy signature verification failed for ${opts.file}`);
  }
  return { policy: parsePolicy(raw), hash: policyHashOfBytes(raw) };
}
