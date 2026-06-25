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
  /** Names/scopes served authoritatively by the private registry (ADR-0010). */
  privateNamespaces: string[];
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
  privateNamespaces: [],
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

const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

export function parsePolicy(raw: Buffer): EnterprisePolicy {
  const p = JSON.parse(raw.toString("utf8")) as Partial<EnterprisePolicy>;
  if (p?.schema !== 1 || typeof p.version !== "string" || !p.scoring || typeof p.scoring !== "object") {
    throw new Error("invalid policy: expected schema 1 with a version and scoring block");
  }
  const s = p.scoring as EnterprisePolicy["scoring"];
  if (!s.severityWeight || typeof s.diffMultiplier !== "number" || !s.thresholds || !s.hardBlockSeverity) {
    throw new Error("invalid policy: incomplete scoring block");
  }

  // Validate severityWeight has all five severity keys with numeric values.
  for (const sev of SEVERITIES) {
    const w = (s.severityWeight as Record<string, unknown>)[sev];
    if (typeof w !== "number") {
      throw new Error(`invalid policy: scoring.severityWeight must have a numeric value for "${sev}"`);
    }
  }

  // Validate thresholds.
  if (typeof (s.thresholds as Record<string, unknown>).allow !== "number" ||
      typeof (s.thresholds as Record<string, unknown>).warn !== "number") {
    throw new Error("invalid policy: scoring.thresholds must have numeric allow and warn fields");
  }

  // Validate hardBlockSeverity.
  if (!(SEVERITIES as readonly string[]).includes(s.hardBlockSeverity as string)) {
    throw new Error(`invalid policy: scoring.hardBlockSeverity must be one of ${SEVERITIES.join(", ")} (got "${s.hardBlockSeverity}")`);
  }

  // Validate rules.disabled if present.
  if (p.rules !== undefined) {
    const disabled = (p.rules as Record<string, unknown>).disabled;
    if (disabled !== undefined) {
      if (!Array.isArray(disabled) || !disabled.every((x) => typeof x === "string")) {
        throw new Error("invalid policy: rules.disabled must be an array of strings");
      }
    }
  }

  // Validate allow entries if present.
  if (p.allow !== undefined) {
    if (!Array.isArray(p.allow)) {
      throw new Error("invalid policy: allow must be an array");
    }
    for (let i = 0; i < p.allow.length; i++) {
      const entry = p.allow[i] as Record<string, unknown>;
      if (!entry || typeof entry !== "object") {
        throw new Error(`invalid policy: allow[${i}] must be an object`);
      }
      if (typeof entry.package !== "string") {
        throw new Error(`invalid policy: allow[${i}] must have a string "package" field`);
      }
      if (!Array.isArray(entry.rules) || !(entry.rules as unknown[]).every((r) => typeof r === "string")) {
        throw new Error(`invalid policy: allow[${i}].rules must be an array of strings`);
      }
      if (entry.reason !== undefined && typeof entry.reason !== "string") {
        throw new Error(`invalid policy: allow[${i}].reason must be a string`);
      }
    }
  }

  // Validate deny entries if present.
  if (p.deny !== undefined) {
    if (!Array.isArray(p.deny)) {
      throw new Error("invalid policy: deny must be an array");
    }
    for (let i = 0; i < p.deny.length; i++) {
      const entry = p.deny[i] as Record<string, unknown>;
      if (!entry || typeof entry !== "object") {
        throw new Error(`invalid policy: deny[${i}] must be an object`);
      }
      if (typeof entry.package !== "string") {
        throw new Error(`invalid policy: deny[${i}] must have a string "package" field`);
      }
      if (entry.reason !== undefined && typeof entry.reason !== "string") {
        throw new Error(`invalid policy: deny[${i}].reason must be a string`);
      }
    }
  }

  // Validate privateNamespaces if present.
  if (p.privateNamespaces !== undefined) {
    if (!Array.isArray(p.privateNamespaces) || !p.privateNamespaces.every((x) => typeof x === "string")) {
      throw new Error("invalid policy: privateNamespaces must be an array of strings");
    }
  }

  return {
    schema: 1,
    version: p.version,
    scoring: s,
    rules: { disabled: p.rules?.disabled ?? [] },
    allow: p.allow ?? [],
    deny: p.deny ?? [],
    privateNamespaces: p.privateNamespaces ?? [],
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
