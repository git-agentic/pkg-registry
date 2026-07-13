import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";

export type RetractionReason = "security" | "withdrawn" | "broken" | "legal";

export interface RetractionAdvisory {
  kind: "retraction";
  id: string;
  name: string;
  version: string;
  integrity: string;
  reason: RetractionReason;
  retractedAt: string;
  severity: "high" | "medium";
}

export interface RetractionCorpus {
  schema: 1;
  version: string;
  issuedAt: string;
  advisories: RetractionAdvisory[];
}

export interface RetractionCorpusIdentity { version: string; hash: string; }
export interface LoadedRetractionCorpus { corpus: RetractionCorpus; hash: string; }

export const EMPTY_RETRACTION_CORPUS: RetractionCorpus = {
  schema: 1, version: "empty", issuedAt: "1970-01-01T00:00:00.000Z", advisories: [],
};

function canonicalInstant(value: unknown, path: string): string {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new Error(`invalid retraction corpus: ${path} must be a canonical ISO timestamp`);
  }
  return value;
}

function nonempty(value: unknown, path: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`invalid retraction corpus: ${path} must be a non-empty string`);
  return value;
}

export function parseRetractionCorpus(raw: Buffer): RetractionCorpus {
  let decoded: unknown;
  try { decoded = JSON.parse(raw.toString("utf8")); }
  catch { throw new Error("invalid retraction corpus: expected JSON"); }
  const input = decoded as Record<string, unknown>;
  if (input?.schema !== 1 || !Array.isArray(input.advisories)) {
    throw new Error("invalid retraction corpus: expected schema 1 with advisories array");
  }
  const version = nonempty(input.version, "version");
  const issuedAt = canonicalInstant(input.issuedAt, "issuedAt");
  const ids = new Set<string>();
  const coordinates = new Set<string>();
  const reasons: RetractionReason[] = ["security", "withdrawn", "broken", "legal"];
  const advisories = input.advisories.map((candidate, index): RetractionAdvisory => {
    if (!candidate || typeof candidate !== "object") throw new Error(`invalid retraction corpus: advisories[${index}] must be an object`);
    const value = candidate as Record<string, unknown>;
    if (value.kind !== "retraction") throw new Error(`invalid retraction corpus: advisories[${index}].kind must be retraction`);
    const id = nonempty(value.id, `advisories[${index}].id`);
    const name = nonempty(value.name, `advisories[${index}].name`);
    const packageVersion = nonempty(value.version, `advisories[${index}].version`);
    const integrity = nonempty(value.integrity, `advisories[${index}].integrity`);
    if (!/^sha(?:1|256|512)-[A-Za-z0-9+/]+={0,2}$/.test(integrity)) {
      throw new Error(`invalid retraction corpus: advisories[${index}].integrity must be SRI`);
    }
    if (!reasons.includes(value.reason as RetractionReason)) throw new Error(`invalid retraction corpus: advisories[${index}].reason is invalid`);
    const reason = value.reason as RetractionReason;
    const severity = reason === "security" ? "high" : "medium";
    if (value.severity !== severity) throw new Error(`invalid retraction corpus: advisories[${index}].severity must be ${severity} for ${reason}`);
    const retractedAt = canonicalInstant(value.retractedAt, `advisories[${index}].retractedAt`);
    if (Date.parse(retractedAt) > Date.parse(issuedAt)) throw new Error(`invalid retraction corpus: advisories[${index}] cannot postdate issuance`);
    const coordinate = `${name}\u0000${packageVersion}`;
    if (ids.has(id) || coordinates.has(coordinate)) throw new Error("invalid retraction corpus: duplicate advisory id or package coordinate");
    ids.add(id); coordinates.add(coordinate);
    return { kind: "retraction", id, name, version: packageVersion, integrity, reason, retractedAt, severity };
  });
  return { schema: 1, version, issuedAt, advisories };
}

export function retractionCorpusHashOfBytes(raw: Buffer): string {
  return `sha256-${createHash("sha256").update(raw).digest("hex")}`;
}

export function signRetractionCorpus(raw: Buffer, privateKeyPem: string): string {
  return sign(null, raw, createPrivateKey(privateKeyPem)).toString("base64");
}

export function verifyRetractionCorpusBytes(raw: Buffer, signature: string, publicKeyPem: string): boolean {
  try { return verify(null, raw, createPublicKey(publicKeyPem), Buffer.from(signature, "base64")); }
  catch { return false; }
}

export function loadRetractionCorpus(opts: { file: string; sig: string; publicKeyPem: string }): LoadedRetractionCorpus {
  const raw = readFileSync(opts.file);
  const signature = readFileSync(opts.sig, "utf8").trim();
  if (!verifyRetractionCorpusBytes(raw, signature, opts.publicKeyPem)) throw new Error("retraction corpus signature verification failed");
  return { corpus: parseRetractionCorpus(raw), hash: retractionCorpusHashOfBytes(raw) };
}
