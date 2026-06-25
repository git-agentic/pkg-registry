import { createHash } from "node:crypto";
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
