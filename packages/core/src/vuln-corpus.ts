import type { Severity } from "./types.js";

/**
 * Bundled corpus of KNOWN-VULNERABLE npm package version ranges (Phase 22). Curated snapshot
 * (2026-07); a STATIC input — never fetched at audit time (invariant #3). Metadata only
 * (advisory identifiers + semver ranges), never package code. Every entry is a real,
 * publicly-documented npm CVE; verify (id, ranges, severity, fixedIn) against osv.dev /
 * github.com/advisories. Regenerate via `scripts/make-vulns.ts`.
 */
export interface VulnAdvisory {
  name: string;
  ranges: string[]; // affected semver ranges, e.g. "<4.17.12" or ">=7.0.0 <7.4.6"
  severity: Severity; // CVSS-derived, faithful (drives the finding severity)
  id: string; // "GHSA-…" / "CVE-…"
  fixedIn?: string[]; // patched version(s), for remediation
  reference?: string; // advisory URL
}

const SEVERITIES = new Set<Severity>(["info", "low", "medium", "high", "critical"]);

// Well-documented, publicly-confirmed npm CVEs. (name, range, id, severity) fields were
// verified against the GitHub Advisory Database (github.com/advisories) as of the Task 1
// fix wave (see Task 1 report for per-entry verification notes and sources). Kept small,
// accurate, de-duplicated; no entry's `name` collides with a fixture package name (verified
// against fixtures/registry.json).
export const KNOWN_VULNERABILITIES: readonly VulnAdvisory[] = [
  { name: "lodash", ranges: ["<4.17.12"], severity: "critical", id: "GHSA-jf85-cpcp-j695", fixedIn: ["4.17.12"], reference: "https://github.com/advisories/GHSA-jf85-cpcp-j695" },
  { name: "lodash", ranges: ["<4.17.21"], severity: "high", id: "GHSA-35jh-r3h4-6jhm", fixedIn: ["4.17.21"], reference: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm" },
  { name: "minimist", ranges: ["<1.2.6"], severity: "critical", id: "GHSA-xvch-5gv4-984h", fixedIn: ["1.2.6"], reference: "https://github.com/advisories/GHSA-xvch-5gv4-984h" },
  { name: "axios", ranges: ["<0.21.1"], severity: "medium", id: "GHSA-4w2v-q235-vp99", fixedIn: ["0.21.1"], reference: "https://github.com/advisories/GHSA-4w2v-q235-vp99" },
  { name: "node-fetch", ranges: ["<2.6.7"], severity: "high", id: "GHSA-r683-j2x4-v87g", fixedIn: ["2.6.7"], reference: "https://github.com/advisories/GHSA-r683-j2x4-v87g" },
  { name: "ws", ranges: [">=7.0.0 <7.4.6"], severity: "medium", id: "GHSA-6fc8-4gx4-v693", fixedIn: ["7.4.6"], reference: "https://github.com/advisories/GHSA-6fc8-4gx4-v693" },
];

/** name → its known vulnerabilities. Built once over the bundled corpus. */
export function buildVulnIndex(vulns: readonly VulnAdvisory[]): Map<string, VulnAdvisory[]> {
  const m = new Map<string, VulnAdvisory[]>();
  for (const v of vulns) {
    const list = m.get(v.name) ?? [];
    list.push(v);
    m.set(v.name, list);
  }
  return m;
}

/** Coerce one parsed-JSON entry into a VulnAdvisory, or undefined if malformed. Shared by both parsers. */
function coerceVulnEntry(e: unknown): VulnAdvisory | undefined {
  if (
    e && typeof e === "object" &&
    typeof (e as VulnAdvisory).name === "string" &&
    typeof (e as VulnAdvisory).id === "string" &&
    Array.isArray((e as VulnAdvisory).ranges) &&
    (e as VulnAdvisory).ranges.length > 0 &&
    (e as VulnAdvisory).ranges.every((r) => typeof r === "string") &&
    SEVERITIES.has((e as VulnAdvisory).severity)
  ) {
    const v = e as VulnAdvisory;
    const out: VulnAdvisory = { name: v.name, ranges: [...v.ranges], severity: v.severity, id: v.id };
    if (Array.isArray(v.fixedIn) && v.fixedIn.every((f) => typeof f === "string")) out.fixedIn = [...v.fixedIn];
    if (typeof v.reference === "string") out.reference = v.reference;
    return out;
  }
  return undefined;
}

/** Parse an operator-supplied vuln JSON array. Pure, total: drops malformed entries; [] on garbage. */
export function parseVulnAdvisories(raw: string): VulnAdvisory[] {
  let doc: unknown;
  try { doc = JSON.parse(raw); } catch { return []; }
  if (!Array.isArray(doc)) return [];
  const out: VulnAdvisory[] = [];
  for (const e of doc) { const v = coerceVulnEntry(e); if (v) out.push(v); }
  return out;
}

/**
 * Strict variant for the startup fail-closed path: a corrupt (not just unreadable)
 * SENTINEL_VULNERABILITIES file must halt boot, not silently degrade. Throws on non-JSON /
 * non-array; a legit empty array `[]` returns `[]`. Per-entry malformed rows are dropped (non-fatal).
 */
export function parseVulnAdvisoriesStrict(raw: string): VulnAdvisory[] {
  let doc: unknown;
  try { doc = JSON.parse(raw); } catch { throw new Error("SENTINEL_VULNERABILITIES is not valid JSON"); }
  if (!Array.isArray(doc)) throw new Error("SENTINEL_VULNERABILITIES must be a JSON array");
  const out: VulnAdvisory[] = [];
  for (const e of doc) { const v = coerceVulnEntry(e); if (v) out.push(v); }
  return out;
}
