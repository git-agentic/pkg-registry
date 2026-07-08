/**
 * Bundled corpus of KNOWN-MALICIOUS npm package versions. Curated snapshot (2026-07);
 * a STATIC input — never fetched at audit time (invariant #3). Metadata only (advisory
 * identifiers), never malware code. Entries are publicly-documented incidents; every
 * (name, version, id) triple below was fetched and cross-checked against
 * github.com/advisories at authoring time (see Task 1 report for per-entry notes).
 */
export interface Advisory {
  name: string;
  version: string;
  id: string;                       // advisory id, e.g. "GHSA-…" / "MAL-…"
  severity?: "critical" | "high";   // default critical
  reference?: string;               // advisory URL
}

// Well-documented, publicly-confirmed compromised releases. (name, version) pairs are
// historical fact; ids are real GHSA identifiers for these incidents (verified against
// github.com/advisories at authoring time). Kept small, accurate, and de-duplicated.
export const KNOWN_ADVISORIES: readonly Advisory[] = [
  { name: "event-stream", version: "3.3.6", id: "GHSA-mh6f-8j2x-4483", reference: "https://github.com/advisories/GHSA-mh6f-8j2x-4483" },
  { name: "flatmap-stream", version: "0.1.1", id: "GHSA-9x64-5r7x-2q53", reference: "https://github.com/advisories/GHSA-9x64-5r7x-2q53" },
  { name: "ua-parser-js", version: "0.7.29", id: "GHSA-pjwm-rvh2-c87w", reference: "https://github.com/advisories/GHSA-pjwm-rvh2-c87w" },
  { name: "ua-parser-js", version: "0.8.0", id: "GHSA-pjwm-rvh2-c87w", reference: "https://github.com/advisories/GHSA-pjwm-rvh2-c87w" },
  { name: "ua-parser-js", version: "1.0.0", id: "GHSA-pjwm-rvh2-c87w", reference: "https://github.com/advisories/GHSA-pjwm-rvh2-c87w" },
  { name: "node-ipc", version: "10.1.1", id: "GHSA-97m3-w2cp-4xx6", reference: "https://github.com/advisories/GHSA-97m3-w2cp-4xx6" },
  { name: "coa", version: "2.0.3", id: "GHSA-73qr-pfmq-6rp8", reference: "https://github.com/advisories/GHSA-73qr-pfmq-6rp8" },
  { name: "rc", version: "1.2.9", id: "GHSA-g2q5-5433-rhrf", reference: "https://github.com/advisories/GHSA-g2q5-5433-rhrf" },
];

/** name → its known-bad advisories. Built once over the bundled corpus. */
export function buildAdvisoryIndex(advisories: readonly Advisory[]): Map<string, Advisory[]> {
  const m = new Map<string, Advisory[]>();
  for (const a of advisories) {
    const list = m.get(a.name) ?? [];
    list.push(a);
    m.set(a.name, list);
  }
  return m;
}

/** Parse an operator-supplied advisory JSON array. Pure, total: drops malformed entries; [] on garbage. */
export function parseAdvisories(raw: string): Advisory[] {
  let doc: unknown;
  try { doc = JSON.parse(raw); } catch { return []; }
  if (!Array.isArray(doc)) return [];
  const out: Advisory[] = [];
  for (const e of doc) {
    if (e && typeof e === "object" && typeof (e as Advisory).name === "string" && typeof (e as Advisory).version === "string" && typeof (e as Advisory).id === "string") {
      const a = e as Advisory;
      const adv: Advisory = { name: a.name, version: a.version, id: a.id };
      if (a.severity === "critical" || a.severity === "high") adv.severity = a.severity;
      if (typeof a.reference === "string") adv.reference = a.reference;
      out.push(adv);
    }
  }
  return out;
}
