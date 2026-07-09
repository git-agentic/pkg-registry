/**
 * Regenerates a ready-to-paste `KNOWN_VULNERABILITIES` array for
 * `packages/core/src/vuln-corpus.ts` from a LOCAL export of a vulnerability
 * feed — it does NOT fetch anything itself (invariant #3: the audit path is
 * offline; keeping this script's default path offline too means "regenerate
 * the corpus" stays a deliberate, reviewable, out-of-band step, never
 * something that runs at audit time).
 *
 * Source: an OSV (osv.dev) npm-ecosystem export, or the GitHub Advisory
 * Database export, filtered to ordinary version-range vulnerabilities
 * (`ecosystem: "npm"`) — NOT the `type: "malicious"` / `type: "malware"`
 * known-bad-package records that `scripts/make-advisories.ts` /
 * `advisory-corpus.ts` already cover. This script is for real CVEs in
 * otherwise-legitimate packages (a disclosed prototype-pollution bug, an
 * ReDoS, an SSRF, etc.), e.g.:
 *
 *   - OSV: https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
 *     (unzip; each record's `affected[].ranges` gives the vulnerable
 *     semver range(s), `database_specific.severity` or the CVSS vector
 *     gives severity, `affected[].ranges[].events` gives the fixed
 *     version)
 *   - GHSA: `gh api graphql` against the Advisory Database, or the
 *     `github/advisory-database` git export, filtered to
 *     `ecosystem: "npm"` and NOT `type: "malware"`.
 *
 * This script expects the LOCAL export already normalized to a flat JSON
 * array of objects shaped like:
 *
 *   {
 *     "name": "lodash",
 *     "ranges": ["<4.17.12"],
 *     "severity": "critical" | "high" | "medium" | "low" | "info",
 *     "id": "GHSA-jf85-cpcp-j695",
 *     "ecosystem": "npm",
 *     "fixedIn"?: ["4.17.12"],
 *     "reference"?: "https://github.com/advisories/GHSA-jf85-cpcp-j695"
 *   }
 *
 * (If your export has a different shape — e.g. raw OSV JSON with
 * `affected[].ranges[].events` instead of a flat `ranges`/`fixedIn` pair —
 * transform it to the above before running this script, the same way
 * `make-advisories.ts` expects a pre-normalized shape. That keeps the
 * parsing logic here small and honest about what it actually reads, rather
 * than growing bespoke parsers for every upstream feed format.)
 *
 * Usage:
 *
 *   npm run vulns -- --in ./osv-npm-export.json [--out packages/core/src/vuln-corpus.ts]
 *
 * or directly:
 *
 *   tsx scripts/make-vulns.ts --in ./osv-npm-export.json
 *
 * With no `--out`, the generated array is printed to stdout (ready to paste
 * into `KNOWN_VULNERABILITIES` by hand) — the safer default, since this
 * touches source under `packages/core/src`. Pass `--out` only when you want
 * the regenerator to write `vuln-corpus.ts` directly; review the diff
 * before committing either way — this is a security-relevant corpus, and a
 * `severity` field drives real hard-block behavior (a wrong `critical`
 * blocks a legitimate install; a wrong `low` silently under-flags a real
 * CVE).
 */
import { readFileSync, writeFileSync } from "node:fs";

type Severity = "info" | "low" | "medium" | "high" | "critical";
const SEVERITIES = new Set<Severity>(["info", "low", "medium", "high", "critical"]);

interface RawEntry {
  name?: unknown;
  ranges?: unknown;
  severity?: unknown;
  id?: unknown;
  ecosystem?: unknown;
  fixedIn?: unknown;
  reference?: unknown;
}

interface VulnAdvisory {
  name: string;
  ranges: string[];
  severity: Severity;
  id: string;
  fixedIn?: string[];
  reference?: string;
}

function parseArgs(argv: string[]): { in?: string; out?: string } {
  const out: { in?: string; out?: string } = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--in") out.in = argv[++i];
    else if (argv[i] === "--out") out.out = argv[++i];
  }
  return out;
}

/**
 * Pure, total: filters to npm-ecosystem, version-range entries with a
 * recognized severity, and dedupes by (name, id).
 */
export function buildCorpus(raw: unknown): VulnAdvisory[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: VulnAdvisory[] = [];
  for (const e of raw as RawEntry[]) {
    if (!e || typeof e !== "object") continue;
    if (typeof e.ecosystem === "string" && e.ecosystem.toLowerCase() !== "npm") continue;
    if (typeof e.name !== "string" || !e.name) continue;
    if (typeof e.id !== "string" || !e.id) continue;
    if (!Array.isArray(e.ranges) || e.ranges.length === 0 || !e.ranges.every((r) => typeof r === "string")) continue;
    if (typeof e.severity !== "string" || !SEVERITIES.has(e.severity as Severity)) continue;
    const key = `${e.name}@${e.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const adv: VulnAdvisory = { name: e.name, ranges: [...(e.ranges as string[])], severity: e.severity as Severity, id: e.id };
    if (Array.isArray(e.fixedIn) && e.fixedIn.every((f) => typeof f === "string")) adv.fixedIn = [...(e.fixedIn as string[])];
    if (typeof e.reference === "string") adv.reference = e.reference;
    out.push(adv);
  }
  // Stable, readable ordering: by name, then id.
  out.sort((a, b) => (a.name === b.name ? a.id.localeCompare(b.id) : a.name.localeCompare(b.name)));
  return out;
}

function renderArray(vulns: VulnAdvisory[]): string {
  const lines = vulns.map((v) => {
    const parts = [
      `name: ${JSON.stringify(v.name)}`,
      `ranges: ${JSON.stringify(v.ranges)}`,
      `severity: ${JSON.stringify(v.severity)}`,
      `id: ${JSON.stringify(v.id)}`,
    ];
    if (v.fixedIn) parts.push(`fixedIn: ${JSON.stringify(v.fixedIn)}`);
    if (v.reference) parts.push(`reference: ${JSON.stringify(v.reference)}`);
    return `  { ${parts.join(", ")} },`;
  });
  return `export const KNOWN_VULNERABILITIES: readonly VulnAdvisory[] = [\n${lines.join("\n")}\n];\n`;
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  if (!args.in) {
    console.error("Usage: tsx scripts/make-vulns.ts --in <export.json> [--out <file>]");
    console.error("See the header comment in this file for the expected input shape and source pointers.");
    process.exit(1);
  }
  const raw = JSON.parse(readFileSync(args.in, "utf8"));
  const corpus = buildCorpus(raw);
  const rendered = renderArray(corpus);
  console.error(`# ${corpus.length} vulnerabilities after npm-ecosystem filter + (name, id) dedupe`);
  if (args.out) {
    writeFileSync(args.out, rendered);
    console.error(`# wrote ${args.out} — review + paste the array body into vuln-corpus.ts by hand`);
  } else {
    process.stdout.write(rendered);
  }
}

// Entrypoint guard so importing buildCorpus/renderArray for a test never re-runs main().
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  main();
}
