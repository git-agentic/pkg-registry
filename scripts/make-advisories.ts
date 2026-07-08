/**
 * Regenerates a ready-to-paste `KNOWN_ADVISORIES` array for
 * `packages/core/src/advisory-corpus.ts` from a LOCAL export of a
 * malicious-packages feed — it does NOT fetch anything itself (invariant #3:
 * the audit path is offline; keeping this script's default path offline too
 * means "regenerate the corpus" stays a deliberate, reviewable, out-of-band
 * step, never something that runs at audit time).
 *
 * Source: an OSV (osv.dev) "malicious-packages" export, or the GitHub
 * Advisory Database export, filtered to `type: "malicious"` (OSV) or
 * `type: "malware"` (GHSA) entries. Both publish npm-ecosystem exports you
 * can download ahead of time, e.g.:
 *
 *   - OSV: https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
 *     (unzip, the malicious-package entries have `"database_specific":
 *     {"malicious_packages_origins": [...] }` or an id prefixed `MAL-`)
 *   - GHSA: `gh api graphql` against the Advisory Database, or the
 *     `github/advisory-database` git export, filtered to
 *     `type: "malware"` + `ecosystem: "npm"`.
 *
 * This script expects the LOCAL export already normalized to a flat JSON
 * array of objects shaped like:
 *
 *   { "name": "event-stream", "version": "3.3.6", "id": "GHSA-...", "ecosystem": "npm", "severity"?: "critical"|"high", "reference"?: "https://..." }
 *
 * (If your export has a different shape, transform it to the above before
 * running this script — that keeps the parsing logic here small and honest
 * about what it actually reads, rather than growing bespoke parsers for
 * every upstream format.)
 *
 * Usage:
 *
 *   npm run advisories -- --in ./osv-export.json [--out packages/core/src/advisory-corpus.ts]
 *
 * or directly:
 *
 *   tsx scripts/make-advisories.ts --in ./osv-export.json
 *
 * With no `--out`, the generated array is printed to stdout (ready to paste
 * into `KNOWN_ADVISORIES` by hand) — the safer default, since this touches
 * source under `packages/core/src`. Pass `--out` only when you want the
 * regenerator to write `advisory-corpus.ts` directly; review the diff before
 * committing either way (this is a security-relevant corpus — a bad entry
 * either hard-blocks a legitimate release or silently drops real coverage).
 */
import { readFileSync, writeFileSync } from "node:fs";

interface RawEntry {
  name?: unknown;
  version?: unknown;
  id?: unknown;
  ecosystem?: unknown;
  severity?: unknown;
  reference?: unknown;
}

interface Advisory {
  name: string;
  version: string;
  id: string;
  severity?: "critical" | "high";
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

/** Pure, total: filters to npm + specific-version entries, dedupes by (name, version). */
export function buildCorpus(raw: unknown): Advisory[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: Advisory[] = [];
  for (const e of raw as RawEntry[]) {
    if (!e || typeof e !== "object") continue;
    if (typeof e.ecosystem === "string" && e.ecosystem.toLowerCase() !== "npm") continue;
    if (typeof e.name !== "string" || !e.name) continue;
    if (typeof e.version !== "string" || !e.version) continue;
    if (typeof e.id !== "string" || !e.id) continue;
    const key = `${e.name}@${e.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const adv: Advisory = { name: e.name, version: e.version, id: e.id };
    if (e.severity === "critical" || e.severity === "high") adv.severity = e.severity;
    if (typeof e.reference === "string") adv.reference = e.reference;
    out.push(adv);
  }
  // Stable, readable ordering: by name, then version.
  out.sort((a, b) => (a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name)));
  return out;
}

function renderArray(advisories: Advisory[]): string {
  const lines = advisories.map((a) => {
    const parts = [`name: ${JSON.stringify(a.name)}`, `version: ${JSON.stringify(a.version)}`, `id: ${JSON.stringify(a.id)}`];
    if (a.severity) parts.push(`severity: ${JSON.stringify(a.severity)}`);
    if (a.reference) parts.push(`reference: ${JSON.stringify(a.reference)}`);
    return `  { ${parts.join(", ")} },`;
  });
  return `export const KNOWN_ADVISORIES: readonly Advisory[] = [\n${lines.join("\n")}\n];\n`;
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  if (!args.in) {
    console.error("Usage: tsx scripts/make-advisories.ts --in <export.json> [--out <file>]");
    console.error("See the header comment in this file for the expected input shape and source pointers.");
    process.exit(1);
  }
  const raw = JSON.parse(readFileSync(args.in, "utf8"));
  const corpus = buildCorpus(raw);
  const rendered = renderArray(corpus);
  console.error(`# ${corpus.length} advisories after npm-ecosystem filter + (name, version) dedupe`);
  if (args.out) {
    writeFileSync(args.out, rendered);
    console.error(`# wrote ${args.out} — review + paste the array body into advisory-corpus.ts by hand`);
  } else {
    process.stdout.write(rendered);
  }
}

// Entrypoint guard so importing buildCorpus/renderArray for a test never re-runs main().
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  main();
}
