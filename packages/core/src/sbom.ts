import { ENGINE_VERSION } from "./audit.js";
import type { TreeAuditResult } from "./tree.js";

export interface CycloneDXComponent {
  type: "library";
  name: string;
  version: string;
  purl: string;
  properties: { name: string; value: string }[];
}

export interface CycloneDXBom {
  bomFormat: "CycloneDX";
  specVersion: "1.6";
  version: number;
  metadata: { timestamp: string; tools: { vendor: string; name: string; version: string }[] };
  components: CycloneDXComponent[];
}

/** purl for an npm package: scoped `@scope/name` → `pkg:npm/%40scope/name@version`. */
function npmPurl(name: string, version: string): string {
  const encoded = name.startsWith("@") ? "%40" + name.slice(1) : name;
  return `pkg:npm/${encoded}@${version}`;
}

/**
 * Project an audited dependency tree into a CycloneDX 1.6 JSON BOM. Pure: the only
 * time input is the injected `now` (deterministic/testable). Each package becomes a
 * `library` component carrying Sentinel's verdict/score/top-finding as `sentinel:*`
 * properties.
 */
export function toCycloneDX(tree: TreeAuditResult, opts: { now: string }): CycloneDXBom {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    metadata: {
      timestamp: opts.now,
      tools: [{ vendor: "Sentinel", name: "sentinel", version: ENGINE_VERSION }],
    },
    components: tree.packages.map((p) => {
      const properties = [
        { name: "sentinel:verdict", value: p.status },
        { name: "sentinel:score", value: p.score === null ? "n/a" : String(p.score) },
      ];
      if (p.topFinding) properties.push({ name: "sentinel:topFinding", value: p.topFinding });
      if (p.integrityMismatch) properties.push({ name: "sentinel:integrityMismatch", value: "true" });
      return { type: "library" as const, name: p.name, version: p.version, purl: npmPurl(p.name, p.version), properties };
    }),
  };
}
