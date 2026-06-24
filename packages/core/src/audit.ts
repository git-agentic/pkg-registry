import { Buffer } from "node:buffer";
import { baselineFrom, extractTarball, integrityOf } from "./extract.js";
import { extractCapabilities, diffCapabilities } from "./capabilities.js";
import { RULES } from "./rules/index.js";
import { scoreFindings, verdictFor } from "./score.js";
import type {
  AuditInput,
  AuditReport,
  Capability,
  Finding,
  PackageFile,
  PackageMeta,
} from "./types.js";

export const ENGINE_VERSION = "0.1.0";

/** Run the heuristic rule pipeline over an already-extracted package. */
export function runRules(input: AuditInput): Finding[] {
  return RULES.flatMap((rule) => {
    try {
      return rule.run(input);
    } catch {
      // A rule must never crash the audit; fail open for that rule only.
      return [];
    }
  });
}

/** Assemble a full {@link AuditReport} from metadata + extracted files. */
export function buildReport(
  meta: PackageMeta,
  files: PackageFile[],
  opts: {
    mode: "full" | "diff";
    durationMs: number;
    llmSummary?: string | null;
    baselineCapabilities?: Capability[];
  } = { mode: "full", durationMs: 0 },
): AuditReport {
  const input: AuditInput = { meta, files, mode: opts.mode };
  const findings = runRules(input);
  const score = scoreFindings(findings);
  const verdict = verdictFor(score, findings);
  const capabilities = extractCapabilities(input);
  const capabilityDelta = opts.baselineCapabilities
    ? diffCapabilities(capabilities, opts.baselineCapabilities)
    : null;
  return {
    schema: 2,
    meta,
    score,
    verdict,
    findings: findings.sort((a, b) => b.weight - a.weight),
    capabilities,
    capabilityDelta,
    engine: {
      version: ENGINE_VERSION,
      rules: RULES.map((r) => r.id),
      llm: null,
      mode: opts.mode,
    },
    llmSummary: opts.llmSummary ?? null,
    auditedAt: new Date().toISOString(),
    durationMs: opts.durationMs,
  };
}

export interface AuditTarballInput {
  /** Registry metadata for the version being audited (from the packument). */
  meta: Omit<PackageMeta, "integrity" | "unpackedSize" | "fileCount"> & {
    integrity?: string | null;
  };
  tarball: Buffer;
  /** Previous version's tarball, to enable diff-mode weighting. */
  baselineTarball?: Buffer;
}

/**
 * End-to-end audit of a tarball: extract, (optionally) diff against the previous
 * version, run rules, and score. This is the function the proxy and CLI call.
 */
export async function auditTarball(input: AuditTarballInput): Promise<AuditReport> {
  const started = Date.now();
  const mode: "full" | "diff" = input.baselineTarball ? "diff" : "full";

  let baseline: Map<string, string> | undefined;
  let baselineCapabilities: Capability[] | undefined;
  if (input.baselineTarball) {
    const prev = await extractTarball(input.baselineTarball);
    baseline = baselineFrom(prev.files);
    baselineCapabilities = extractCapabilities({ meta: input.meta as PackageMeta, files: prev.files, mode: "diff" });
  }

  const extracted = await extractTarball(input.tarball, baseline);
  const meta: PackageMeta = {
    ...input.meta,
    integrity: input.meta.integrity ?? integrityOf(input.tarball),
    unpackedSize: extracted.unpackedSize,
    fileCount: extracted.fileCount,
    hasInstallScripts: detectInstallScripts(extracted.files) || input.meta.hasInstallScripts,
  };

  return buildReport(meta, extracted.files, {
    mode,
    durationMs: Date.now() - started,
    baselineCapabilities,
  });
}

function detectInstallScripts(files: PackageFile[]): boolean {
  const pkg = files.find((f) => f.path === "package/package.json");
  if (!pkg) return false;
  try {
    const scripts = JSON.parse(pkg.content)?.scripts ?? {};
    return ["preinstall", "install", "postinstall"].some((h) => Boolean(scripts[h]));
  } catch {
    return false;
  }
}
