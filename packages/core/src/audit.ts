import { Buffer } from "node:buffer";
import { baselineFrom, extractTarball, integrityOf } from "./extract.js";
import { extractCapabilities, diffCapabilities } from "./capabilities.js";
import { RULES } from "./rules/index.js";
import { capabilityNoveltyFindings } from "./rules/capability-novelty.js";
import { score } from "./score.js";
import { DEFAULT_POLICY } from "./policy.js";
import { verifyRegistrySignature, NPM_SIGNING_KEYS, type RegistrySignature, type NpmSigningKey } from "./signature.js";
import { verifyProvenance, loadDefaultTrustMaterial, type ProvenanceTrustMaterial } from "./provenance.js";
import type {
  Audit,
  AuditInput,
  AuditReport,
  Capability,
  ExtractionObservations,
  Finding,
  PackageFile,
  PackageMeta,
  ReleaseContext,
} from "./types.js";
import type { Advisory } from "./advisory-corpus.js";
import type { VulnAdvisory } from "./vuln-corpus.js";

export const ENGINE_VERSION = "0.1.0-alpha.2";

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

/** Assemble the policy-independent {@link Audit} from metadata + extracted files. */
export function buildAudit(
  meta: PackageMeta,
  files: PackageFile[],
  opts: {
    mode: "full" | "diff";
    durationMs: number;
    baselineCapabilities?: Capability[];
    releaseContext?: ReleaseContext;
    advisories?: Advisory[];
    vulnerabilities?: VulnAdvisory[];
    extractionObservations?: ExtractionObservations;
  } = { mode: "full", durationMs: 0 },
): Audit {
  const input: AuditInput = { meta, files, mode: opts.mode, releaseContext: opts.releaseContext, advisories: opts.advisories, vulnerabilities: opts.vulnerabilities, extractionObservations: opts.extractionObservations };
  const ruleFindings = runRules(input);
  const capabilities = extractCapabilities(input);
  const capabilityDelta = opts.baselineCapabilities
    ? diffCapabilities(capabilities, opts.baselineCapabilities)
    : null;
  const findings = [...ruleFindings, ...capabilityNoveltyFindings(capabilityDelta, opts.releaseContext)];
  return {
    schema: 3,
    meta,
    findings,
    capabilities,
    capabilityDelta,
    engine: { version: ENGINE_VERSION, rules: RULES.map((r) => r.id), mode: opts.mode },
    auditedAt: new Date().toISOString(),
    durationMs: opts.durationMs,
  };
}

export interface AuditTarballInput {
  /** Registry metadata for the version being audited (from the packument). */
  meta: Omit<PackageMeta, "integrity" | "unpackedSize" | "fileCount" | "signature" | "provenance"> & {
    integrity?: string | null;
  };
  tarball: Buffer;
  /** Previous version's tarball, to enable diff-mode weighting. */
  baselineTarball?: Buffer;
  /** Raw `dist.signatures` from the packument (base64 sigs), verified offline. */
  signatures?: RegistrySignature[] | null;
  /** Whether the packument declared `dist.attestations`. */
  hasProvenance?: boolean;
  /** Trusted signing keys (default: bundled npm keys). Never fetched at audit time. */
  signingKeys?: NpmSigningKey[];
  /** Fetched attestation-endpoint response (acquisition path), or null when unfetchable. */
  attestations?: unknown | null;
  /** Pinned Sigstore trust material. undefined ⇒ bundled default; null ⇒ none (provenance stays unknown when claimed). */
  trustMaterial?: ProvenanceTrustMaterial | null;
  /** Injectable clock (ISO) for trust-root staleness; defaults to now. */
  verifyAt?: string;
  releaseContext?: ReleaseContext;
  /** Operator-supplied known-malicious advisories, merged with the bundled corpus (Phase 21). */
  advisories?: Advisory[];
  /** Operator-supplied known vulnerabilities, merged with the bundled corpus (Phase 22). */
  vulnerabilities?: VulnAdvisory[];
  /** Decompression-bomb caps for extraction (ADR-0039). Undefined ⇒ core defaults. */
  extractLimits?: { maxUnpackedBytes?: number; maxFileCount?: number };
  /** Publish-only strictness: require a parseable npm manifest matching this coordinate. */
  requirePackageManifest?: { name: string; version: string };
}

/** Extract + diff + run rules + capabilities → policy-independent {@link Audit}. */
export async function runAudit(input: AuditTarballInput): Promise<Audit> {
  const started = Date.now();
  const mode: "full" | "diff" = input.baselineTarball ? "diff" : "full";

  const limits = input.extractLimits;
  let baseline: Map<string, string> | undefined;
  let baselineCapabilities: Capability[] | undefined;
  if (input.baselineTarball) {
    const prev = await extractTarball(input.baselineTarball, undefined, limits);
    baseline = baselineFrom(prev.files);
    baselineCapabilities = extractCapabilities({ meta: input.meta as PackageMeta, files: prev.files, mode: "diff" });
  }

  const extracted = await extractTarball(input.tarball, baseline, limits);
  // A cap breach is already a deterministic critical resource-abuse result; do
  // not replace that complete report with a secondary "missing manifest" parse
  // error caused by the intentionally-truncated extraction.
  if (input.requirePackageManifest && !extracted.truncated) {
    if (extracted.packageManifestEntryCount > 1) {
      throw new Error("malformed npm tarball: duplicate package/package.json entries");
    }
    const file = extracted.files.find((f) => f.path === "package/package.json");
    if (!file) throw new Error("malformed npm tarball: missing readable package/package.json");
    let manifest: { name?: unknown; version?: unknown };
    try { manifest = JSON.parse(file.content) as { name?: unknown; version?: unknown }; }
    catch { throw new Error("malformed npm tarball: package/package.json is not valid JSON"); }
    if (typeof manifest.name !== "string" || typeof manifest.version !== "string") {
      throw new Error("malformed npm tarball: package/package.json requires string name and version");
    }
    if (manifest.name !== input.requirePackageManifest.name || manifest.version !== input.requirePackageManifest.version) {
      throw new Error(
        `malformed npm tarball: package/package.json identity ${manifest.name}@${manifest.version} does not match publish target ${input.requirePackageManifest.name}@${input.requirePackageManifest.version}`,
      );
    }
  }
  // Always recompute from the served bytes (ADR-0022): the claimed integrity is
  // an assertion to CHECK, not a value to trust. Mismatch ⇒ critical finding.
  const actualIntegrity = integrityOf(input.tarball);
  const claimedIntegrity = input.meta.integrity ?? null;
  const integrityMismatch = claimedIntegrity !== null && claimedIntegrity !== actualIntegrity;
  // The registry signature is over the CLAIMED integrity (npm's statement about
  // its own dist entry); byte-tampering is carried by integrity-mismatch instead.
  const signature = verifyRegistrySignature(
    { name: input.meta.name, version: input.meta.version, integrity: claimedIntegrity ?? actualIntegrity },
    input.signatures ?? null,
    input.signingKeys ?? NPM_SIGNING_KEYS,
  );
  const prov = verifyProvenance({
    name: input.meta.name,
    version: input.meta.version,
    integrity: actualIntegrity,
    claimed: input.hasProvenance ?? false,
    attestations: input.attestations ?? null,
    trust: input.trustMaterial === undefined ? loadDefaultTrustMaterial() : input.trustMaterial,
    now: input.verifyAt,
  });
  const meta: PackageMeta = {
    ...input.meta,
    integrity: actualIntegrity,
    unpackedSize: extracted.unpackedSize,
    fileCount: extracted.fileCount,
    hasInstallScripts: detectInstallScripts(extracted.files) || input.meta.hasInstallScripts,
    signature,
    provenance: prov.status,
    provenanceIdentity: prov.identity,
  };

  const extractionObservations = {
    contentMismatch: extracted.contentMismatch,
    contentMismatchTotals: extracted.contentMismatchTotals,
    unscannedTotals: extracted.unscannedTotals,
  };
  const audit = buildAudit(meta, extracted.files, { mode, durationMs: Date.now() - started, baselineCapabilities, releaseContext: input.releaseContext, advisories: input.advisories, vulnerabilities: input.vulnerabilities, extractionObservations });
  if (integrityMismatch) {
    audit.findings.push({
      ruleId: "integrity-mismatch", category: "provenance", severity: "critical",
      message: `served tarball bytes do not match the claimed dist.integrity (${claimedIntegrity!.slice(0, 24)}…) — possible mirror tampering`,
      onChangedFile: false, evidence: [],
    });
  }
  if (extracted.truncated) {
    audit.findings.push({
      ruleId: "resource-abuse", category: "resource", severity: "critical",
      message: "tarball exceeded extraction limits (unpacked size or file count) — possible decompression bomb; audit truncated",
      onChangedFile: false, evidence: [],
    });
  }
  if (extracted.unscannedTotals.count > 0) {
    const { count, native: nativeCount, bytes: totalBytes } = extracted.unscannedTotals;
    const mb = (totalBytes / (1024 * 1024)).toFixed(1);
    // Use the combined install-script signal (packument OR scanned package.json),
    // not a re-derived detectInstallScripts(extracted.files) — a package whose
    // signal only comes from the packument (package.json wasn't scanned) must
    // still escalate (#11 review fix).
    const escalate = nativeCount > 0 && meta.hasInstallScripts;
    audit.findings.push({
      ruleId: "unscanned-content", category: "metadata",
      severity: escalate ? "medium" : "low",
      message: escalate
        ? `${count} executable-looking file(s) (${mb} MB) were not scanned, including ${nativeCount} native/binary, and the package runs install scripts`
        : `${count} executable-looking file(s) (${mb} MB) were not scanned (${nativeCount} native, ${count - nativeCount} large-code)`,
      onChangedFile: false, evidence: [],
    });
  }
  if (extracted.contentMismatchTotals.count > 0) {
    const EXEC = new Set(["elf", "macho", "pe", "wasm"]);
    const kinds = Object.keys(extracted.contentMismatchTotals.byKind);
    const anyExec = kinds.some((k) => EXEC.has(k));
    const sample = extracted.contentMismatch.slice(0, 3).map((e) => ({ file: e.path, snippet: `${e.detectedKind} bytes behind ${e.declaredExt}` }));
    audit.findings.push({
      ruleId: "content-mismatch", category: "metadata",
      severity: anyExec ? "medium" : "low",
      message: `${extracted.contentMismatchTotals.count} file(s) have binary/compressed content behind a text-looking extension (${kinds.join(", ")}) — possible concealed payload container`,
      onChangedFile: false, evidence: sample,
    });
  }
  if (prov.rootStale) {
    audit.findings.push({
      ruleId: "trust-root-stale", category: "provenance", severity: "info",
      message: "pinned Sigstore trust root is past its validity window — update packages/core/trust/trusted-root.json",
      onChangedFile: false, evidence: [],
    });
  }
  return audit;
}

/**
 * End-to-end audit scored under the built-in {@link DEFAULT_POLICY}. The proxy
 * does NOT use this (it scores under the loaded enterprise policy); it is for the
 * offline CLI `scan` and for tests, and reproduces today's numbers exactly.
 */
export async function auditTarball(input: AuditTarballInput): Promise<AuditReport> {
  return score(await runAudit(input), DEFAULT_POLICY);
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
