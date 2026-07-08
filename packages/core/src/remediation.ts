import type { AuditReport, Category, Finding, Severity } from "./types.js";

export interface RemediationItem { ruleId: string; severity: Severity; summary: string; action: string; }
export interface WaiverTemplate {
  name: string;
  version: string;
  integrity: string | null;
  approveCommand: string;
  requestPayload: { name: string; version: string; integrity: string | null; reason: string };
}
export interface Remediation { items: RemediationItem[]; waiver: WaiverTemplate | null; guidance: string; }

interface Guide { summary: string; action: string; }

/** Per-ruleId remediation guidance. Authored here (not in the rules) so rules stay pure. */
const REMEDIATIONS: Record<string, Guide> = {
  "install-scripts": { summary: "Runs install-time lifecycle scripts.", action: "Review the scripts; approve the capability manifest (`sentinel approve …`) if they're required, otherwise prefer a script-free alternative." },
  "secret-exfil": { summary: "Reads credentials/tokens and may exfiltrate them.", action: "Do not install until reviewed. If this is a false positive, waive with a recorded rationale; otherwise remove the dependency." },
  "network-egress": { summary: "Makes network connections.", action: "Confirm the egress is expected for this package's purpose; if not, remove it or pin to a version without it." },
  "obfuscation": { summary: "Contains obfuscated/minified-beyond-normal code.", action: "Inspect the source; obfuscation in a dependency is a red flag — prefer a readable, well-known alternative." },
  "provenance": { summary: "Missing or unverifiable build provenance.", action: "Request an exception, or choose a package that publishes SLSA build provenance (`dist.attestations`)." },
  "provenance-identity": { summary: "Provenance identity does not match the required repo/workflow/builder.", action: "Verify the release's build identity; if the mismatch is unexpected, do not install and report it." },
  "typosquat": { summary: "Name resembles a popular package.", action: "Confirm you meant this exact package name — check for a one-character typo against the intended dependency." },
  "dependency-confusion": { summary: "Public name look-alike of a claimed private namespace.", action: "Confirm this is the intended public package, not an attacker shadowing your internal name; if internal, install from the private registry." },
  "release-anomaly": { summary: "This release differs from the package's own history (maintainer change, dormancy, or a new first-version capability).", action: "Confirm the change is legitimate; if the ownership/behavior change is unexpected, pin to a known-good earlier version (run `sentinel explain` for a suggestion)." },
  "capability-novelty": { summary: "Adds a dangerous capability the prior version did not have.", action: "Review why this version newly needs network/process access; if unexpected, pin to the prior version." },
  "integrity-mismatch": { summary: "The lockfile's pinned hash differs from what the registry serves.", action: "Regenerate the lockfile from a trusted source, or investigate possible tampering/registry compromise." },
  "known-advisory": { summary: "Listed as known-malicious in a security advisory.", action: "This exact version is publicly documented as malicious — remove it and pin to a version published BEFORE the compromise (or a patched later release); do not waive." },
};

// NOTE: the project's `Category` union (packages/core/src/types.ts) is
// obfuscation | network | secret-exfil | install-script | metadata | provenance
// — there is no "capability" category. Fallback keys below use the real values.
const CATEGORY_FALLBACK: Partial<Record<Category, Guide>> = {
  "install-script": { summary: "Requests a sensitive install-time capability.", action: "Review the capability; approve it via the manifest if required, else avoid the package." },
  metadata: { summary: "A supply-chain metadata signal.", action: "Review the finding; confirm the package's identity and provenance before installing." },
};

const GENERIC: Guide = { summary: "A security finding was flagged.", action: "Review the finding details; approve with a recorded rationale only if you understand and accept the risk." };

function guideFor(ruleId: string, category: Category): Guide {
  return REMEDIATIONS[ruleId] ?? CATEGORY_FALLBACK[category] ?? GENERIC;
}

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Short action string for a ruleId — used by compact surfaces (the PR comment). */
export function remediationHint(ruleId: string): string {
  return (REMEDIATIONS[ruleId] ?? GENERIC).action;
}

/**
 * Advisory remediation for an audited package: per-finding `{ summary, action }` guidance ordered
 * worst-first, plus a waiver / approval-request template when the verdict is warn/block. Pure,
 * deterministic, total (unknown ruleId → generic). Never feeds scoring.
 */
export function remediate(report: AuditReport): Remediation {
  const items: RemediationItem[] = [...report.findings]
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])
    .map((f: Finding) => {
      const g = guideFor(f.ruleId, f.category);
      return { ruleId: f.ruleId, severity: f.severity, summary: g.summary, action: g.action };
    });

  const m = report.meta;
  const waiver: WaiverTemplate | null =
    report.verdict === "allow"
      ? null
      : {
          name: m.name, version: m.version, integrity: m.integrity,
          approveCommand: `sentinel approve ${m.name} ${m.version} --reason "<state your review rationale>"`,
          requestPayload: { name: m.name, version: m.version, integrity: m.integrity, reason: "<state your review rationale>" },
        };

  const guidance =
    report.verdict === "allow"
      ? `allow — no action required${items.length ? ` (${items.length} informational finding(s))` : ""}.`
      : `${report.verdict} — ${items.length} finding(s); see the actions below${waiver ? " or waive with the recorded rationale" : ""}.`;

  return { items, waiver, guidance };
}
