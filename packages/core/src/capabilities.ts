import type { AuditInput, Capability, CapabilityDelta } from "./types.js";
import { capabilityAtom, scanForCapabilities } from "./detect/patterns.js";
import { codeFiles } from "./rules/util.js";

const MAX_EVIDENCE_PER_ATOM = 3;

/**
 * Deterministic, complete requested-capability inventory for a package. A
 * superset of what trips findings — records benign-but-real capabilities too.
 * Each file is scanned under try/catch so one bad file fails open.
 */
export function extractCapabilities(input: AuditInput): Capability[] {
  const byAtom = new Map<string, Capability>();
  for (const file of codeFiles(input)) {
    let found: Capability[] = [];
    try {
      found = scanForCapabilities(file);
    } catch {
      found = [];
    }
    for (const cap of found) {
      const key = capabilityAtom(cap);
      const existing = byAtom.get(key);
      if (existing) {
        if (existing.evidence.length < MAX_EVIDENCE_PER_ATOM) {
          existing.evidence.push(...cap.evidence.slice(0, MAX_EVIDENCE_PER_ATOM - existing.evidence.length));
        }
      } else {
        byAtom.set(key, { kind: cap.kind, target: cap.target, evidence: cap.evidence.slice(0, MAX_EVIDENCE_PER_ATOM) });
      }
    }
  }
  return [...byAtom.values()].sort((a, b) =>
    a.kind === b.kind ? a.target.localeCompare(b.target) : a.kind.localeCompare(b.kind),
  );
}

/** Atom-set difference between a current and baseline inventory. */
export function diffCapabilities(current: Capability[], baseline: Capability[]): CapabilityDelta {
  const baseAtoms = new Set(baseline.map(capabilityAtom));
  const curAtoms = new Set(current.map(capabilityAtom));
  return {
    added: current.filter((c) => !baseAtoms.has(capabilityAtom(c))),
    removed: baseline.filter((c) => !curAtoms.has(capabilityAtom(c))),
  };
}
