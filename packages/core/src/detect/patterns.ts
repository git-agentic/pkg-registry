import type { Capability, CapabilityKind, Evidence, PackageFile } from "../types.js";
import { truncate } from "../rules/util.js";

export interface CapMatcher {
  kind: CapabilityKind;
  /** Global regex scanned line-by-line. */
  re: RegExp;
  /** Capture-group index holding the concrete target; omit for a dynamic "*". */
  group?: number;
}

/**
 * Capability detectors. These CAPTURE the target (host/path/command) where the
 * rules only flag risk. Shared low-level layer for the capability pass; the
 * rules keep their own risk patterns untouched.
 */
export const CAPABILITY_MATCHERS: CapMatcher[] = [
  // network — concrete targets
  { kind: "network", re: /\bhttps?:\/\/([a-z0-9.\-]+)/gi, group: 1 },
  { kind: "network", re: /hostname\s*:\s*['"]([^'"]+)['"]/gi, group: 1 },
  // network — dynamic
  { kind: "network", re: /\b(?:fetch|axios)\s*\(/gi },
  { kind: "network", re: /\bnew\s+WebSocket\b|navigator\.sendBeacon/gi },
  { kind: "network", re: /require\(\s*['"](?:node:)?(?:https?|net|dgram|dns|tls)['"]\s*\)/gi },
  { kind: "network", re: /from\s+['"](?:node:)?(?:https?|net|dgram|dns|tls)['"]/gi },

  // filesystem — concrete sensitive targets
  { kind: "filesystem", re: /(\.npmrc)\b/gi, group: 1 },
  { kind: "filesystem", re: /(\.aws[\\/]credentials)\b/gi, group: 1 },
  { kind: "filesystem", re: /(\.ssh[\\/](?:id_rsa|id_ed25519|id_\w+))\b/gi, group: 1 },
  { kind: "filesystem", re: /(\/etc\/(?:passwd|shadow))\b/gi, group: 1 },
  // filesystem — dynamic
  { kind: "filesystem", re: /\bfs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\b/gi },

  // process — concrete command
  { kind: "process", re: /\b(?:execSync|execFileSync|exec|execFile|spawnSync|spawn)\s*\(\s*['"]([a-z0-9_./-]+)/gi, group: 1 },
  { kind: "process", re: /\b(curl|wget)\b/gi, group: 1 },
  // process — dynamic
  { kind: "process", re: /require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]/gi },

  // native
  { kind: "native", re: /require\(\s*['"]([^'"]+\.node)['"]\s*\)/gi, group: 1 },
];

export function normalizeTarget(kind: CapabilityKind, raw: string): string {
  const t = raw.trim();
  if (kind === "network") return t.toLowerCase().replace(/:\d+$/, "");
  return t.replace(/\\/g, "/");
}

export function capabilityAtom(c: { kind: CapabilityKind; target: string }): string {
  return `${c.kind}:${c.target}`;
}

/** Scan a single file, emitting one Capability per regex match (target + evidence). */
export function scanForCapabilities(file: PackageFile): Capability[] {
  const out: Capability[] = [];
  const lines = file.content.split(/\r?\n/);
  for (const m of CAPABILITY_MATCHERS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      m.re.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = m.re.exec(line)) !== null) {
        const raw = m.group ? match[m.group] : undefined;
        const target = raw ? normalizeTarget(m.kind, raw) : "*";
        const ev: Evidence = { file: file.path, line: i + 1, snippet: truncate(line.trim(), 160) };
        out.push({ kind: m.kind, target, evidence: [ev] });
        if (!m.re.global) break;
      }
    }
  }
  return out;
}
