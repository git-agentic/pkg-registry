import type {
  AuditInput,
  Category,
  Evidence,
  Finding,
  PackageFile,
  Severity,
} from "../types.js";

/** Files we actually scan for code patterns (skip JSON/markdown/licenses). */
export function codeFiles(input: AuditInput): PackageFile[] {
  return input.files.filter((f) => /\.(c?js|mjs|cjs|ts|mts|cts|jsx|tsx)$/i.test(f.path));
}

/** Build line-anchored evidence for the first N matches of a regex in a file. */
export function scanLines(
  file: PackageFile,
  re: RegExp,
  maxMatches = 3,
): Evidence[] {
  const out: Evidence[] = [];
  const lines = file.content.split(/\r?\n/);
  for (let i = 0; i < lines.length && out.length < maxMatches; i++) {
    const line = lines[i] ?? "";
    // Reset lastIndex for global regexes reused across lines.
    re.lastIndex = 0;
    if (re.test(line)) {
      out.push({ file: file.path, line: i + 1, snippet: truncate(line.trim(), 160) });
    }
  }
  return out;
}

export function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/**
 * Construct a finding. Records whether any cited file is new/changed in this
 * release (`onChangedFile`); the diff multiplier and severity weight are applied
 * later in `score()`, not here, so findings stay policy-independent.
 */
export function mkFinding(args: {
  ruleId: string;
  category: Category;
  severity: Severity;
  message: string;
  evidence: Evidence[];
  files: PackageFile[];
}): Finding {
  const changedPaths = new Set(args.files.filter((f) => f.changed).map((f) => f.path));
  const onChangedFile = args.evidence.some((e) => changedPaths.has(e.file));
  return {
    ruleId: args.ruleId,
    category: args.category,
    severity: args.severity,
    message: args.message,
    onChangedFile,
    evidence: args.evidence,
  };
}
