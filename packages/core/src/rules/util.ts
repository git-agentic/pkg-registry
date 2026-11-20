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

/**
 * Linear-time stand-in for `HEAD[^STOP]*?MARKER`: yields each `head` match that
 * has a `marker` before the next `stop` match. The naive regex rescans to the
 * statement end from every head and goes quadratic on repeated heads; here each
 * statement is scanned once. `head` and `marker` must be global; `stop` is a
 * source pattern (no flags).
 */
export function* headsWithTail(
  content: string,
  head: RegExp,
  stop: string,
  marker: RegExp,
): Generator<RegExpMatchArray> {
  const stopRe = new RegExp(stop, "g");
  let segEnd = -1;
  let lastMarker = -1;
  for (const m of content.matchAll(head)) {
    const end = m.index! + m[0].length;
    if (end > segEnd) {
      stopRe.lastIndex = end;
      const hit = stopRe.exec(content);
      segEnd = hit ? hit.index : content.length;
      lastMarker = -1;
      for (const k of content.slice(end, segEnd).matchAll(marker)) lastMarker = end + k.index!;
    }
    if (lastMarker >= end) yield m;
  }
}

/** Offset → 1-based line lookup built once (binary search), instead of rescanning from 0. */
export function lineLocator(content: string): (pos: number) => number {
  const starts = [0];
  for (let i = content.indexOf("\n"); i !== -1; i = content.indexOf("\n", i + 1)) starts.push(i + 1);
  return (pos) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= pos) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
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
