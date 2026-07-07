/** Lowercase, strip a leading @, drop separators. */
function stripSeparators(s: string): string {
  return s.toLowerCase().replace(/^@/, "").replace(/[/_-]/g, "");
}

/** Map visually-confusable characters to a canonical form. */
function deHomoglyph(s: string): string {
  return s
    .replace(/rn/g, "m") // digraph confusable first
    .replace(/[0]/g, "o")
    .replace(/[1|]/g, "l")
    .replace(/[5]/g, "s");
}

/** Separator- and homoglyph-folded canonical form for squat comparison. */
export function canonical(s: string): string {
  return deHomoglyph(stripSeparators(s));
}

/**
 * Flatten a package (or namespace) name to its scope-or-base for dependency-confusion
 * comparison: `@acme/utils` → `acme`, `@acme/*` → `acme`, `acme-internal` → `acmeinternal`.
 */
export function normalizeName(s: string): string {
  const noScope = s.replace(/^@/, "");
  const base = noScope.includes("/") ? noScope.split("/")[0]! : noScope;
  return base.replace(/[*]/g, "").replace(/[/_-]/g, "").toLowerCase();
}

/** Optimal-string-alignment (Damerau-Levenshtein with adjacent transpositions). */
export function damerauLevenshtein(a: string, b: string): number {
  const al = a.length, bl = b.length;
  if (al === 0) return bl;
  if (bl === 0) return al;
  const d: number[][] = Array.from({ length: al + 1 }, () => new Array<number>(bl + 1).fill(0));
  for (let i = 0; i <= al; i++) d[i]![0] = i;
  for (let j = 0; j <= bl; j++) d[0]![j] = j;
  for (let i = 1; i <= al; i++) {
    for (let j = 1; j <= bl; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i]![j] = Math.min(d[i]![j]!, d[i - 2]![j - 2]! + 1);
      }
    }
  }
  return d[al]![bl]!;
}

/** True iff `name` is a likely typosquat of the distinct `target`. */
export function typosquatMatch(name: string, target: string): boolean {
  if (name === target) return false;
  const a = canonical(name), b = canonical(target);
  if (a.length === 0 || b.length === 0) return false;
  if (a === b) return true; // separator / scope / homoglyph collision
  const threshold = b.length >= 7 ? 2 : 1;
  const d = damerauLevenshtein(a, b);
  return d >= 1 && d <= threshold;
}
