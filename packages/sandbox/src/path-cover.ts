/** Split a path into segments after stripping a leading `~/` or `/`. */
export function segments(p: string): string[] {
  return p.replace(/^~?\/?/, "").split("/").filter(Boolean);
}

/**
 * Directional segment-anchored coverage: true iff `approvedTarget` is an
 * ancestor-or-equal of `target` — i.e. an approval grants exactly its own
 * subtree and never widens up to an ancestor (Phase 25, ADR-0038). Segment-
 * anchored, so `ssh` does not cover `.ssh`; the dynamic `*` target covers
 * nothing.
 */
export function pathCovers(approvedTarget: string, target: string): boolean {
  const a = segments(approvedTarget);
  const d = segments(target);
  if (a.length === 0) return false;      // "*" / empty grants nothing
  if (a.length > d.length) return false; // a deeper approval can't cover a shallower path
  for (let i = 0; i < a.length; i++) if (a[i] !== d[i]) return false;
  return true;
}
