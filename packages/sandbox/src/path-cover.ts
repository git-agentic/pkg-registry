/** Split a path into segments after stripping a leading `~/` or `/`. */
export function segments(p: string): string[] {
  return p.replace(/^~?\/?/, "").split("/").filter(Boolean);
}

/**
 * Path-segment-anchored coverage: true iff an approved filesystem target and a deny
 * path share a full segment prefix up to the shorter (one is an ancestor-or-equal of
 * the other). Deliberately NOT a substring match — `ssh` does not cover `.ssh`, and
 * the dynamic `*` capability target covers nothing — so an over-broad/loose approval
 * can't silently cancel an unrelated credential deny.
 *
 * NOTE — descendant-covers-ancestor side-effect: an approval for a path INSIDE a
 * `subpath` deny (e.g. `--approve filesystem:.ssh/config`) currently cancels the
 * ENTIRE `~/.ssh` deny, not just the single file. This is operator-gated (an attacker
 * cannot supply `--approve`), so it is not an immediate security issue. It is a
 * candidate for future tightening: a descendant approval should not be allowed to lift
 * an ancestor `subpath` deny — only an approval for the ancestor itself (or a wider
 * path) should do so.
 */
export function pathCovers(approvedTarget: string, denyPath: string): boolean {
  const a = segments(approvedTarget);
  const d = segments(denyPath);
  if (a.length === 0) return false;
  const n = Math.min(a.length, d.length);
  for (let i = 0; i < n; i++) if (a[i] !== d[i]) return false;
  return true;
}
