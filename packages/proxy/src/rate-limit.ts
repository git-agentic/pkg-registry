/**
 * In-process token-bucket rate limiter (Phase 24, ADR-0037). Pure: the clock is
 * injected (deterministic tests, no wall-clock). One bucket per key; capacity =
 * rpm, refilling at rpm tokens per 60s. A lightweight sweep bounds the bucket
 * map under many distinct keys. This is a backstop — shared deployments should
 * still front the proxy with infra rate limiting.
 */

export interface RateLimiter {
  check(key: string): { allowed: boolean; retryAfterSec: number };
}

interface Bucket {
  tokens: number;
  last: number; // ms timestamp of the last refill
}

const WINDOW_MS = 60_000;
const MAX_TRACKED = 10_000; // sweep idle-full buckets once the map exceeds this

export function createRateLimiter(opts: { rpm: number; now: () => number }): RateLimiter {
  const { rpm, now } = opts;
  const capacity = rpm;
  const refillPerMs = rpm / WINDOW_MS;
  const buckets = new Map<string, Bucket>();

  function sweep(t: number): void {
    for (const [k, b] of buckets) {
      // A full bucket untouched for a full window is indistinguishable from a
      // never-seen key, so it is safe to drop.
      if (t - b.last >= WINDOW_MS && b.tokens >= capacity) buckets.delete(k);
    }
  }

  return {
    check(key: string) {
      const t = now();
      let b = buckets.get(key);
      if (!b) {
        if (buckets.size >= MAX_TRACKED) sweep(t);
        b = { tokens: capacity, last: t };
        buckets.set(key, b);
      } else {
        b.tokens = Math.min(capacity, b.tokens + (t - b.last) * refillPerMs);
        b.last = t;
      }
      if (b.tokens >= 1) {
        b.tokens -= 1;
        return { allowed: true, retryAfterSec: 0 };
      }
      const needed = 1 - b.tokens;
      const retryAfterSec = Math.max(1, Math.ceil(needed / refillPerMs / 1000));
      return { allowed: false, retryAfterSec };
    },
  };
}
