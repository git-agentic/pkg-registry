import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { createRateLimiter } from "../src/rate-limit.js";

/** A mutable fake clock in milliseconds. */
function fakeClock(start = 0) {
  let t = start;
  return { now: () => t, advance: (ms: number) => { t += ms; } };
}

describe("createRateLimiter (token bucket)", () => {
  test("allows up to rpm requests in a window, then 429s", () => {
    const clock = fakeClock();
    const rl = createRateLimiter({ rpm: 3, now: clock.now });
    assert.equal(rl.check("a").allowed, true);
    assert.equal(rl.check("a").allowed, true);
    assert.equal(rl.check("a").allowed, true);
    const denied = rl.check("a");
    assert.equal(denied.allowed, false);
    assert.ok(denied.retryAfterSec >= 1, "Retry-After is a positive number of seconds");
  });

  test("refills over time — after the window, requests are allowed again", () => {
    const clock = fakeClock();
    const rl = createRateLimiter({ rpm: 2, now: clock.now });
    rl.check("a"); rl.check("a");
    assert.equal(rl.check("a").allowed, false);
    clock.advance(60_000); // one full minute → bucket refilled
    assert.equal(rl.check("a").allowed, true);
  });

  test("partial refill grants proportional tokens", () => {
    const clock = fakeClock();
    const rl = createRateLimiter({ rpm: 60, now: clock.now }); // 1 token/sec
    for (let i = 0; i < 60; i++) rl.check("a");
    assert.equal(rl.check("a").allowed, false);
    clock.advance(1_000); // 1 second → ~1 token back
    assert.equal(rl.check("a").allowed, true);
    assert.equal(rl.check("a").allowed, false);
  });

  test("distinct keys have independent buckets", () => {
    const clock = fakeClock();
    const rl = createRateLimiter({ rpm: 1, now: clock.now });
    assert.equal(rl.check("a").allowed, true);
    assert.equal(rl.check("a").allowed, false);
    assert.equal(rl.check("b").allowed, true, "key b is unaffected by key a");
  });
});
