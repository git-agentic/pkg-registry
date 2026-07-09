import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { describe, test } from "node:test";
import { parsePositiveInt, readBodyCapped } from "../src/limits.js";

describe("parsePositiveInt", () => {
  test("parses a positive integer", () => {
    assert.equal(parsePositiveInt("5000", "SENTINEL_MAX_TREE_PACKAGES"), 5000);
  });
  test("rejects zero", () => {
    assert.throws(() => parsePositiveInt("0", "X"), /X must be a positive integer/);
  });
  test("rejects a negative number", () => {
    assert.throws(() => parsePositiveInt("-3", "X"), /positive integer/);
  });
  test("rejects a non-integer", () => {
    assert.throws(() => parsePositiveInt("3.5", "X"), /positive integer/);
  });
  test("rejects garbage", () => {
    assert.throws(() => parsePositiveInt("lots", "X"), /positive integer/);
  });
  test("rejects trailing junk", () => {
    assert.throws(() => parsePositiveInt("100MB", "X"), /positive integer/);
  });
});

/** Build a Response whose body streams `chunks`, with an optional content-length header. */
function streamResponse(chunks: Buffer[], contentLength?: number): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const c of chunks) controller.enqueue(new Uint8Array(c));
      controller.close();
    },
  });
  const headers: Record<string, string> = {};
  if (contentLength !== undefined) headers["content-length"] = String(contentLength);
  return new Response(stream, { headers });
}

describe("readBodyCapped", () => {
  test("returns the full body when under the cap", async () => {
    const res = streamResponse([Buffer.from("hello "), Buffer.from("world")]);
    const buf = await readBodyCapped(res, 1000, "test body");
    assert.equal(buf.toString(), "hello world");
  });

  test("early-rejects when content-length exceeds the cap (body not consumed)", async () => {
    // undici pulls a pull-driven ReadableStream at Response construction regardless of
    // our code, so we assert on res.bodyUsed — it flips true only if readBodyCapped
    // calls getReader(), which the content-length early-reject path must never do.
    const res = streamResponse([Buffer.from("x".repeat(100))], 999999);
    await assert.rejects(() => readBodyCapped(res, 10, "test body"), /too large/);
    assert.equal(res.bodyUsed, false, "early-reject must not consume the body");
  });

  test("aborts mid-stream when the running total exceeds the cap (lying/absent content-length)", async () => {
    // No content-length; body is 100 bytes but cap is 10.
    const res = streamResponse([Buffer.alloc(6, 1), Buffer.alloc(6, 2)]);
    await assert.rejects(() => readBodyCapped(res, 10, "test body"), /too large/);
  });

  test("a body exactly at the cap is allowed", async () => {
    const res = streamResponse([Buffer.alloc(10, 7)]);
    const buf = await readBodyCapped(res, 10, "test body");
    assert.equal(buf.length, 10);
  });

  test("a null body yields an empty buffer", async () => {
    const res = new Response(null);
    const buf = await readBodyCapped(res, 10, "test body");
    assert.equal(buf.length, 0);
  });
});
