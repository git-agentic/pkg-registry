import { Buffer } from "node:buffer";

/**
 * Resource-limit helpers (Phase 24, ADR-0037). Pure — no I/O beyond consuming
 * a Response body stream, no env access (index.ts owns the FATAL wrapping).
 */

/** Parse a strictly-positive integer env value. Throws (caller FATALs) on anything else. */
export function parsePositiveInt(raw: string, name: string): number {
  const n = Number(raw.trim());
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`${name} must be a positive integer, got "${raw}"`);
  }
  return n;
}

/**
 * Read a fetch Response body into a Buffer, refusing to buffer more than
 * `maxBytes`. Two layers: reject up front if the declared content-length
 * already exceeds the cap (body never read), and abort mid-stream if the
 * running byte total exceeds the cap (content-length can lie or be absent).
 * Bounds per-fetch memory to the cap instead of letting `arrayBuffer()`/`json()`
 * buffer an unbounded body first.
 */
export async function readBodyCapped(res: Response, maxBytes: number, what: string): Promise<Buffer> {
  const declared = res.headers.get("content-length");
  if (declared !== null) {
    const len = Number(declared);
    if (Number.isFinite(len) && len > maxBytes) {
      throw new Error(`${what} too large: content-length ${len} exceeds cap ${maxBytes}`);
    }
  }
  if (!res.body) return Buffer.alloc(0);

  const chunks: Buffer[] = [];
  let total = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`${what} too large: streamed ${total}+ bytes exceeds cap ${maxBytes}`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}
