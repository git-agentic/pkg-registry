import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import * as tar from "tar";
import type { PackageFile } from "./types.js";

const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip very large files from text scanning
const TEXT_EXT = /\.(c?js|mjs|cjs|ts|mts|cts|jsx|tsx|json|map|sh|txt|md|yml|yaml)$/i;

/** Decompression-bomb guards (ADR-0039). Defaults never hit a legitimate package. */
export const DEFAULT_MAX_UNPACKED_BYTES = 1024 * 1024 * 1024; // 1 GiB total decompressed
export const DEFAULT_MAX_FILE_COUNT = 100_000;

export interface ExtractResult {
  files: PackageFile[];
  unpackedSize: number;
  fileCount: number;
  /** True when a cap was hit and extraction was aborted early (ADR-0039). */
  truncated: boolean;
}

/**
 * Extract a `.tgz` npm tarball (gzip+tar) in memory and return its text files.
 * Binary and oversized entries are counted toward size/count but not scanned.
 * Guards against decompression bombs: caps total unpacked bytes and entry count,
 * feeding the parser in slices so a breach halts decompression mid-stream. On a
 * breach it returns `truncated: true` (never throws — throwing is reserved for a
 * malformed tar). `baseline` marks changed files for the diff multiplier.
 */
export async function extractTarball(
  tgz: Buffer,
  baseline?: Map<string, string>,
  opts: { maxUnpackedBytes?: number; maxFileCount?: number } = {},
): Promise<ExtractResult> {
  const maxUnpacked = opts.maxUnpackedBytes ?? DEFAULT_MAX_UNPACKED_BYTES;
  const maxFiles = opts.maxFileCount ?? DEFAULT_MAX_FILE_COUNT;
  const files: PackageFile[] = [];
  let unpackedSize = 0;
  let fileCount = 0;
  let truncated = false;
  let failure: Error | null = null;

  const parser = new tar.Parser();
  parser.on("entry", (entry: tar.ReadEntry) => {
    if (truncated || entry.type !== "File") {
      entry.resume();
      return;
    }
    fileCount += 1;
    if (fileCount > maxFiles) {
      truncated = true;
      entry.resume();
      return;
    }
    const chunks: Buffer[] = [];
    let bytes = 0;
    entry.on("data", (c: Buffer) => {
      unpackedSize += c.length;
      if (unpackedSize > maxUnpacked) truncated = true;
      bytes += c.length;
      if (!truncated && bytes <= MAX_FILE_BYTES) chunks.push(c);
    });
    entry.on("end", () => {
      if (truncated) return;
      const path = normalize(entry.path);
      if (bytes <= MAX_FILE_BYTES && TEXT_EXT.test(path)) {
        const content = Buffer.concat(chunks).toString("utf8");
        const prev = baseline?.get(path);
        files.push({ path, content, size: bytes, changed: baseline ? prev !== content : false });
      }
    });
    entry.on("error", (e: unknown) => { failure = e instanceof Error ? e : new Error(String(e)); });
  });
  parser.on("error", (e: unknown) => { failure = e instanceof Error ? e : new Error(String(e)); });

  // Resolve on the parser's own 'end' event, not the writable-side 'finish'
  // callback passed to `.end()` — 'finish' can fire before every entry's
  // 'data'/'end' handlers have run, which would return an incomplete `files`
  // for larger tarballs. Set this up before feeding so it can't be missed.
  const done = new Promise<void>((resolve) => parser.on("end", () => resolve()));

  // Feed compressed bytes in slices so a cap breach halts decompression mid-stream
  // rather than decompressing the whole bomb in one synchronous write. Yield to the
  // event loop between slices so queued entry/data handlers can set `truncated`.
  const SLICE = 256 * 1024;
  for (let off = 0; off < tgz.length && !truncated && !failure; off += SLICE) {
    parser.write(tgz.subarray(off, off + SLICE));
    await new Promise<void>((r) => setImmediate(r));
  }
  if (!truncated && !failure) {
    parser.end();
    await done;
  }
  if (failure) throw failure;
  return { files, unpackedSize, fileCount, truncated };
}

/** Build a `path -> content` baseline map from a previously extracted set. */
export function baselineFrom(files: PackageFile[]): Map<string, string> {
  return new Map(files.map((f) => [f.path, f.content]));
}

/** SRI algorithms Sentinel can recompute for a lockfile-integrity cross-check. */
export type SriAlgorithm = "sha1" | "sha256" | "sha512";

/** Compute the SRI integrity string (`<algo>-<base64>`) for a tarball in `algo`. */
export function integrityOfAlgo(tgz: Buffer, algo: SriAlgorithm): string {
  const digest = createHash(algo).update(tgz).digest("base64");
  return `${algo}-${digest}`;
}

/** Compute the SRI integrity string (`sha512-<base64>`) for a tarball. */
export function integrityOf(tgz: Buffer): string {
  return integrityOfAlgo(tgz, "sha512");
}

function normalize(p: string): string {
  // npm tarballs prefix everything with `package/`.
  return p.replace(/^\.\//, "");
}
