import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import { createGunzip } from "node:zlib";
import * as tar from "tar";
import type { PackageFile } from "./types.js";

const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip very large files from text scanning
const TEXT_EXT = /\.(c?js|mjs|cjs|ts|mts|cts|jsx|tsx|json|map|sh|txt|md|yml|yaml)$/i;
/** Executable code extensions (subset of TEXT_EXT); flagged as unscanned when over MAX_FILE_BYTES. */
const CODE_EXT = /\.(c?js|mjs|cjs|ts|mts|cts|jsx|tsx)$/i;
/** Native / binary executable extensions; never scanned, flagged as unscanned when present. */
const NATIVE_EXT = /\.(node|wasm|so|dll|dylib|exe)$/i;
/** Cap on the unscanned list to bound memory on a pathological many-binary tarball. */
const MAX_UNSCANNED = 100;

/** Decompression-bomb guards (ADR-0039). Defaults never hit a legitimate package. */
export const DEFAULT_MAX_UNPACKED_BYTES = 1024 * 1024 * 1024; // 1 GiB total decompressed
export const DEFAULT_MAX_FILE_COUNT = 100_000;

export interface UnscannedEntry {
  path: string;
  size: number;
  kind: "large-code" | "native";
}

export interface ExtractResult {
  files: PackageFile[];
  unpackedSize: number;
  fileCount: number;
  /** True when a cap was hit and extraction was aborted early (ADR-0039). */
  truncated: boolean;
  /** Counted-but-unscanned executable-looking files: large code + native binaries (#11). */
  unscanned: UnscannedEntry[];
  /**
   * Complete, never-capped running totals over every unscanned executable-looking
   * entry — including any beyond the `unscanned` list's `MAX_UNSCANNED` cap. Use
   * these (not `unscanned.length`/a filter over it) for counts/bytes/native-count,
   * so an attacker padding the list past the cap can't hide a native binary or
   * undercount bytes (#11 review fix).
   */
  unscannedTotals: { count: number; native: number; bytes: number };
}

/**
 * Extract a `.tgz` npm tarball (gzip+tar) in memory and return its text files.
 * Binary and oversized entries are counted toward size/count but not scanned.
 *
 * Guards against decompression bombs by counting at the **decompression
 * boundary**, not per tar-entry (ADR-0039). We own the gunzip: every byte we
 * decompress is counted toward `maxUnpackedBytes` before it is handed to the tar
 * parser, so a bomb built from tar metadata that never surfaces as an `entry`
 * event — pax/GNU meta headers (`x`/`g`/`L`/`K`), ignored or oversized meta,
 * invalid entries — is caught all the same. A prior per-entry counter was blind
 * to these: node-tar decompresses those bytes but emits no `entry`, so 200 MiB
 * could unpack under a 1 MiB cap with `truncated:false`. On a breach we set
 * `truncated: true` and `destroy()` the gunzip — the mechanism that actually
 * halts decompression (zlib's streaming `maxOutputLength` does not enforce),
 * bounding CPU/memory. `unpackedSize` is now the total decompressed tar-stream
 * byte count (headers + padding + all entries), which is the correct cap metric;
 * `fileCount` remains File-entry count. Never throws on a bomb — a security
 * review found node-tar silently tolerates a malformed *tar* body (partial or
 * empty extraction, the byte cap already intact — fail-safe), so throwing is
 * reserved for a malformed **gzip**, or a tar error node-tar itself chooses to
 * surface. `baseline` marks changed files for the diff multiplier.
 */
export async function extractTarball(
  tgz: Buffer,
  baseline?: Map<string, string>,
  opts: { maxUnpackedBytes?: number; maxFileCount?: number } = {},
): Promise<ExtractResult> {
  const maxUnpacked = opts.maxUnpackedBytes ?? DEFAULT_MAX_UNPACKED_BYTES;
  const maxFiles = opts.maxFileCount ?? DEFAULT_MAX_FILE_COUNT;
  const files: PackageFile[] = [];
  const unscanned: UnscannedEntry[] = [];
  const unscannedTotals = { count: 0, native: 0, bytes: 0 };
  let unpackedSize = 0;
  let fileCount = 0;
  let entryCount = 0;
  let truncated = false;
  let failure: Error | null = null;

  // The parser is used for FILE EXTRACTION only (retain ≤2 MiB text files, count
  // File entries and total entries). It is NOT the byte-cap authority — the
  // gunzip below is. node-tar's Parser auto-detects the gzip magic and only
  // unzips when present, so the decompressed tar bytes we feed it (no magic) are
  // parsed as plain tar.
  const parser = new tar.Parser();
  parser.on("entry", (entry: tar.ReadEntry) => {
    if (truncated) {
      entry.resume();
      return;
    }
    entryCount += 1;
    if (entryCount > maxFiles) {
      truncated = true;
      entry.resume();
      return;
    }
    const isFile = entry.type === "File";
    if (isFile) fileCount += 1;
    const chunks: Buffer[] = [];
    let bytes = 0;
    entry.on("data", (c: Buffer) => {
      if (isFile) {
        bytes += c.length;
        if (!truncated && bytes <= MAX_FILE_BYTES) chunks.push(c);
      }
    });
    entry.on("end", () => {
      if (truncated || !isFile) return;
      const path = normalize(entry.path);
      if (bytes <= MAX_FILE_BYTES && TEXT_EXT.test(path)) {
        const content = Buffer.concat(chunks).toString("utf8");
        const prev = baseline?.get(path);
        files.push({ path, content, size: bytes, changed: baseline ? prev !== content : false });
        return;
      }
      // Not scanned — record executable-looking content so the blind spot isn't silent (#11).
      const isLargeCode = bytes > MAX_FILE_BYTES && CODE_EXT.test(path);
      const isNative = NATIVE_EXT.test(path);
      if (isLargeCode || isNative) {
        // Totals are COMPLETE and never capped — an attacker padding the list
        // past MAX_UNSCANNED must not be able to hide a native binary or
        // undercount bytes/count (#11 review fix).
        unscannedTotals.count += 1;
        unscannedTotals.bytes += bytes;
        if (isNative) unscannedTotals.native += 1;
        if (unscanned.length < MAX_UNSCANNED) {
          unscanned.push({ path, size: bytes, kind: isLargeCode ? "large-code" : "native" });
        }
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

  const isGzip = tgz.length >= 2 && tgz[0] === 0x1f && tgz[1] === 0x8b;

  if (isGzip) {
    // Own the gunzip so every decompressed byte is counted at the boundary,
    // regardless of tar semantics. On a cap breach we destroy() the gunzip,
    // which halts decompression promptly and bounds CPU/memory.
    const gunzip = createGunzip();
    gunzip.on("data", (chunk: Buffer) => {
      if (truncated || failure) return;
      unpackedSize += chunk.length;
      if (unpackedSize > maxUnpacked) {
        truncated = true;
        gunzip.destroy();
        return;
      }
      // Feed the decompressed tar bytes onward for file extraction. A parser
      // entry handler may set `truncated` (entry-count cap) or `failure`
      // (malformed tar) synchronously during this write — if so, stop
      // decompressing the rest of the payload.
      parser.write(chunk);
      if (truncated || failure) gunzip.destroy();
    });
    // A destroy()-induced abort/premature-close error is expected on the
    // truncate path and must not clobber a genuine gzip/tar failure. Only
    // record a real failure when we have neither truncated nor already failed.
    gunzip.on("error", (e: unknown) => {
      if (!truncated && !failure) failure = e instanceof Error ? e : new Error(String(e));
    });
    const gzClosed = new Promise<void>((resolve) => gunzip.on("close", () => resolve()));
    gunzip.end(tgz);
    await gzClosed;
  } else {
    // Not gzip: the buffer is already an uncompressed tar. Feed it to the parser
    // directly while still counting its bytes toward `unpackedSize`, in slices so
    // a cap breach halts before feeding the whole payload. npm tarballs are always
    // gzip; this preserves robustness for a raw tar.
    const SLICE = 256 * 1024;
    for (let off = 0; off < tgz.length && !truncated && !failure; off += SLICE) {
      const chunk = tgz.subarray(off, off + SLICE);
      unpackedSize += chunk.length;
      if (unpackedSize > maxUnpacked) { truncated = true; break; }
      parser.write(chunk);
    }
  }

  if (!truncated && !failure) {
    parser.end();
    await done;
  }
  if (failure) throw failure;
  return { files, unpackedSize, fileCount, truncated, unscanned, unscannedTotals };
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
