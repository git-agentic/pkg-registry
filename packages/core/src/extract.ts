import { createHash } from "node:crypto";
import { Buffer, isUtf8 } from "node:buffer";
import { posix } from "node:path";
import { createGunzip } from "node:zlib";
import * as tar from "tar";
import type { PackageFile, ContentMismatchEntry } from "./types.js";
import { classifyContent, MAGIC_PREFIX_BYTES } from "./detect/magic.js";

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
  /**
   * Number of tar entries that land on the root package.json after npm-style path
   * normalization (any first segment, `.`/`//` collapsed, case-insensitive), regardless of entry type.
   */
  packageManifestEntryCount: number;
  /**
   * Reasons the root manifest npm would install cannot be trusted to be the one scanned:
   * several entries land on it (npm keeps the last), it is case-variant, or it is too large to scan.
   * Empty for a normal tarball (and for one with no manifest at all).
   */
  manifestConfusion: string[];
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
  /** Files whose raw-byte signature disagrees with a text-looking extension. Capped list. */
  contentMismatch: ContentMismatchEntry[];
  /** Complete, never-capped mismatch totals: overall count + counts by detected kind. */
  contentMismatchTotals: { count: number; byKind: Record<string, number> };
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
  let packageManifestEntryCount = 0;
  let manifestVariant = false;
  let manifestOversized = false;
  const unscanned: UnscannedEntry[] = [];
  const unscannedTotals = { count: 0, native: 0, bytes: 0 };
  const contentMismatch: ContentMismatchEntry[] = [];
  const contentMismatchTotals = { count: 0, byKind: {} as Record<string, number> };
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
    // `null` ⇒ npm would not extract it (escapes the root / no name): never retained.
    // The POSIX reading (`\` is a filename character, as node-tar does on Linux/macOS) is the retained path.
    const normalizedPath = npmPath(entry.path);
    // Windows clients read `\` as a separator: an entry lands on the root manifest under EITHER reading.
    const winPath = npmPath(entry.path.replace(/\\/g, "/"));
    const isManifest = [normalizedPath, winPath].some((x) => x?.toLowerCase() === "package/package.json");
    if (isManifest) {
      packageManifestEntryCount += 1;
      if (normalizedPath !== "package/package.json") manifestVariant = true;
    }
    // node-tar reports typeflag 7 as "ContiguousFile" and 0/NUL as "File"/"OldFile"; npm installs all as files.
    const isFile = /File$/.test(entry.type);
    if (isFile) fileCount += 1;
    const chunks: Buffer[] = [];
    let bytes = 0;
    const prefixChunks: Buffer[] = [];
    let prefixLen = 0;
    entry.on("data", (c: Buffer) => {
      if (isFile) {
        bytes += c.length;
        if (prefixLen < MAGIC_PREFIX_BYTES) {
          const need = MAGIC_PREFIX_BYTES - prefixLen;
          prefixChunks.push(c.subarray(0, need));
          prefixLen += Math.min(need, c.length);
        }
        if (!truncated && bytes <= MAX_FILE_BYTES) chunks.push(c);
      }
    });
    entry.on("end", () => {
      if (truncated || !isFile) return;
      const path = normalizedPath;
      if (path === null) return;
      if (isManifest && bytes > MAX_FILE_BYTES) manifestOversized = true;
      const cls = classifyContent(Buffer.concat(prefixChunks));
      const declaredExt = extOf(path);
      const textLooking = TEXT_EXT.test(path);
      const buf = bytes <= MAX_FILE_BYTES ? Buffer.concat(chunks) : null;
      if (cls.class !== "text" && textLooking) {
        // Binary/compressed/archive/ambiguous signature behind a text-looking
        // extension → mismatch, always reported.
        contentMismatchTotals.count += 1;
        contentMismatchTotals.byKind[cls.kind] = (contentMismatchTotals.byKind[cls.kind] ?? 0) + 1;
        if (contentMismatch.length < MAX_UNSCANNED) {
          contentMismatch.push({ path, declaredExt, detectedKind: cls.kind, size: bytes });
        }
        // `MZ:` and `BZh:` are valid JS labels: valid UTF-8 without NUL is still source
        // Node will run, so it must stay visible to the rules. Real binaries are tracked only above.
        if (!buf || !isUtf8(buf) || buf.includes(0)) return;
      }
      // Extension-less text (`setup`, `bin/run`, `Makefile`) can be named by a script hook; retain it.
      const extensionless = !posix.basename(path).includes(".") && cls.class === "text" && buf !== null && !buf.includes(0);
      if (buf && (textLooking || extensionless)) {
        const content = buf.toString("utf8");
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
    let head = Buffer.alloc(0);
    let headChecked = false;
    gunzip.on("data", (chunk: Buffer) => {
      if (truncated || failure) return;
      unpackedSize += chunk.length;
      if (unpackedSize > maxUnpacked) {
        truncated = true;
        gunzip.destroy();
        return;
      }
      // The tar Parser auto-detects gzip/zstd, so a compressed payload inside the
      // gzip would be decompressed by it, past our cap. Refuse nested compression.
      if (!headChecked) {
        head = Buffer.concat([head, chunk.subarray(0, MAGIC_PREFIX_BYTES)]);
        if (head.length >= 6) headChecked = true;
        if (classifyContent(head).class === "compressed") {
          truncated = true;
          gunzip.destroy();
          return;
        }
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
    // A raw zstd (or other compressed) stream would be decompressed by the Parser, uncounted.
    if (classifyContent(tgz.subarray(0, MAGIC_PREFIX_BYTES)).class === "compressed") truncated = true;
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
  const manifestConfusion: string[] = [];
  if (packageManifestEntryCount > 1) manifestConfusion.push(`${packageManifestEntryCount} entries land on the root package.json (npm keeps the last one)`);
  if (manifestVariant) manifestConfusion.push("the root package.json entry is spelled with different case or path form than package/package.json");
  if (manifestOversized) manifestConfusion.push("the root package.json is over 2 MiB and cannot be scanned");
  return { files, packageManifestEntryCount, manifestConfusion, unpackedSize, fileCount, truncated, unscanned, unscannedTotals, contentMismatch, contentMismatchTotals };
}

/** Build a `path -> content` baseline map from a previously extracted set. */
export function baselineFrom(files: PackageFile[]): Map<string, string> {
  return new Map(files.map((f) => [f.path, f.content]));
}

/** SRI algorithms Sentinel can recompute for a lockfile-integrity cross-check. */
export type SriAlgorithm = "sha1" | "sha256" | "sha384" | "sha512";

/** Compute the SRI integrity string (`<algo>-<base64>`) for a tarball in `algo`. */
export function integrityOfAlgo(tgz: Buffer, algo: SriAlgorithm): string {
  const digest = createHash(algo).update(tgz).digest("base64");
  return `${algo}-${digest}`;
}

/** Compute the SRI integrity string (`sha512-<base64>`) for a tarball. */
export function integrityOf(tgz: Buffer): string {
  return integrityOfAlgo(tgz, "sha512");
}

/**
 * Map a tar entry path to where npm would put it, rooted at `package/`: npm strips the
 * first path segment WHATEVER it is, then the filesystem collapses `.`, `//` and `..`.
 * Returns null for an entry npm would not extract (outside the root, or no name).
 */
function npmPath(p: string): string | null {
  // Leading slashes left by `package//x` are stripped (node-tar's stripAbsolutePath).
  // Trailing separators are dropped by the destination resolution (`package.json/` installs as `package.json`).
  const rest = posix.normalize(p.split("/").slice(1).join("/").replace(/^\/+/, "")).replace(/\/+$/, "");
  if (rest === "" || rest === "." || rest === ".." || rest.startsWith("../")) return null;
  return `package/${rest}`;
}

function extOf(p: string): string {
  const m = /(\.[a-z0-9]+)$/i.exec(p);
  return m ? m[1]!.toLowerCase() : "";
}
