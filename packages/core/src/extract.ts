import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import * as tar from "tar";
import { Writable } from "node:stream";
import type { PackageFile } from "./types.js";

const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip very large files from text scanning
const TEXT_EXT = /\.(c?js|mjs|cjs|ts|mts|cts|jsx|tsx|json|map|sh|txt|md|yml|yaml)$/i;

export interface ExtractResult {
  files: PackageFile[];
  unpackedSize: number;
  fileCount: number;
}

/**
 * Extract a `.tgz` npm tarball (gzip+tar) entirely in memory and return its
 * text files. Binary and oversized entries are counted toward size/count but
 * not scanned. `baseline` (the previous version's file set) marks changed files
 * for the diff multiplier.
 */
export async function extractTarball(
  tgz: Buffer,
  baseline?: Map<string, string>,
): Promise<ExtractResult> {
  const files: PackageFile[] = [];
  let unpackedSize = 0;
  let fileCount = 0;

  const parser = new tar.Parser();

  await new Promise<void>((resolve, reject) => {
    parser.on("entry", (entry: tar.ReadEntry) => {
      if (entry.type !== "File") {
        entry.resume();
        return;
      }
      fileCount += 1;
      const chunks: Buffer[] = [];
      let bytes = 0;
      entry.on("data", (c: Buffer) => {
        bytes += c.length;
        if (bytes <= MAX_FILE_BYTES) chunks.push(c);
      });
      entry.on("end", () => {
        unpackedSize += bytes;
        const path = normalize(entry.path);
        if (bytes <= MAX_FILE_BYTES && TEXT_EXT.test(path)) {
          const content = Buffer.concat(chunks).toString("utf8");
          const prev = baseline?.get(path);
          files.push({
            path,
            content,
            size: bytes,
            changed: baseline ? prev !== content : false,
          });
        }
      });
      entry.on("error", reject);
    });
    parser.on("end", resolve);
    parser.on("error", reject);

    const sink = new Writable({
      write(chunk, _enc, cb) {
        parser.write(chunk);
        cb();
      },
      final(cb) {
        parser.end();
        cb();
      },
    });
    sink.on("error", reject);
    sink.end(tgz);
  });

  return { files, unpackedSize, fileCount };
}

/** Build a `path -> content` baseline map from a previously extracted set. */
export function baselineFrom(files: PackageFile[]): Map<string, string> {
  return new Map(files.map((f) => [f.path, f.content]));
}

/** Compute the SRI integrity string (`sha512-<base64>`) for a tarball. */
export function integrityOf(tgz: Buffer): string {
  const digest = createHash("sha512").update(tgz).digest("base64");
  return `sha512-${digest}`;
}

function normalize(p: string): string {
  // npm tarballs prefix everything with `package/`.
  return p.replace(/^\.\//, "");
}
