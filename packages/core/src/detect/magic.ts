import { Buffer } from "node:buffer";

export const MAGIC_PREFIX_BYTES = 512;

export type DetectedKind =
  | "elf" | "macho" | "pe" | "mz" | "wasm"
  | "gzip" | "xz" | "zstd" | "bzip2" | "zip" | "cafebabe" | "text";
export type DetectedClass = "executable" | "compressed" | "archive" | "ambiguous" | "text";
export interface Classification { kind: DetectedKind; class: DetectedClass }

const TEXT: Classification = { kind: "text", class: "text" };

function starts(b: Buffer, ...sig: number[]): boolean {
  if (b.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[i] !== sig[i]) return false;
  return true;
}

/**
 * Classify a file by a BOUNDED prefix of its raw bytes (the caller reads at most
 * MAGIC_PREFIX_BYTES). Validation only reaches as far as the bytes actually
 * present — never an out-of-bounds read. `text` means no binary signature
 * matched (the normal case).
 */
export function classifyContent(prefix: Buffer): Classification {
  if (starts(prefix, 0x7f, 0x45, 0x4c, 0x46)) return { kind: "elf", class: "executable" };
  if (starts(prefix, 0x00, 0x61, 0x73, 0x6d)) return { kind: "wasm", class: "executable" };
  if (starts(prefix, 0xfe, 0xed, 0xfa, 0xce) || starts(prefix, 0xfe, 0xed, 0xfa, 0xcf) ||
      starts(prefix, 0xce, 0xfa, 0xed, 0xfe) || starts(prefix, 0xcf, 0xfa, 0xed, 0xfe)) {
    return { kind: "macho", class: "executable" };
  }
  // Fat Mach-O and Java .class share CA FE BA BE — cannot disambiguate from the header alone.
  if (starts(prefix, 0xca, 0xfe, 0xba, 0xbe)) return { kind: "cafebabe", class: "ambiguous" };
  if (starts(prefix, 0x1f, 0x8b)) return { kind: "gzip", class: "compressed" };
  if (starts(prefix, 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)) return { kind: "xz", class: "compressed" };
  if (starts(prefix, 0x28, 0xb5, 0x2f, 0xfd)) return { kind: "zstd", class: "compressed" };
  if (starts(prefix, 0x42, 0x5a, 0x68)) return { kind: "bzip2", class: "compressed" };
  if (starts(prefix, 0x50, 0x4b, 0x03, 0x04) || starts(prefix, 0x50, 0x4b, 0x05, 0x06) ||
      starts(prefix, 0x50, 0x4b, 0x07, 0x08)) {
    return { kind: "zip", class: "archive" };
  }
  // PE: MZ stub at 0, then validate PE\0\0 at e_lfanew ONLY when fully in-bounds.
  if (starts(prefix, 0x4d, 0x5a)) {
    if (prefix.length >= 0x40) {
      const eLfanew = prefix.readUInt32LE(0x3c);
      if (eLfanew >= 0 && eLfanew + 4 <= prefix.length &&
          prefix[eLfanew] === 0x50 && prefix[eLfanew + 1] === 0x45 &&
          prefix[eLfanew + 2] === 0x00 && prefix[eLfanew + 3] === 0x00) {
        return { kind: "pe", class: "executable" };
      }
    }
    return { kind: "mz", class: "ambiguous" };
  }
  return TEXT;
}
