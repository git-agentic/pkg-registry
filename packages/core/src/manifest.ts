import type { ExtractResult } from "./extract.js";

export interface PackageCoordinate {
  name: string;
  version: string;
}

/**
 * Locate, parse, and minimally validate `package/package.json` from an
 * already-extracted tarball, returning the name/version it declares.
 *
 * COD2-1058: this used to be written twice — once inline in `runAudit`'s
 * `requirePackageManifest` branch (the publish-gate identity check) and once
 * in the CLI's `scan` coordinate reader — and the two copies had already
 * drifted on error wording. This is the one place that owns "how do we read
 * the coordinate a tarball itself declares." A caller that additionally needs
 * to check that coordinate against something else (a known publish target, a
 * filename, …) does that check on top of this result; it does not re-derive
 * name/version itself.
 *
 * Refuses rather than falls back on any ambiguity — a manifest that cannot be
 * read unambiguously is a coordinate that is unknown, not one to guess at.
 */
export function readPackageManifest(extracted: ExtractResult): PackageCoordinate {
  if (extracted.packageManifestEntryCount > 1) {
    throw new Error("malformed npm tarball: duplicate package/package.json entries");
  }
  const file = extracted.files.find((f) => f.path === "package/package.json");
  if (!file) {
    throw new Error("malformed npm tarball: missing readable package/package.json");
  }
  let manifest: { name?: unknown; version?: unknown };
  try {
    manifest = JSON.parse(file.content) as { name?: unknown; version?: unknown };
  } catch {
    throw new Error("malformed npm tarball: package/package.json is not valid JSON");
  }
  if (typeof manifest.name !== "string" || manifest.name.length === 0) {
    throw new Error("malformed npm tarball: package/package.json declares no name");
  }
  if (typeof manifest.version !== "string" || manifest.version.length === 0) {
    throw new Error("malformed npm tarball: package/package.json declares no version");
  }
  return { name: manifest.name, version: manifest.version };
}
