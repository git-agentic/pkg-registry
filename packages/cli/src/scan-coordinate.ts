import { Buffer } from "node:buffer";
import { extractTarball } from "@git-agentic/sentinel-core";

export interface PackageCoordinate {
  name: string;
  version: string;
}

/**
 * The package coordinate as the tarball itself states it.
 *
 * COD2-1058: `scan` used to derive this from the tarball's filename, which
 * `npm pack` writes as `<name>-<version>.tgz` — so the "name" carried the
 * version and never matched a real package name. That value fed typosquat
 * detection, policy.deny, waiver matching and the exit code.
 *
 * Refuses rather than falls back: a tarball whose manifest cannot be read is
 * a tarball whose coordinate is unknown, and reporting an unknown coordinate
 * as a known one is the defect this replaces.
 */
export async function packageCoordinateFromTarball(
  tarball: Buffer,
): Promise<PackageCoordinate> {
  const extracted = await extractTarball(tarball);
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
