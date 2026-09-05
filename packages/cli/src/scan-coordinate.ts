import { Buffer } from "node:buffer";
import { extractTarball, readPackageManifest, type PackageCoordinate } from "@git-agentic/sentinel-core";

export type { PackageCoordinate };

/**
 * The package coordinate as the tarball itself states it.
 *
 * COD2-1058: `scan` used to derive this from the tarball's filename, which
 * `npm pack` writes as `<name>-<version>.tgz` — so the "name" carried the
 * version and never matched a real package name. That value fed typosquat
 * detection, policy.deny, waiver matching and the exit code.
 *
 * Extraction and manifest reading both already exist in
 * `@git-agentic/sentinel-core` for `runAudit`'s own publish-time identity
 * check — this calls the same `extractTarball` + `readPackageManifest`
 * rather than re-deriving either, so the two callers can't drift again.
 */
export async function packageCoordinateFromTarball(
  tarball: Buffer,
): Promise<PackageCoordinate> {
  const extracted = await extractTarball(tarball);
  return readPackageManifest(extracted);
}
