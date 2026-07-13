import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PrivatePackageStore } from "./private-store.js";

/** Export retained native content without rewriting package bytes. Each .tgz can
 * be passed directly to `npm publish --registry <stock-registry>`. */
export function exportNativeStore(storeDir: string, outputDir: string): { packages: number; versions: number } {
  const store = new PrivatePackageStore(storeDir);
  mkdirSync(outputDir, { recursive: true });
  let versions = 0;
  for (const name of store.names().sort()) {
    const packageDir = join(outputDir, encodeURIComponent(name));
    mkdirSync(packageDir, { recursive: true });
    const packument = store.packument(name)!;
    writeFileSync(join(packageDir, "packument.json"), JSON.stringify(packument, null, 2));
    for (const version of store.versions(name).sort()) {
      const tarball = store.getTarball(name, version)!;
      writeFileSync(join(packageDir, `${version}.tgz`), tarball);
      versions++;
    }
  }
  return { packages: store.names().length, versions };
}
