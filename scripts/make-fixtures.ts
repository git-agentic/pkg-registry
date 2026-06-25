/**
 * Packs each fixture version's `package/` directory into a real npm-style
 * `.tgz`, computes integrity + sizes, and writes `fixtures/registry.json` —
 * the document the proxy's LocalFixtureUpstream serves. Run: `npm run fixtures`.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, statSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as tar from "tar";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const FIX = join(ROOT, "fixtures");
const OUT_DIR = join(FIX, ".tarballs");

interface IndexFile {
  packages: Record<
    string,
    {
      class: "benign" | "malicious";
      versions: Record<string, { signatureStatus: "signed" | "unsigned" | "unknown" }>;
    }
  >;
}

interface RegistryVersion {
  version: string;
  author: string | null;
  license: string | null;
  hasInstallScripts: boolean;
  signatureStatus: "signed" | "unsigned" | "unknown";
  dist: { tarballFile: string; integrity: string; unpackedSize: number; fileCount: number };
}

interface RegistryDoc {
  packages: Record<
    string,
    { name: string; author: string | null; versions: Record<string, RegistryVersion> }
  >;
}

function authorString(a: unknown): string | null {
  if (!a) return null;
  if (typeof a === "string") return a;
  if (typeof a === "object" && a && "name" in a) return String((a as { name: unknown }).name);
  return null;
}

function main(): void {
  const index = JSON.parse(readFileSync(join(FIX, "index.json"), "utf8")) as IndexFile;
  mkdirSync(OUT_DIR, { recursive: true });
  const registry: RegistryDoc = { packages: {} };

  for (const [name, pkg] of Object.entries(index.packages)) {
    const entry = { name, author: null as string | null, versions: {} as Record<string, RegistryVersion> };

    for (const [version, vmeta] of Object.entries(pkg.versions)) {
      const versionDir = join(FIX, pkg.class, name, version);
      const pkgJson = JSON.parse(readFileSync(join(versionDir, "package", "package.json"), "utf8"));
      const author = authorString(pkgJson.author);
      entry.author ??= author;

      const tarballName = `${name}-${version}.tgz`;
      const tarballPath = join(OUT_DIR, tarballName);
      // Deterministic build: `portable` normalizes tar headers (uid/gid/uname/gname),
      // `gzip.portable` zeroes the gzip mtime/OS bytes, and a fixed `mtime` overrides
      // per-file timestamps. Without these, every rebuild yields different bytes →
      // different integrity → registry.json drifts and fixtures fail to verify.
      tar.create(
        {
          gzip: { portable: true },
          cwd: versionDir,
          file: tarballPath,
          portable: true,
          mtime: new Date("2020-01-01T00:00:00Z"),
          sync: true,
        },
        ["package"],
      );

      const buf = readFileSync(tarballPath);
      const integrity = `sha512-${createHash("sha512").update(buf).digest("base64")}`;
      const { unpackedSize, fileCount } = measure(versionDir);
      const hasInstallScripts = ["preinstall", "install", "postinstall"].some(
        (h) => Boolean(pkgJson.scripts?.[h]),
      );

      entry.versions[version] = {
        version,
        author,
        license: pkgJson.license ?? null,
        hasInstallScripts,
        signatureStatus: vmeta.signatureStatus,
        dist: { tarballFile: tarballName, integrity, unpackedSize, fileCount },
      };
      console.log(`packed ${name}@${version} -> ${tarballName} (${buf.length} B, integrity ${integrity.slice(0, 23)}…)`);
    }
    registry.packages[name] = entry;
  }

  writeFileSync(join(FIX, "registry.json"), JSON.stringify(registry, null, 2) + "\n");
  console.log(`\nwrote fixtures/registry.json (${Object.keys(registry.packages).length} packages)`);
}

/** Sum unpacked file sizes + count for the package/ tree (mirrors npm's unpackedSize). */
function measure(versionDir: string): { unpackedSize: number; fileCount: number } {
  let unpackedSize = 0;
  let fileCount = 0;
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else {
        unpackedSize += st.size;
        fileCount += 1;
      }
    }
  };
  walk(join(versionDir, "package"));
  return { unpackedSize, fileCount };
}

main();
