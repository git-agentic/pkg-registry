/**
 * Packs each fixture version's `package/` directory into a real npm-style
 * `.tgz`, computes integrity + sizes, and writes `fixtures/registry.json` —
 * the document the proxy's LocalFixtureUpstream serves. Run: `npm run fixtures`.
 */
import { createHash, generateKeyPairSync, sign, createPrivateKey } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, statSync, readdirSync, existsSync } from "node:fs";
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
      versions: Record<string, { signature: "valid" | "tampered" | "unknown-key" | "none"; provenance: boolean }>;
    }
  >;
}

interface RegistryVersion {
  version: string;
  author: string | null;
  license: string | null;
  hasInstallScripts: boolean;
  dist: { tarballFile: string; integrity: string; unpackedSize: number; fileCount: number };
  signatures?: { keyid: string; sig: string }[] | null;
  attestations?: boolean;
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

  // Synthetic signing key for fixtures: load-or-generate so the keyid + private key
  // are stable across rebuilds (only the ECDSA `sig` bytes churn, per-signature nonce).
  const SIGNING_DIR = join(FIX, "signing");
  const KEY_FILE = join(SIGNING_DIR, "test-key.json");
  mkdirSync(SIGNING_DIR, { recursive: true });
  let priv: string, keyid: string;
  if (existsSync(KEY_FILE)) {
    ({ priv, keyid } = JSON.parse(readFileSync(KEY_FILE, "utf8")));
  } else {
    const kp = generateKeyPairSync("ec", { namedCurve: "P-256" });
    priv = kp.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const spkiDer = kp.publicKey.export({ type: "spki", format: "der" }) as Buffer;
    keyid = "SHA256:" + createHash("sha256").update(spkiDer).digest("base64");
    writeFileSync(KEY_FILE, JSON.stringify({ priv, keyid, spkiPem: kp.publicKey.export({ type: "spki", format: "pem" }).toString() }, null, 2));
  }
  const keyMeta = JSON.parse(readFileSync(KEY_FILE, "utf8")) as { priv: string; keyid: string; spkiPem: string };
  writeFileSync(join(FIX, "signing-keys.json"), JSON.stringify([{ keyid: keyMeta.keyid, spkiPem: keyMeta.spkiPem, expires: null }], null, 2) + "\n");

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

      const payload = Buffer.from(`${name}@${version}:${integrity}`);
      let signatures: { keyid: string; sig: string }[] | null = null;
      if (vmeta.signature === "valid") {
        signatures = [{ keyid: keyMeta.keyid, sig: sign("sha256", payload, createPrivateKey(keyMeta.priv)).toString("base64") }];
      } else if (vmeta.signature === "tampered") {
        const bad = Buffer.from(`${name}@${version}:sha512-TAMPERED`);
        signatures = [{ keyid: keyMeta.keyid, sig: sign("sha256", bad, createPrivateKey(keyMeta.priv)).toString("base64") }];
      } else if (vmeta.signature === "unknown-key") {
        signatures = [{ keyid: "SHA256:unknown-test-key", sig: sign("sha256", payload, createPrivateKey(keyMeta.priv)).toString("base64") }];
      } // "none" -> null

      entry.versions[version] = {
        version,
        author,
        license: pkgJson.license ?? null,
        hasInstallScripts,
        dist: { tarballFile: tarballName, integrity, unpackedSize, fileCount },
        signatures,
        attestations: vmeta.provenance,
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
