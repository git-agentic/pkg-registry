import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { RegistrySignature } from "@sentinel/core";

export interface UpstreamVersion {
  version: string;
  author: string | null;
  maintainers: string[];
  license: string | null;
  signatures: RegistrySignature[] | null;
  hasProvenance: boolean;
  integrity: string | null;
  hasInstallScripts: boolean;
}

export interface UpstreamPackument {
  /** npm-shaped packument document. The server rewrites each `dist.tarball`. */
  doc: PackumentDoc;
  /** Normalised per-version metadata used by the audit engine. */
  versions: Record<string, UpstreamVersion>;
}

export interface PackumentDoc {
  name: string;
  "dist-tags"?: Record<string, string>;
  versions: Record<string, VersionManifest>;
  [k: string]: unknown;
}

interface VersionManifest {
  name: string;
  version: string;
  dist: { tarball: string; integrity?: string; signatures?: { keyid: string; sig: string }[]; attestations?: unknown };
  scripts?: Record<string, string>;
  author?: unknown;
  maintainers?: { name: string }[];
  license?: string;
  [k: string]: unknown;
}

export interface Upstream {
  readonly name: string;
  getPackument(pkg: string): Promise<UpstreamPackument>;
  getTarball(pkg: string, version: string): Promise<Buffer>;
}

function authorString(a: unknown): string | null {
  if (!a) return null;
  if (typeof a === "string") return a;
  if (typeof a === "object" && a && "name" in a) return String((a as { name: unknown }).name);
  return null;
}

function normalizeVersion(m: VersionManifest): UpstreamVersion {
  return {
    version: m.version,
    author: authorString(m.author),
    maintainers: (m.maintainers ?? []).map((x) => x.name).filter(Boolean),
    license: typeof m.license === "string" ? m.license : null,
    signatures: Array.isArray(m.dist?.signatures) && m.dist.signatures.length > 0 ? m.dist.signatures : null,
    hasProvenance: Boolean(m.dist?.attestations),
    integrity: m.dist?.integrity ?? null,
    hasInstallScripts: ["preinstall", "install", "postinstall"].some(
      (h) => Boolean(m.scripts?.[h]),
    ),
  };
}

/** Fetches from the real npm registry. */
export class NpmUpstream implements Upstream {
  readonly name = "npm";
  constructor(private readonly registry = "https://registry.npmjs.org") {}

  async getPackument(pkg: string): Promise<UpstreamPackument> {
    const res = await fetch(`${this.registry}/${encodeURIComponent(pkg).replace("%40", "@")}`, {
      headers: { accept: "application/json" },
    });
    if (!res.ok) throw new HttpError(res.status, `upstream packument ${pkg}: ${res.status}`);
    const doc = (await res.json()) as PackumentDoc;
    const versions: Record<string, UpstreamVersion> = {};
    for (const [v, m] of Object.entries(doc.versions ?? {})) {
      versions[v] = normalizeVersion(m);
    }
    return { doc, versions };
  }

  async getTarball(pkg: string, version: string): Promise<Buffer> {
    const pm = await this.getPackument(pkg);
    const url = pm.doc.versions[version]?.dist?.tarball;
    if (!url) throw new HttpError(404, `no tarball for ${pkg}@${version}`);
    const res = await fetch(url);
    if (!res.ok) throw new HttpError(res.status, `upstream tarball ${pkg}@${version}: ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  }
}

interface RegistryDoc {
  packages: Record<
    string,
    {
      name: string;
      author: string | null;
      versions: Record<
        string,
        {
          version: string;
          author: string | null;
          license: string | null;
          hasInstallScripts: boolean;
          signatures?: { keyid: string; sig: string }[] | null;
          attestations?: boolean;
          dist: { tarballFile: string; integrity: string; unpackedSize: number; fileCount: number };
        }
      >;
    }
  >;
}

/**
 * Serves the packed fixtures in `fixtures/` — hermetic, offline, deterministic.
 * Used by the test suite and the local demo so the malware-detection guarantee
 * never depends on a live network.
 */
export class LocalFixtureUpstream implements Upstream {
  readonly name = "local-fixtures";
  private readonly doc: RegistryDoc;
  constructor(private readonly fixturesDir: string) {
    this.doc = JSON.parse(readFileSync(join(fixturesDir, "registry.json"), "utf8")) as RegistryDoc;
  }

  async getPackument(pkg: string): Promise<UpstreamPackument> {
    const p = this.doc.packages[pkg];
    if (!p) throw new HttpError(404, `unknown fixture package ${pkg}`);
    const versions: Record<string, UpstreamVersion> = {};
    const docVersions: Record<string, VersionManifest> = {};
    const distTags: Record<string, string> = {};
    let latest = "0.0.0";
    for (const [v, m] of Object.entries(p.versions)) {
      versions[v] = {
        version: v,
        author: m.author,
        maintainers: [],
        license: m.license,
        signatures: m.signatures ?? null,
        hasProvenance: Boolean(m.attestations),
        integrity: m.dist.integrity,
        hasInstallScripts: m.hasInstallScripts,
      };
      docVersions[v] = {
        name: pkg,
        version: v,
        dist: {
          tarball: `fixture:${pkg}@${v}`,
          integrity: m.dist.integrity,
          signatures: m.signatures ?? undefined,
          attestations: m.attestations ? {} : undefined,
        },
        license: m.license ?? undefined,
        // npm reads this flag from the packument to decide whether to run a package's install
        // scripts (an optimization that skips extraction otherwise). Without it, npm would never
        // run enforce-probe's postinstall on a by-name install.
        hasInstallScript: m.hasInstallScripts,
      };
      if (cmpSemver(v, latest) > 0) latest = v;
    }
    distTags.latest = latest;
    return { doc: { name: pkg, "dist-tags": distTags, versions: docVersions }, versions };
  }

  async getTarball(pkg: string, version: string): Promise<Buffer> {
    const m = this.doc.packages[pkg]?.versions[version];
    if (!m) throw new HttpError(404, `unknown fixture ${pkg}@${version}`);
    const buf = readFileSync(join(this.fixturesDir, ".tarballs", m.dist.tarballFile));
    const integrity = `sha512-${createHash("sha512").update(buf).digest("base64")}`;
    if (integrity !== m.dist.integrity) {
      throw new HttpError(502, `integrity mismatch for ${pkg}@${version}`);
    }
    return buf;
  }
}

/** Pick the immediate predecessor version (for diff-mode auditing). */
export function previousVersion(versions: string[], target: string): string | null {
  const lower = versions.filter((v) => cmpSemver(v, target) < 0).sort(cmpSemver);
  return lower.length ? (lower[lower.length - 1] ?? null) : null;
}

/** Minimal semver compare (major.minor.patch; prerelease tags compared lexically). */
export function cmpSemver(a: string, b: string): number {
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (d !== 0) return Math.sign(d);
  }
  if (pa.pre === pb.pre) return 0;
  if (!pa.pre) return 1; // release > prerelease
  if (!pb.pre) return -1;
  return pa.pre < pb.pre ? -1 : 1;
}

function parse(v: string): { nums: number[]; pre: string } {
  const [core = "", pre = ""] = v.replace(/^v/, "").split("-", 2);
  return { nums: core.split(".").map((n) => parseInt(n, 10) || 0), pre };
}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}
